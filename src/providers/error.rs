use std::io;
use anyhow::anyhow;
use thiserror::Error;

use crate::providers::git_sync::SyncError;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretError {
    #[error("secret '{key}' not found in provider '{provider}'")]
    NotFound { key: String, provider: &'static str },

    #[error(
        "secret '{key}' already exists in provider '{provider}' (use update_secret to change its value)"
    )]
    AlreadyExists { key: String, provider: &'static str },

    #[error("authentication failed for provider '{provider}': {source}")]
    AuthFailed {
        provider: &'static str,
        #[source]
        source: anyhow::Error,
    },

    #[error("network error contacting provider '{provider}': {source}")]
    Network {
        provider: &'static str,
        #[source]
        source: anyhow::Error,
    },

    #[error("operation '{operation}' not supported by provider '{provider}'")]
    Unsupported {
        operation: &'static str,
        provider: &'static str,
    },

    #[error("required CLI tool '{tool}' not found in PATH")]
    CliNotFound { tool: &'static str },

    #[error("provider '{provider}' configuration error: {message}")]
    Config {
        provider: &'static str,
        message: String,
    },

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<SyncError> for SecretError {
    fn from(err: SyncError) -> Self {
        match err {
            SyncError::GitNotFound => SecretError::CliNotFound { tool: "git" },
            SyncError::AuthFailed { source } => SecretError::AuthFailed {
                provider: "local",
                source,
            },
            SyncError::Network { source } => SecretError::Network {
                provider: "local",
                source,
            },
            SyncError::Config { message } => SecretError::Config {
                provider: "local",
                message,
            },
            SyncError::GitCommandFailed { message } => {
                SecretError::Other(anyhow!("git command failed: {}", message))
            }
            SyncError::Io(e) => SecretError::Io(e),
            SyncError::Other(e) => SecretError::Other(e),
        }
    }
}

pub(crate) fn classify_aws_error(
    err: anyhow::Error,
    key: Option<&str>,
    _op: &'static str,
) -> SecretError {
    let provider = "aws_secrets_manager";
    let chain_text = err
        .chain()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(" | ")
        .to_lowercase();

    if chain_text.contains("resourcenotfoundexception") || chain_text.contains("not found") {
        SecretError::NotFound {
            key: key.unwrap_or("").to_string(),
            provider,
        }
    } else if chain_text.contains("alreadyexistsexception") {
        SecretError::AlreadyExists {
            key: key.unwrap_or("").to_string(),
            provider,
        }
    } else if chain_text.contains("accessdenied")
        || chain_text.contains("expiredtoken")
        || chain_text.contains("invalidsignature")
        || chain_text.contains("unauthorized")
        || chain_text.contains("unrecognizedclient")
    {
        SecretError::AuthFailed { provider, source: err }
    } else if chain_text.contains("dispatch failure")
        || chain_text.contains("timeout")
        || chain_text.contains("connection")
        || chain_text.contains("dns")
    {
        SecretError::Network { provider, source: err }
    } else {
        SecretError::Other(err)
    }
}

pub(crate) fn classify_gcp_error(
    err: anyhow::Error,
    key: Option<&str>,
    _op: &'static str,
) -> SecretError {
    let provider = "gcp_secret_manager";

    if let Some(status) = err.downcast_ref::<gcloud_sdk::tonic::Status>() {
        use gcloud_sdk::tonic::Code;
        return match status.code() {
            Code::NotFound => SecretError::NotFound {
                key: key.unwrap_or("").to_string(),
                provider,
            },
            Code::AlreadyExists => SecretError::AlreadyExists {
                key: key.unwrap_or("").to_string(),
                provider,
            },
            Code::Unauthenticated | Code::PermissionDenied => SecretError::AuthFailed {
                provider,
                source: err,
            },
            Code::Unavailable | Code::DeadlineExceeded => SecretError::Network {
                provider,
                source: err,
            },
            _ => SecretError::Other(err),
        };
    }

    let chain_text = err
        .chain()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(" | ")
        .to_lowercase();

    if chain_text.contains("notfound") || chain_text.contains("not found") {
        SecretError::NotFound {
            key: key.unwrap_or("").to_string(),
            provider,
        }
    } else if chain_text.contains("alreadyexists") || chain_text.contains("already exists") {
        SecretError::AlreadyExists {
            key: key.unwrap_or("").to_string(),
            provider,
        }
    } else if chain_text.contains("unauthenticated") || chain_text.contains("permissiondenied") {
        SecretError::AuthFailed { provider, source: err }
    } else if chain_text.contains("unavailable") || chain_text.contains("deadlineexceeded") {
        SecretError::Network { provider, source: err }
    } else {
        SecretError::Other(err)
    }
}

pub(crate) fn classify_azure_error(
    err: anyhow::Error,
    key: Option<&str>,
    _op: &'static str,
) -> SecretError {
    let provider = "azure_key_vault";

    if let Some(azure_err) = err.downcast_ref::<azure_core::Error>() {
        use azure_core::error::ErrorKind;
        if let ErrorKind::HttpResponse { status, .. } = azure_err.kind() {
            let code = u16::from(*status);
            return match code {
                401 | 403 => SecretError::AuthFailed { provider, source: err },
                404 => SecretError::NotFound {
                    key: key.unwrap_or("").to_string(),
                    provider,
                },
                _ => SecretError::Other(err),
            };
        }
    }

    let chain_text = err
        .chain()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(" | ")
        .to_lowercase();

    if chain_text.contains("not found") || chain_text.contains("notfound") {
        SecretError::NotFound {
            key: key.unwrap_or("").to_string(),
            provider,
        }
    } else if chain_text.contains("unauthorized")
        || chain_text.contains("forbidden")
        || chain_text.contains("401")
        || chain_text.contains("403")
        || chain_text.contains("authentication")
    {
        SecretError::AuthFailed { provider, source: err }
    } else if chain_text.contains("timeout")
        || chain_text.contains("connection")
        || chain_text.contains("dns")
    {
        SecretError::Network { provider, source: err }
    } else {
        SecretError::Other(err)
    }
}
