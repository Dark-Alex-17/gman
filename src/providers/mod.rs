//! Secret provider trait and registry.
//!
//! Implementations provide storage/backends for secrets and a common
//! interface used by the CLI.
pub mod aws_secrets_manager;
pub mod azure_key_vault;
pub mod error;
pub mod gcp_secret_manager;
pub mod git_sync;
pub mod gopass;
pub mod local;
pub mod one_password;

use std::fmt::{Display, Formatter};
use std::{env, fmt};

use anyhow::{Context, Result};
use aws_secrets_manager::AwsSecretsManagerProvider;
use azure_key_vault::AzureKeyVaultProvider;
use gcp_secret_manager::GcpSecretManagerProvider;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationErrors};

pub use crate::providers::error::SecretError;
pub use crate::providers::git_sync::SyncError;
use crate::providers::gopass::GopassProvider;
use crate::providers::local::LocalProvider;
use crate::providers::one_password::OnePasswordProvider;

pub(in crate::providers) static ENV_PATH: Lazy<Result<String>> =
    Lazy::new(|| env::var("PATH").context("No PATH environment variable"));

/// A secret storage backend capable of CRUD, with optional
/// update, listing, and sync support.
#[async_trait::async_trait]
pub trait SecretProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn get_secret(&self, key: &str) -> Result<String, SecretError>;
    async fn set_secret(&self, key: &str, value: &str) -> Result<(), SecretError>;
    async fn update_secret(&self, _key: &str, _value: &str) -> Result<(), SecretError> {
        Err(SecretError::Unsupported {
            operation: "update_secret",
            provider: self.name(),
        })
    }
    async fn delete_secret(&self, key: &str) -> Result<(), SecretError>;
    async fn list_secrets(&self) -> Result<Vec<String>, SecretError> {
        Err(SecretError::Unsupported {
            operation: "list_secrets",
            provider: self.name(),
        })
    }
    async fn sync(&mut self) -> Result<(), SecretError> {
        Err(SecretError::Unsupported {
            operation: "sync",
            provider: self.name(),
        })
    }
}

/// Registry of built-in providers.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
pub enum SupportedProvider {
    Local {
        #[serde(flatten)]
        provider_def: LocalProvider,
    },
    AwsSecretsManager {
        #[serde(flatten)]
        provider_def: AwsSecretsManagerProvider,
    },
    GcpSecretManager {
        #[serde(flatten)]
        provider_def: GcpSecretManagerProvider,
    },
    AzureKeyVault {
        #[serde(flatten)]
        provider_def: AzureKeyVaultProvider,
    },
    Gopass {
        #[serde(flatten)]
        provider_def: GopassProvider,
    },
    OnePassword {
        #[serde(flatten)]
        provider_def: OnePasswordProvider,
    },
}

impl Validate for SupportedProvider {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            SupportedProvider::Local { provider_def } => provider_def.validate(),
            SupportedProvider::AwsSecretsManager { provider_def } => provider_def.validate(),
            SupportedProvider::GcpSecretManager { provider_def } => provider_def.validate(),
            SupportedProvider::AzureKeyVault { provider_def } => provider_def.validate(),
            SupportedProvider::Gopass { provider_def } => provider_def.validate(),
            SupportedProvider::OnePassword { provider_def } => provider_def.validate(),
        }
    }
}

impl Default for SupportedProvider {
    fn default() -> Self {
        SupportedProvider::Local {
            provider_def: LocalProvider::default(),
        }
    }
}

impl Display for SupportedProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SupportedProvider::Local { .. } => write!(f, "local"),
            SupportedProvider::AwsSecretsManager { .. } => write!(f, "aws_secrets_manager"),
            SupportedProvider::GcpSecretManager { .. } => write!(f, "gcp_secret_manager"),
            SupportedProvider::AzureKeyVault { .. } => write!(f, "azure_key_vault"),
            SupportedProvider::Gopass { .. } => write!(f, "gopass"),
            SupportedProvider::OnePassword { .. } => write!(f, "one_password"),
        }
    }
}

#[allow(unused_imports)]
pub(crate) use crate::providers::error::{
    classify_aws_error, classify_azure_error, classify_gcp_error,
};
