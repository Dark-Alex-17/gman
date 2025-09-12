//! Secret provider trait and registry.
//!
//! Implementations provide storage/backends for secrets and a common
//! interface used by the CLI.
pub mod aws_secrets_manager;
mod git_sync;
pub mod local;

use crate::providers::local::LocalProvider;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use validator::{Validate, ValidationErrors};

/// A secret storage backend capable of CRUD, with optional
/// update, listing, and sync support.
#[async_trait::async_trait]
pub trait SecretProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn get_secret(&self, key: &str) -> Result<String>;
    async fn set_secret(&self, key: &str, value: &str) -> Result<()>;
    async fn update_secret(&self, _key: &str, _value: &str) -> Result<()> {
        Err(anyhow!(
            "update secret not supported for provider {}",
            self.name()
        ))
    }
    async fn delete_secret(&self, key: &str) -> Result<()>;
    async fn list_secrets(&self) -> Result<Vec<String>> {
        Err(anyhow!(
            "list secrets is not supported for the provider {}",
            self.name()
        ))
    }
    async fn sync(&mut self) -> Result<()> {
        Err(anyhow!(
            "sync is not supported for the provider {}",
            self.name()
        ))
    }
}

/// Registry of built-in providers.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
//TODO test that this works with the AWS config
pub enum SupportedProvider {
    Local {
        #[serde(flatten)]
        provider_def: LocalProvider,
    },
    AwsSecretsManager {
        #[serde(flatten)]
        provider_def: aws_secrets_manager::AwsSecretsManagerProvider,
    },
}

impl Validate for SupportedProvider {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            SupportedProvider::Local { provider_def } => provider_def.validate(),
            SupportedProvider::AwsSecretsManager { provider_def } => provider_def.validate(),
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
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SupportedProvider::Local { .. } => write!(f, "local"),
            SupportedProvider::AwsSecretsManager { .. } => write!(f, "aws_secrets_manager"),
        }
    }
}
