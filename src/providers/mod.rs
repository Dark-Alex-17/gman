//! Secret provider trait and registry.
//!
//! Implementations provide storage/backends for secrets and a common
//! interface used by the CLI.
mod git_sync;
pub mod local;

use crate::providers::local::LocalProvider;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use thiserror::Error;
use validator::{Validate, ValidationErrors};

/// A secret storage backend capable of CRUD and sync, with optional
/// update and listing
pub trait SecretProvider {
    fn name(&self) -> &'static str;
    fn get_secret(&self, key: &str) -> Result<String>;
    fn set_secret(&self, key: &str, value: &str) -> Result<()>;
    fn update_secret(&self, _key: &str, _value: &str) -> Result<()> {
        Err(anyhow!(
            "update secret not supported for provider {}",
            self.name()
        ))
    }
    fn delete_secret(&self, key: &str) -> Result<()>;
    fn list_secrets(&self) -> Result<Vec<String>> {
        Err(anyhow!(
            "list secrets is not supported for the provider {}",
            self.name()
        ))
    }
    fn sync(&mut self) -> Result<()>;
}

/// Errors when parsing a provider identifier.
#[derive(Debug, Error)]
pub enum ParseProviderError {
    #[error("unsupported provider '{0}'")]
    Unsupported(String),
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
}

impl Validate for SupportedProvider {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            SupportedProvider::Local { provider_def } => provider_def.validate(),
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
        }
    }
}
