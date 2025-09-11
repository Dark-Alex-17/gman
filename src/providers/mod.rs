//! Secret provider trait and registry.
//!
//! Implementations provide storage/backends for secrets and a common
//! interface used by the CLI.
//!
//! Selecting a provider from a string:
//! ```
//! use std::str::FromStr;
//! use gman::providers::SupportedProvider;
//!
//! let p = SupportedProvider::from_str("local").unwrap();
//! assert_eq!(p.to_string(), "local");
//! ```
mod git_sync;
pub mod local;

use crate::config::ProviderConfig;
use crate::providers::local::LocalProvider;
use anyhow::{Result, anyhow};
use serde::Deserialize;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use thiserror::Error;

/// A secret storage backend capable of CRUD and sync, with optional
/// update and listing
pub trait SecretProvider {
    fn name(&self) -> &'static str;
    fn get_secret(&self, config: &ProviderConfig, key: &str) -> Result<String>;
    fn set_secret(&self, config: &ProviderConfig, key: &str, value: &str) -> Result<()>;
    fn update_secret(&self, _config: &ProviderConfig, _key: &str, _value: &str) -> Result<()> {
        Err(anyhow!(
            "update secret not supported for provider {}",
            self.name()
        ))
    }
    fn delete_secret(&self, config: &ProviderConfig, key: &str) -> Result<()>;
    fn list_secrets(&self, _config: &ProviderConfig) -> Result<Vec<String>> {
        Err(anyhow!(
            "list secrets is not supported for the provider {}",
            self.name()
        ))
    }
    fn sync(&self, config: &mut ProviderConfig) -> Result<()>;
}

/// Errors when parsing a provider identifier.
#[derive(Debug, Error)]
pub enum ParseProviderError {
    #[error("unsupported provider '{0}'")]
    Unsupported(String),
}

/// Registry of built-in providers.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
pub enum SupportedProvider {
    Local(LocalProvider),
}

impl Default for SupportedProvider {
    fn default() -> Self {
        SupportedProvider::Local(LocalProvider)
    }
}

impl FromStr for SupportedProvider {
    type Err = ParseProviderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "local" => Ok(SupportedProvider::Local(LocalProvider)),
            _ => Err(ParseProviderError::Unsupported(s.to_string())),
        }
    }
}

impl Display for SupportedProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SupportedProvider::Local(_) => write!(f, "local"),
        }
    }
}
