mod git_sync;
pub mod local;

use crate::config::Config;
use crate::providers::local::LocalProvider;
use anyhow::{Result, anyhow};
use serde::Deserialize;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use thiserror::Error;

pub trait SecretProvider {
    fn name(&self) -> &'static str;
    fn get_secret(&self, config: &Config, key: &str) -> Result<String>;
    fn set_secret(&self, config: &Config, key: &str, value: &str) -> Result<()>;
    fn update_secret(&self, _config: &Config, _key: &str, _value: &str) -> Result<()> {
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
    fn sync(&self, config: &mut Config) -> Result<()>;
}

#[derive(Debug, Error)]
pub enum ParseProviderError {
    #[error("unsupported provider '{0}'")]
    Unsupported(String),
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
pub enum SupportedProvider {
    Local(LocalProvider),
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
