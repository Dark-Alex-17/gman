//! Application configuration and run-profile validation.
//!
//! The [`Config`] type captures global settings such as which secret provider
//! to use and Git sync preferences. The [`RunConfig`] type describes how to
//! inject secrets when wrapping a command.
//!
//! Example: validate a minimal run profile
//! ```
//! use gman::config::RunConfig;
//! use validator::Validate;
//!
//! let rc = RunConfig{
//!     name: Some("echo".into()),
//!     secrets: Some(vec!["api_key".into()]),
//!     files: None,
//!     flag: None,
//!     flag_position: None,
//!     arg_format: None,
//! };
//! rc.validate().unwrap();
//! ```
use crate::providers::local::LocalProvider;
use crate::providers::{SecretProvider, SupportedProvider};
use anyhow::{Context, Result};
use log::debug;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::{DisplayFromStr, skip_serializing_none};
use std::borrow::Cow;
use std::path::PathBuf;
use std::{env, fs};
use validator::{Validate, ValidationError};

#[skip_serializing_none]
/// Describe how to inject secrets for a named command profile.
///
/// A valid profile either defines no flag/file settings or provides a complete
/// set of `flag`, `flag_position`, and `arg_format`. Additionally, the flag
/// mode and the file‑injection mode are mutually exclusive.
#[derive(Debug, Clone, Validate, Serialize, Deserialize, PartialEq, Eq)]
#[validate(schema(function = "flags_or_none", skip_on_field_errors = false))]
#[validate(schema(function = "flags_or_files"))]
pub struct RunConfig {
    #[validate(required)]
    pub name: Option<String>,
    #[validate(required)]
    pub secrets: Option<Vec<String>>,
    pub files: Option<Vec<PathBuf>>,
    pub flag: Option<String>,
    #[validate(range(min = 1))]
    pub flag_position: Option<usize>,
    pub arg_format: Option<String>,
}

fn flags_or_none(run_config: &RunConfig) -> Result<(), ValidationError> {
    match (
        &run_config.flag,
        &run_config.flag_position,
        &run_config.arg_format,
    ) {
        (Some(_), Some(_), Some(format)) => {
            let has_key = format.contains("{{key}}");
            let has_value = format.contains("{{value}}");
            if has_key && has_value {
                Ok(())
            } else {
                let mut err = ValidationError::new("missing_placeholders");
                err.message = Some(Cow::Borrowed(
                    "must contain both '{{key}}' and '{{value}}' (with the '{{' and '}}' characters) in the arg_format",
                ));
                err.add_param(Cow::Borrowed("has_key"), &has_key);
                err.add_param(Cow::Borrowed("has_value"), &has_value);
                Err(err)
            }
        }
        (None, None, None) => Ok(()),
        _ => {
            let mut err = ValidationError::new("both_or_none");
            err.message = Some(Cow::Borrowed(
                "When defining a flag to pass secrets into the command with, all of 'flag', 'flag_position', and 'arg_format' must be defined in the run configuration",
            ));
            Err(err)
        }
    }
}

fn flags_or_files(run_config: &RunConfig) -> Result<(), ValidationError> {
    match (&run_config.flag, &run_config.files) {
        (Some(_), Some(_)) => {
            let mut err = ValidationError::new("flag_and_file");
            err.message = Some(Cow::Borrowed(
                "Cannot specify both 'flag' and 'file' in the same run configuration",
            ));
            Err(err)
        }
        _ => Ok(()),
    }
}

#[serde_as]
#[skip_serializing_none]
/// Configuration for a secret provider.
///
/// Example: create a local provider config and validate it
/// ```
/// use gman::config::ProviderConfig;
/// use gman::providers::SupportedProvider;
/// use gman::providers::local::LocalProvider;
/// use validator::Validate;
///
/// let provider_type = SupportedProvider::Local(LocalProvider);
/// let provider_config = ProviderConfig { provider_type, ..Default::default() };
/// provider_config.validate().unwrap();
/// ```
#[derive(Debug, Clone, Validate, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderConfig {
    #[validate(required)]
    pub name: Option<String>,
    #[serde_as(as = "DisplayFromStr")]
    #[serde(rename = "type")]
    pub provider_type: SupportedProvider,
    pub password_file: Option<PathBuf>,
    pub git_branch: Option<String>,
    pub git_remote_url: Option<String>,
    pub git_user_name: Option<String>,
    #[validate(email)]
    pub git_user_email: Option<String>,
    pub git_executable: Option<PathBuf>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            name: Some("local".into()),
            provider_type: SupportedProvider::Local(LocalProvider),
            password_file: Config::local_provider_password_file(),
            git_branch: Some("main".into()),
            git_remote_url: None,
            git_user_name: None,
            git_user_email: None,
            git_executable: None,
        }
    }
}

impl ProviderConfig {
    /// Instantiate the configured secret provider.
    ///
    /// ```no_run
    /// # use gman::config::ProviderConfig;
    /// let provider_config = ProviderConfig::default().extract_provider();
    /// println!("using provider: {}", provider_config.name());
    /// ```
    pub fn extract_provider(&self) -> Box<dyn SecretProvider> {
        match &self.provider_type {
            SupportedProvider::Local(p) => {
                debug!("Using local secret provider");
                Box::new(*p)
            }
        }
    }
}

#[serde_as]
#[skip_serializing_none]
/// Global configuration for the library and CLI.
///
/// Example: pick a provider and validate the configuration
/// ```
/// use gman::config::Config;
/// use gman::config::ProviderConfig;
/// use gman::providers::SupportedProvider;
/// use gman::providers::local::LocalProvider;
/// use validator::Validate;
///
/// let provider_type = SupportedProvider::Local(LocalProvider);
/// let provider_config = ProviderConfig { provider_type, ..Default::default() };
/// let cfg = Config{ providers: vec![provider_config], ..Default::default() };
/// cfg.validate().unwrap();
/// ```
#[derive(Debug, Clone, Validate, Serialize, Deserialize, PartialEq, Eq)]
#[validate(schema(function = "default_provider_exists"))]
pub struct Config {
    pub default_provider: Option<String>,
    #[validate(length(min = 1))]
    #[validate(nested)]
    pub providers: Vec<ProviderConfig>,
    #[validate(nested)]
    pub run_configs: Option<Vec<RunConfig>>,
}

fn default_provider_exists(config: &Config) -> Result<(), ValidationError> {
    if let Some(default) = &config.default_provider {
        if config
            .providers
            .iter()
            .any(|p| p.name.as_deref() == Some(default))
        {
            Ok(())
        } else {
            let mut err = ValidationError::new("default_provider_missing");
            err.message = Some(Cow::Borrowed(
                "The default_provider does not match any configured provider names",
            ));
            Err(err)
        }
    } else {
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_provider: Some("local".into()),
            providers: vec![ProviderConfig::default()],
            run_configs: None,
        }
    }
}

impl Config {
    /// Instantiate the configured secret provider.
    ///
    /// ```no_run
    /// # use gman::config::Config;
    /// let provider_config = Config::default().extract_provider_config(None).unwrap();
    /// println!("using provider config: {:?}", provider_config.name);
    /// ```
    pub fn extract_provider_config(&self, provider_name: Option<String>) -> Result<ProviderConfig> {
        let name = provider_name
            .or_else(|| self.default_provider.clone())
            .unwrap_or_else(|| "local".into());
        self.providers
            .iter()
            .find(|p| p.name.as_deref() == Some(&name))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No provider configuration found for '{}'", name))
    }

    /// Discover the default password file for the local provider.
    ///
    /// On most systems this resolves to `~/.gman_password` when the file
    /// exists, otherwise `None`.
    pub fn local_provider_password_file() -> Option<PathBuf> {
        let candidate = dirs::home_dir().map(|p| p.join(".gman_password"));
        match candidate {
            Some(p) if p.exists() => Some(p),
            _ => None,
        }
    }
}

/// Load and validate the application configuration.
///
/// This uses the `confy` crate to load the configuration from a file
/// (e.g. `~/.config/gman/config.yaml`). If the file does
/// not exist, a default configuration is created and saved.
///
/// ```no_run
/// # use gman::config::load_config;
/// let config = load_config().unwrap();
/// println!("loaded config: {:?}", config);
/// ```
pub fn load_config() -> Result<Config> {
    let xdg_path = env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);

    let mut config: Config = if let Some(base) = xdg_path.as_ref() {
        let app_dir = base.join("gman");
        let yml = app_dir.join("config.yml");
        let yaml = app_dir.join("config.yaml");
        if yml.exists() || yaml.exists() {
            let load_path = if yml.exists() { &yml } else { &yaml };
            let content = fs::read_to_string(load_path)
                .with_context(|| format!("failed to read config file '{}'", load_path.display()))?;
            let cfg: Config = serde_yaml::from_str(&content).with_context(|| {
                format!("failed to parse YAML config at '{}'", load_path.display())
            })?;
            cfg
        } else {
            confy::load("gman", "config")?
        }
    } else {
        confy::load("gman", "config")?
    };

    config.validate()?;

    config
        .providers
        .iter_mut()
        .filter(|p| matches!(p.provider_type, SupportedProvider::Local(_)))
        .for_each(|p| {
            if p.password_file.is_none()
                && let Some(local_password_file) = Config::local_provider_password_file()
            {
                p.password_file = Some(local_password_file);
            }
        });

    Ok(config)
}

/// Returns the configuration file path that `confy` will use for this app.
pub fn get_config_file_path() -> Result<PathBuf> {
    if let Some(base) = env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
        let dir = base.join("gman");
        let yml = dir.join("config.yml");
        let yaml = dir.join("config.yaml");
        if yml.exists() || yaml.exists() {
            return Ok(if yml.exists() { yml } else { yaml });
        }
        // Prefer .yml if creating anew
        return Ok(dir.join("config.yml"));
    }
    Ok(confy::get_configuration_file_path("gman", "config")?)
}
