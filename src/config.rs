use crate::providers::{SecretProvider, SupportedProvider};
use log::debug;
use serde::{Deserialize, Serialize};
use serde_with::DisplayFromStr;
use serde_with::serde_as;
use std::borrow::Cow;
use std::path::PathBuf;
use validator::{Validate, ValidationError};

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
#[derive(Debug, Clone, Validate, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde_as(as = "DisplayFromStr")]
    pub provider: SupportedProvider,
    pub password_file: Option<PathBuf>,
    pub git_branch: Option<String>,
    pub git_remote_url: Option<String>,
    pub git_user_name: Option<String>,
    #[validate(email)]
    pub git_user_email: Option<String>,
    pub git_executable: Option<PathBuf>,
    #[validate(nested)]
    pub run_configs: Option<Vec<RunConfig>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            provider: SupportedProvider::Local(Default::default()),
            password_file: Config::local_provider_password_file(),
            git_branch: Some("main".into()),
            git_remote_url: None,
            git_user_name: None,
            git_user_email: None,
            git_executable: None,
            run_configs: None,
        }
    }
}

impl Config {
    pub fn extract_provider(&self) -> Box<dyn SecretProvider> {
        match &self.provider {
            SupportedProvider::Local(p) => {
                debug!("Using local secret provider");
                Box::new(*p)
            }
        }
    }

    pub fn local_provider_password_file() -> Option<PathBuf> {
        let mut path = dirs::home_dir().map(|p| p.join(".gman_password"));
        if let Some(p) = &path
            && !p.exists()
        {
            path = None;
        }

        path
    }
}
