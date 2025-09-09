use crate::providers::{SecretProvider, SupportedProvider};
use log::debug;
use serde::{Deserialize, Serialize};
use serde_with::DisplayFromStr;
use serde_with::serde_as;
use std::path::PathBuf;
use validator::Validate;

#[serde_as]
#[derive(Debug, Clone, Validate, Serialize, Deserialize)]
pub struct Config {
    #[serde_as(as = "DisplayFromStr")]
    pub provider: SupportedProvider,
    pub password_file: Option<PathBuf>,
    pub git_branch: Option<String>,
		/// The git remote URL to push changes to (e.g. git@github.com:user/repo.git)
    pub git_remote_url: Option<String>,
    pub git_user_name: Option<String>,
    #[validate(email)]
    pub git_user_email: Option<String>,
		pub git_executable: Option<PathBuf>,
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
        if let Some(p) = &path {
            if !p.exists() {
                path = None;
            }
        }

        path
    }
}
