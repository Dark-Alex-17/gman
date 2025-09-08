use crate::providers::{SecretProvider, SupportedProvider};
use serde::{Deserialize, Serialize};
use serde_with::DisplayFromStr;
use serde_with::serde_as;
use std::path::PathBuf;
use log::{debug};
use validator::Validate;

#[serde_as]
#[derive(Debug, Validate, Serialize, Deserialize)]
pub struct Config {
    #[serde_as(as = "DisplayFromStr")]
    pub provider: SupportedProvider,
    pub password_file: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            provider: SupportedProvider::Local(Default::default()),
            password_file: Config::local_provider_password_file(),
        }
    }
}

impl Config {
	pub fn extract_provider(&self) -> Box<&dyn SecretProvider> {
		match &self.provider {
			SupportedProvider::Local(p) => {
				debug!("Using local secret provider");
				Box::new(p)
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
