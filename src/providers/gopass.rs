use std::io::{Read, Write};
use std::process::{Command, Stdio};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use validator::Validate;

use crate::providers::error::SecretError;
use crate::providers::{ENV_PATH, SecretProvider};

const PROVIDER: &str = "gopass";

fn map_spawn_err(e: std::io::Error) -> SecretError {
    if e.kind() == std::io::ErrorKind::NotFound {
        SecretError::CliNotFound { tool: "gopass" }
    } else {
        SecretError::Io(e)
    }
}

#[skip_serializing_none]
/// Gopass-based secret provider
/// See [Gopass](https://gopass.pw/) for more information.
///
/// You must already have gopass installed and configured on your system.
///
/// This provider stores secrets in a gopass store. It requires
/// an optional store name to be specified. If no store name is
/// specified, the default store will be used.
///
/// Example
/// ```no_run
/// use gman::providers::gopass::GopassProvider;
/// use gman::providers::{SecretProvider, SupportedProvider};
/// use gman::config::Config;
///
/// let provider = GopassProvider::default();
/// let _ = provider.set_secret("MY_SECRET", "value");
/// ```
#[derive(Debug, Default, Clone, Validate, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GopassProvider {
    pub store: Option<String>,
}

#[async_trait::async_trait]
impl SecretProvider for GopassProvider {
    fn name(&self) -> &'static str {
        "GopassProvider"
    }

    async fn get_secret(&self, key: &str) -> Result<String, SecretError> {
        ensure_gopass_installed()?;

        let mut child = Command::new("gopass")
            .args(["show", "-yfon", key])
            .env("PATH", ENV_PATH.as_ref().expect("No ENV_PATH set"))
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(map_spawn_err)?;

        let mut output = String::new();
        child
            .stdout
            .as_mut()
            .expect("Failed to open gopass stdout")
            .read_to_string(&mut output)?;

        let status = child.wait()?;
        if !status.success() {
            return Err(SecretError::NotFound {
                key: key.to_string(),
                provider: PROVIDER,
            });
        }

        Ok(output.trim_end_matches(&['\r', '\n'][..]).to_string())
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<(), SecretError> {
        ensure_gopass_installed()?;

        let mut child = Command::new("gopass")
            .args(["insert", "-f", key])
            .env("PATH", ENV_PATH.as_ref().expect("No ENV_PATH set"))
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(map_spawn_err)?;

        {
            let stdin = child.stdin.as_mut().expect("Failed to open gopass stdin");
            stdin.write_all(value.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.to_lowercase().contains("already exists") {
                return Err(SecretError::AlreadyExists {
                    key: key.to_string(),
                    provider: PROVIDER,
                });
            }

            return Err(SecretError::Other(anyhow!(
                "gopass insert failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    async fn update_secret(&self, key: &str, value: &str) -> Result<(), SecretError> {
        ensure_gopass_installed()?;

        self.set_secret(key, value).await
    }

    async fn delete_secret(&self, key: &str) -> Result<(), SecretError> {
        ensure_gopass_installed()?;

        let mut child = Command::new("gopass")
            .args(["rm", "-f", key])
            .env("PATH", ENV_PATH.as_ref().expect("No ENV_PATH set"))
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(map_spawn_err)?;

        let status = child.wait()?;
        if !status.success() {
            return Err(SecretError::NotFound {
                key: key.to_string(),
                provider: PROVIDER,
            });
        }

        Ok(())
    }

    async fn list_secrets(&self) -> Result<Vec<String>, SecretError> {
        ensure_gopass_installed()?;

        let mut child = Command::new("gopass")
            .args(["ls", "-f"])
            .env("PATH", ENV_PATH.as_ref().expect("No ENV_PATH set"))
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(map_spawn_err)?;

        let mut output = String::new();
        child
            .stdout
            .as_mut()
            .expect("Failed to open gopass stdout")
            .read_to_string(&mut output)?;

        let result = child.wait_with_output()?;
        if !result.status.success() {
            return Err(SecretError::Other(anyhow!(
                "gopass ls failed: {}",
                String::from_utf8_lossy(&result.stderr)
            )));
        }

        let secrets: Vec<String> = output
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        Ok(secrets)
    }

    async fn sync(&mut self) -> Result<(), SecretError> {
        ensure_gopass_installed()?;
        let mut child = Command::new("gopass");
        child.arg("sync");

        if let Some(store) = &self.store {
            child.args(["-s", store]);
        }

        let output = child
            .env("PATH", ENV_PATH.as_ref().expect("No ENV_PATH set"))
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(map_spawn_err)?
            .wait_with_output()?;

        if !output.status.success() {
            return Err(SecretError::Network {
                provider: PROVIDER,
                source: anyhow!(
                    "gopass sync failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            });
        }

        Ok(())
    }
}

fn ensure_gopass_installed() -> Result<(), SecretError> {
    if which::which("gopass").is_err() {
        Err(SecretError::CliNotFound { tool: "gopass" })
    } else {
        Ok(())
    }
}
