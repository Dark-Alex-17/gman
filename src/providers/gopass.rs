use crate::providers::{ENV_PATH, SecretProvider};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use validator::Validate;

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

    async fn get_secret(&self, key: &str) -> Result<String> {
        ensure_gopass_installed()?;

        let mut child = Command::new("gopass")
            .args(["show", "-yfon", key])
            .env("PATH", ENV_PATH.as_ref().expect("No ENV_PATH set"))
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to spawn gopass command")?;

        let mut output = String::new();
        child
            .stdout
            .as_mut()
            .expect("Failed to open gopass stdout")
            .read_to_string(&mut output)
            .context("Failed to read gopass output")?;

        let status = child.wait().context("Failed to wait on gopass process")?;
        if !status.success() {
            return Err(anyhow!("gopass command failed with status: {}", status));
        }

        Ok(output.trim_end_matches(&['\r', '\n'][..]).to_string())
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        ensure_gopass_installed()?;

        let mut child = Command::new("gopass")
            .args(["insert", "-f", key])
            .env("PATH", ENV_PATH.as_ref().expect("No ENV_PATH set"))
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to spawn gopass command")?;

        {
            let stdin = child.stdin.as_mut().expect("Failed to open gopass stdin");
            stdin
                .write_all(value.as_bytes())
                .context("Failed to write to gopass stdin")?;
        }

        let status = child.wait().context("Failed to wait on gopass process")?;
        if !status.success() {
            return Err(anyhow!("gopass command failed with status: {}", status));
        }

        Ok(())
    }

    async fn update_secret(&self, key: &str, value: &str) -> Result<()> {
        ensure_gopass_installed()?;

        self.set_secret(key, value).await
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        ensure_gopass_installed()?;

        let mut child = Command::new("gopass")
            .args(["rm", "-f", key])
            .env("PATH", ENV_PATH.as_ref().expect("No ENV_PATH set"))
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to spawn gopass command")?;

        let status = child.wait().context("Failed to wait on gopass process")?;
        if !status.success() {
            return Err(anyhow!("gopass command failed with status: {}", status));
        }

        Ok(())
    }

    async fn list_secrets(&self) -> Result<Vec<String>> {
        ensure_gopass_installed()?;

        let mut child = Command::new("gopass")
            .args(["ls", "-f"])
            .env("PATH", ENV_PATH.as_ref().expect("No ENV_PATH set"))
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to spawn gopass command")?;

        let mut output = String::new();
        child
            .stdout
            .as_mut()
            .expect("Failed to open gopass stdout")
            .read_to_string(&mut output)
            .context("Failed to read gopass output")?;

        let status = child.wait().context("Failed to wait on gopass process")?;
        if !status.success() {
            return Err(anyhow!("gopass command failed with status: {}", status));
        }

        let secrets: Vec<String> = output
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        Ok(secrets)
    }

    async fn sync(&mut self) -> Result<()> {
        ensure_gopass_installed()?;
        let mut child = Command::new("gopass");
        child.arg("sync");

        if let Some(store) = &self.store {
            child.args(["-s", store]);
        }

        let status = child
            .env("PATH", ENV_PATH.as_ref().expect("No ENV_PATH set"))
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to spawn gopass command")?
            .wait()
            .context("Failed to wait on gopass process")?;

        if !status.success() {
            return Err(anyhow!("gopass command failed with status: {}", status));
        }

        Ok(())
    }
}

fn ensure_gopass_installed() -> Result<()> {
    if which::which("gopass").is_err() {
        Err(anyhow!(
            "Gopass is not installed or not found in PATH. Please install Gopass from https://gopass.pw/"
        ))
    } else {
        Ok(())
    }
}
