use crate::providers::{ENV_PATH, SecretProvider};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::io::Read;
use std::process::{Command, Stdio};
use validator::Validate;

#[skip_serializing_none]
/// 1Password-based secret provider.
/// See [1Password CLI](https://developer.1password.com/docs/cli/) for more
/// information.
///
/// You must already have the 1Password CLI (`op`) installed and configured
/// on your system.
///
/// This provider stores secrets as 1Password Password items. It requires
/// an optional vault name and an optional account identifier to be specified.
/// If no vault is specified, the user's default vault is used. If no account
/// is specified, the default signed-in account is used.
///
/// Example
/// ```no_run
/// use gman::providers::one_password::OnePasswordProvider;
/// use gman::providers::{SecretProvider, SupportedProvider};
/// use gman::config::Config;
///
/// let provider = OnePasswordProvider::default();
/// let _ = provider.set_secret("MY_SECRET", "value");
/// ```
#[derive(Debug, Default, Clone, Validate, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OnePasswordProvider {
    pub vault: Option<String>,
    pub account: Option<String>,
}

impl OnePasswordProvider {
    fn base_command(&self) -> Command {
        let mut cmd = Command::new("op");
        cmd.env("PATH", ENV_PATH.as_ref().expect("No ENV_PATH set"));
        if let Some(account) = &self.account {
            cmd.args(["--account", account]);
        }
        cmd
    }

    fn vault_args(&self) -> Vec<&str> {
        match &self.vault {
            Some(vault) => vec!["--vault", vault],
            None => vec![],
        }
    }
}

#[async_trait::async_trait]
impl SecretProvider for OnePasswordProvider {
    fn name(&self) -> &'static str {
        "OnePasswordProvider"
    }

    async fn get_secret(&self, key: &str) -> Result<String> {
        ensure_op_installed()?;

        let mut cmd = self.base_command();
        cmd.args(["item", "get", key, "--fields", "password", "--reveal"]);
        cmd.args(self.vault_args());
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = cmd.spawn().context("Failed to spawn op command")?;

        let mut output = String::new();
        child
            .stdout
            .as_mut()
            .expect("Failed to open op stdout")
            .read_to_string(&mut output)
            .context("Failed to read op output")?;

        let status = child.wait().context("Failed to wait on op process")?;
        if !status.success() {
            return Err(anyhow!("op command failed with status: {}", status));
        }

        Ok(output.trim_end_matches(&['\r', '\n'][..]).to_string())
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        ensure_op_installed()?;

        let mut cmd = self.base_command();
        cmd.args(["item", "create", "--category", "password", "--title", key]);
        cmd.args(self.vault_args());
        cmd.arg(format!("password={}", value));
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = cmd.spawn().context("Failed to spawn op command")?;

        let status = child.wait().context("Failed to wait on op process")?;
        if !status.success() {
            return Err(anyhow!("op command failed with status: {}", status));
        }

        Ok(())
    }

    async fn update_secret(&self, key: &str, value: &str) -> Result<()> {
        ensure_op_installed()?;

        let mut cmd = self.base_command();
        cmd.args(["item", "edit", key]);
        cmd.args(self.vault_args());
        cmd.arg(format!("password={}", value));
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = cmd.spawn().context("Failed to spawn op command")?;

        let status = child.wait().context("Failed to wait on op process")?;
        if !status.success() {
            return Err(anyhow!("op command failed with status: {}", status));
        }

        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        ensure_op_installed()?;

        let mut cmd = self.base_command();
        cmd.args(["item", "delete", key]);
        cmd.args(self.vault_args());
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let mut child = cmd.spawn().context("Failed to spawn op command")?;

        let status = child.wait().context("Failed to wait on op process")?;
        if !status.success() {
            return Err(anyhow!("op command failed with status: {}", status));
        }

        Ok(())
    }

    async fn list_secrets(&self) -> Result<Vec<String>> {
        ensure_op_installed()?;

        let mut cmd = self.base_command();
        cmd.args(["item", "list", "--format", "json"]);
        cmd.args(self.vault_args());
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = cmd.spawn().context("Failed to spawn op command")?;

        let mut output = String::new();
        child
            .stdout
            .as_mut()
            .expect("Failed to open op stdout")
            .read_to_string(&mut output)
            .context("Failed to read op output")?;

        let status = child.wait().context("Failed to wait on op process")?;
        if !status.success() {
            return Err(anyhow!("op command failed with status: {}", status));
        }

        let items: Vec<serde_json::Value> =
            serde_json::from_str(&output).context("Failed to parse op item list JSON output")?;

        let secrets: Vec<String> = items
            .iter()
            .filter_map(|item| item.get("title").and_then(|t| t.as_str()))
            .map(|s| s.to_string())
            .collect();

        Ok(secrets)
    }
}

fn ensure_op_installed() -> Result<()> {
    if which::which("op").is_err() {
        Err(anyhow!(
            "1Password CLI (op) is not installed or not found in PATH. \
             Please install it from https://developer.1password.com/docs/cli/get-started/"
        ))
    } else {
        Ok(())
    }
}
