use std::io::Read;
use std::process::{Command, Stdio};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use validator::Validate;

use crate::providers::error::SecretError;
use crate::providers::{ENV_PATH, SecretProvider};

const PROVIDER: &str = "one_password";

fn map_spawn_err(e: std::io::Error) -> SecretError {
    if e.kind() == std::io::ErrorKind::NotFound {
        SecretError::CliNotFound { tool: "op" }
    } else {
        SecretError::Io(e)
    }
}

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

fn classify_op_stderr(stderr: &str, key: Option<&str>) -> SecretError {
    let lc = stderr.to_lowercase();
    if lc.contains("isn't an item") || lc.contains("doesn't exist") || lc.contains("not found") {
        SecretError::NotFound {
            key: key.unwrap_or("").to_string(),
            provider: PROVIDER,
        }
    } else if lc.contains("not currently signed in")
        || lc.contains("session expired")
        || lc.contains("not signed in")
    {
        SecretError::AuthFailed {
            provider: PROVIDER,
            source: anyhow!("op auth error: {}", stderr.trim()),
        }
    } else {
        SecretError::Other(anyhow!("op command failed: {}", stderr.trim()))
    }
}

#[async_trait::async_trait]
impl SecretProvider for OnePasswordProvider {
    fn name(&self) -> &'static str {
        "OnePasswordProvider"
    }

    async fn get_secret(&self, key: &str) -> Result<String, SecretError> {
        ensure_op_installed()?;

        let mut cmd = self.base_command();
        cmd.args(["item", "get", key, "--fields", "password", "--reveal"]);
        cmd.args(self.vault_args());
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(map_spawn_err)?;

        let mut output = String::new();
        child
            .stdout
            .as_mut()
            .expect("Failed to open op stdout")
            .read_to_string(&mut output)?;

        let result = child.wait_with_output()?;
        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(classify_op_stderr(&stderr, Some(key)));
        }

        Ok(output.trim_end_matches(&['\r', '\n'][..]).to_string())
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<(), SecretError> {
        ensure_op_installed()?;

        let mut cmd = self.base_command();
        cmd.args(["item", "create", "--category", "password", "--title", key]);
        cmd.args(self.vault_args());
        cmd.arg(format!("password={}", value));
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = cmd.spawn().map_err(map_spawn_err)?;

        let result = child.wait_with_output()?;
        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(classify_op_stderr(&stderr, Some(key)));
        }

        Ok(())
    }

    async fn update_secret(&self, key: &str, value: &str) -> Result<(), SecretError> {
        ensure_op_installed()?;

        let mut cmd = self.base_command();
        cmd.args(["item", "edit", key]);
        cmd.args(self.vault_args());
        cmd.arg(format!("password={}", value));
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = cmd.spawn().map_err(map_spawn_err)?;

        let result = child.wait_with_output()?;
        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(classify_op_stderr(&stderr, Some(key)));
        }

        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> Result<(), SecretError> {
        ensure_op_installed()?;

        let mut cmd = self.base_command();
        cmd.args(["item", "delete", key]);
        cmd.args(self.vault_args());
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::piped());

        let child = cmd.spawn().map_err(map_spawn_err)?;

        let result = child.wait_with_output()?;
        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(classify_op_stderr(&stderr, Some(key)));
        }

        Ok(())
    }

    async fn list_secrets(&self) -> Result<Vec<String>, SecretError> {
        ensure_op_installed()?;

        let mut cmd = self.base_command();
        cmd.args(["item", "list", "--format", "json"]);
        cmd.args(self.vault_args());
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(map_spawn_err)?;

        let mut output = String::new();
        child
            .stdout
            .as_mut()
            .expect("Failed to open op stdout")
            .read_to_string(&mut output)?;

        let result = child.wait_with_output()?;
        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(classify_op_stderr(&stderr, None));
        }

        let items: Vec<serde_json::Value> = serde_json::from_str(&output)
            .map_err(|e| SecretError::Other(anyhow!("failed to parse op output: {}", e)))?;

        let secrets: Vec<String> = items
            .iter()
            .filter_map(|item| item.get("title").and_then(|t| t.as_str()))
            .map(|s| s.to_string())
            .collect();

        Ok(secrets)
    }
}

fn ensure_op_installed() -> Result<(), SecretError> {
    if which::which("op").is_err() {
        Err(SecretError::CliNotFound { tool: "op" })
    } else {
        Ok(())
    }
}
