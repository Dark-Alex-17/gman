use anyhow::{Context, anyhow, bail};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{env, fs};
use zeroize::Zeroize;

use crate::config::Config;
use crate::providers::SecretProvider;
use crate::providers::git_sync::{SyncOpts, repo_name_from_url, sync_and_push};
use crate::{
    ARGON_M_COST_KIB, ARGON_P, ARGON_T_COST, HEADER, KDF, KEY_LEN, NONCE_LEN, SALT_LEN, VERSION,
};
use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng},
};
use dialoguer::{Input, theme};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use theme::ColorfulTheme;
use validator::Validate;

#[skip_serializing_none]
/// File-based vault provider with optional Git sync.
///
/// This provider stores encrypted envelopes in a per-user configuration
/// directory via `confy`. A password is obtained from a configured password
/// file or via an interactive prompt.
///
/// Example
/// ```no_run
/// use gman::providers::local::LocalProvider;
/// use gman::providers::{SecretProvider, SupportedProvider};
/// use gman::config::{Config, ProviderConfig};
///
/// let provider = LocalProvider::default();
/// // Will prompt for a password when reading/writing secrets unless a
/// // password file is configured.
/// let _ = provider.set_secret("MY_SECRET", "value");
/// ```
#[derive(Debug, Clone, Validate, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalProvider {
    pub password_file: Option<PathBuf>,
    pub git_branch: Option<String>,
    pub git_remote_url: Option<String>,
    pub git_user_name: Option<String>,
    #[validate(email)]
    pub git_user_email: Option<String>,
    pub git_executable: Option<PathBuf>,
}

impl Default for LocalProvider {
    fn default() -> Self {
        Self {
            password_file: Config::local_provider_password_file(),
            git_branch: Some("main".into()),
            git_remote_url: None,
            git_user_name: None,
            git_user_email: None,
            git_executable: None,
        }
    }
}

#[async_trait::async_trait]
impl SecretProvider for LocalProvider {
    fn name(&self) -> &'static str {
        "LocalProvider"
    }

    async fn get_secret(&self, key: &str) -> Result<String> {
        let vault_path = self.active_vault_path()?;
        let vault: HashMap<String, String> = load_vault(&vault_path).unwrap_or_default();
        let envelope = vault
            .get(key)
            .with_context(|| format!("key '{key}' not found in the vault"))?;

        let password = self.get_password()?;
        let plaintext = decrypt_string(&password, envelope)?;
        drop(password);

        Ok(plaintext)
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        let vault_path = self.active_vault_path()?;
        let mut vault: HashMap<String, String> = load_vault(&vault_path).unwrap_or_default();
        if vault.contains_key(key) {
            error!(
                "Key '{key}' already exists in the vault. Use a different key or delete the existing one first."
            );
            bail!("key '{key}' already exists");
        }

        let password = self.get_password()?;
        let envelope = encrypt_string(&password, value)?;
        drop(password);

        vault.insert(key.to_string(), envelope);

        store_vault(&vault_path, &vault).with_context(|| "failed to save secret to the vault")
    }

    async fn update_secret(&self, key: &str, value: &str) -> Result<()> {
        let vault_path = self.active_vault_path()?;
        let mut vault: HashMap<String, String> = load_vault(&vault_path).unwrap_or_default();

        let password = self.get_password()?;
        let envelope = encrypt_string(&password, value)?;
        drop(password);

        if vault.contains_key(key) {
            debug!("Key '{key}' exists in vault. Overwriting previous value");
            let vault_entry = vault
                .get_mut(key)
                .with_context(|| format!("key '{key}' not found in the vault"))?;
            *vault_entry = envelope;

            return store_vault(&vault_path, &vault)
                .with_context(|| "failed to save secret to the vault");
        }

        vault.insert(key.to_string(), envelope);
        store_vault(&vault_path, &vault).with_context(|| "failed to save secret to the vault")
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        let vault_path = self.active_vault_path()?;
        let mut vault: HashMap<String, String> = load_vault(&vault_path).unwrap_or_default();
        if !vault.contains_key(key) {
            error!("Key '{key}' does not exist in the vault.");
            bail!("key '{key}' does not exist");
        }

        vault.remove(key);
        store_vault(&vault_path, &vault).with_context(|| "failed to save secret to the vault")
    }

    async fn list_secrets(&self) -> Result<Vec<String>> {
        let vault_path = self.active_vault_path()?;
        let vault: HashMap<String, String> = load_vault(&vault_path).unwrap_or_default();
        let keys: Vec<String> = vault.keys().cloned().collect();

        Ok(keys)
    }

    async fn sync(&mut self) -> Result<()> {
        let mut config_changed = false;

        if self.git_branch.is_none() {
            config_changed = true;
            debug!("Prompting user to set git_branch in config for sync");
            let branch: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter git branch to sync with")
                .default("main".into())
                .interact_text()?;

            self.git_branch = Some(branch);
        }

        if self.git_remote_url.is_none() {
            config_changed = true;
            debug!("Prompting user to set git_remote in config for sync");
            let remote: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter remote git URL to sync with")
                .validate_with(|s: &String| {
                    LocalProvider {
                        git_remote_url: Some(s.clone()),
                        ..LocalProvider::default()
                    }
                    .validate()
                    .map(|_| ())
                    .map_err(|e| e.to_string())
                })
                .interact_text()?;

            self.git_remote_url = Some(remote);
        }

        if config_changed {
            debug!("Saving updated config");
            confy::store("gman", "config", &self)
                .with_context(|| "failed to save updated config")?;
        }

        let sync_opts = SyncOpts {
            remote_url: &self.git_remote_url,
            branch: &self.git_branch,
            user_name: &self.git_user_name,
            user_email: &self.git_user_email,
            git_executable: &self.git_executable,
        };

        sync_and_push(&sync_opts)
    }
}

impl LocalProvider {
    fn repo_dir_for_config(&self) -> Result<Option<PathBuf>> {
        if let Some(remote) = &self.git_remote_url {
            let name = repo_name_from_url(remote);
            let dir = base_config_dir()?.join(format!(".{}", name));
            Ok(Some(dir))
        } else {
            Ok(None)
        }
    }

    fn active_vault_path(&self) -> Result<PathBuf> {
        if let Some(dir) = self.repo_dir_for_config()?
            && dir.exists()
        {
            return Ok(dir.join("vault.yml"));
        }

        default_vault_path()
    }

    fn get_password(&self) -> Result<SecretString> {
        if let Some(password_file) = &self.password_file {
            let password = SecretString::new(
                fs::read_to_string(password_file)
                    .with_context(|| format!("failed to read password file {:?}", password_file))?
                    .trim()
                    .to_string()
                    .into(),
            );

            Ok(password)
        } else {
            let password = rpassword::prompt_password("\nPassword: ")?;
            Ok(SecretString::new(password.into()))
        }
    }
}

fn default_vault_path() -> Result<PathBuf> {
    let xdg_path = env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);

    if let Some(xdg) = xdg_path {
        return Ok(xdg.join("gman").join("vault.yml"));
    }

    confy::get_configuration_file_path("gman", "vault").with_context(|| "get config dir")
}

fn base_config_dir() -> Result<PathBuf> {
    default_vault_path()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("Failed to determine config dir"))
}

fn load_vault(path: &Path) -> Result<HashMap<String, String>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let s = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let map: HashMap<String, String> = serde_yaml::from_str(&s).unwrap_or_default();
    Ok(map)
}

fn store_vault(path: &Path, map: &HashMap<String, String>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let s = serde_yaml::to_string(map).with_context(|| "serialize vault")?;
    fs::write(path, s).with_context(|| format!("write {}", path.display()))
}

fn encrypt_string(password: &SecretString, plaintext: &str) -> Result<String> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new(&key);
    let aad = format!("{};{}", HEADER, VERSION);

    let nonce = XNonce::from_slice(&nonce_bytes);
    let mut pt = plaintext.as_bytes().to_vec();
    let ct = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &pt,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;
    pt.zeroize();

    let env = format!(
        "{};{};{};m={m},t={t},p={p};salt={salt};nonce={nonce};ct={ct}",
        HEADER,
        VERSION,
        KDF,
        m = ARGON_M_COST_KIB,
        t = ARGON_T_COST,
        p = ARGON_P,
        salt = B64.encode(salt),
        nonce = B64.encode(nonce_bytes),
        ct = B64.encode(&ct),
    );

    drop(cipher);
    salt.zeroize();
    nonce_bytes.zeroize();

    Ok(env)
}

fn derive_key_with_params(
    password: &SecretString,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p: u32,
) -> Result<Key> {
    let params = Params::new(m_cost, t_cost, p, Some(KEY_LEN))
        .map_err(|e| anyhow!("argon2 params error: {:?}", e))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key_bytes)
        .map_err(|e| anyhow!("argon2 derive error: {:?}", e))?;
    key_bytes.zeroize();
    let key = Key::from_slice(&key_bytes);
    Ok(*key)
}

fn derive_key(password: &SecretString, salt: &[u8]) -> Result<Key> {
    derive_key_with_params(password, salt, ARGON_M_COST_KIB, ARGON_T_COST, ARGON_P)
}

fn decrypt_string(password: &SecretString, envelope: &str) -> Result<String> {
    let parts: Vec<&str> = envelope.trim().split(';').collect();
    if parts.len() < 7 {
        debug!("Invalid envelope format: {:?}", parts);
        bail!("invalid envelope format");
    }
    if parts[0] != HEADER {
        debug!("Invalid header: {}", parts[0]);
        bail!("unexpected header");
    }
    if parts[1] != VERSION {
        debug!("Unsupported version: {}", parts[1]);
        bail!("unsupported version {}", parts[1]);
    }
    if parts[2] != KDF {
        debug!("Unsupported kdf: {}", parts[2]);
        bail!("unsupported kdf {}", parts[2]);
    }

    let params_str = parts[3];
    let mut m = ARGON_M_COST_KIB;
    let mut t = ARGON_T_COST;
    let mut p = ARGON_P;
    for kv in params_str.split(',') {
        if let Some((k, v)) = kv.split_once('=') {
            match k {
                "m" => m = v.parse().unwrap_or(m),
                "t" => t = v.parse().unwrap_or(t),
                "p" => p = v.parse().unwrap_or(p),
                _ => {}
            }
        }
    }

    let salt_b64 = parts[4]
        .strip_prefix("salt=")
        .with_context(|| "missing salt")?;
    let nonce_b64 = parts[5]
        .strip_prefix("nonce=")
        .with_context(|| "missing nonce")?;
    let ct_b64 = parts[6].strip_prefix("ct=").with_context(|| "missing ct")?;

    let mut salt = B64.decode(salt_b64).with_context(|| "bad salt b64")?;
    let mut nonce_bytes = B64.decode(nonce_b64).with_context(|| "bad nonce b64")?;
    let mut ct = B64.decode(ct_b64).with_context(|| "bad ct b64")?;

    if salt.len() != SALT_LEN || nonce_bytes.len() != NONCE_LEN {
        debug!(
            "Salt/nonce length mismatch: salt {}, nonce {}",
            salt.len(),
            nonce_bytes.len()
        );
        bail!("salt/nonce length mismatch");
    }

    let key = derive_key_with_params(password, &salt, m, t, p)?;
    let cipher = XChaCha20Poly1305::new(&key);
    let aad = format!("{};{}", HEADER, VERSION);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let pt = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &ct,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("decryption failed (wrong password or corrupted data)"))?;

    salt.zeroize();
    nonce_bytes.zeroize();
    ct.zeroize();

    let s = String::from_utf8(pt).with_context(|| "plaintext not valid UTF-8")?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use secrecy::{ExposeSecret, SecretString};
    use tempfile::tempdir;

    #[test]
    fn test_derive_key() {
        let password = SecretString::new("test_password".to_string().into());
        let salt = [0u8; 16];
        let key = derive_key(&password, &salt).unwrap();
        assert_eq!(key.as_slice().len(), 32);
    }

    #[test]
    fn test_derive_key_with_params() {
        let password = SecretString::new("test_password".to_string().into());
        let salt = [0u8; 16];
        let key = derive_key_with_params(&password, &salt, 10, 1, 1).unwrap();
        assert_eq!(key.as_slice().len(), 32);
    }

    #[test]
    fn crypto_roundtrip_local_impl() {
        let pw = SecretString::new("pw".into());
        let msg = "hello world";
        let env = encrypt_string(&pw, msg).unwrap();
        let out = decrypt_string(&pw, &env).unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn get_password_reads_password_file() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("pw.txt");
        fs::write(&file, "secretpw\n").unwrap();
        let provider = LocalProvider {
            password_file: Some(file),
            ..LocalProvider::default()
        };
        let pw = provider.get_password().unwrap();
        assert_eq!(pw.expose_secret(), "secretpw");
    }
}
