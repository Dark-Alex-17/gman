use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{env, fs};

use anyhow::{Context as _, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng},
};
use dialoguer::{Input, theme};
use log::{debug, error};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use theme::ColorfulTheme;
use validator::Validate;
use zeroize::Zeroize;

use crate::config::{Config, get_config_file_path, load_config};
use crate::providers::error::SecretError;
use crate::providers::git_sync::{
    SyncOpts, default_git_email, default_git_username, ensure_git_available, repo_name_from_url,
    resolve_git, sync_and_push,
};
use crate::providers::{SecretProvider, SupportedProvider};
use crate::{
    ARGON_M_COST_KIB, ARGON_P, ARGON_T_COST, HEADER, KDF, KEY_LEN, NONCE_LEN, SALT_LEN, VERSION,
    calling_app_name,
};

const PROVIDER: &str = "local";

type LocalResult<T> = std::result::Result<T, SecretError>;

fn cfg_err(message: impl Into<String>) -> SecretError {
    SecretError::Config {
        provider: PROVIDER,
        message: message.into(),
    }
}

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
/// use gman::config::Config;
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
    #[serde(skip)]
    pub runtime_provider_name: Option<String>,
}

impl Default for LocalProvider {
    fn default() -> Self {
        let password_file = match Config::local_provider_password_file() {
            p if p.exists() => Some(p),
            _ => None,
        };

        Self {
            password_file,
            git_branch: Some("main".into()),
            git_remote_url: None,
            git_user_name: None,
            git_user_email: None,
            git_executable: None,
            runtime_provider_name: None,
        }
    }
}

#[async_trait::async_trait]
impl SecretProvider for LocalProvider {
    fn name(&self) -> &'static str {
        "LocalProvider"
    }

    async fn get_secret(&self, key: &str) -> LocalResult<String> {
        let vault_path = self.active_vault_path()?;
        let vault: HashMap<String, String> = load_vault(&vault_path).unwrap_or_default();
        let envelope = vault.get(key).ok_or_else(|| SecretError::NotFound {
            key: key.to_string(),
            provider: PROVIDER,
        })?;

        let password = self.get_password()?;
        let plaintext = decrypt_string(&password, envelope)?;
        drop(password);

        Ok(plaintext)
    }

    async fn set_secret(&self, key: &str, value: &str) -> LocalResult<()> {
        let vault_path = self.active_vault_path()?;
        let mut vault: HashMap<String, String> = load_vault(&vault_path).unwrap_or_default();
        if vault.contains_key(key) {
            error!(
                "Key '{key}' already exists in the vault. Use a different key or delete the existing one first."
            );
            return Err(SecretError::AlreadyExists {
                key: key.to_string(),
                provider: PROVIDER,
            });
        }

        let password = self.get_password()?;
        let envelope = encrypt_string(&password, value).map_err(SecretError::Other)?;
        drop(password);

        vault.insert(key.to_string(), envelope);

        store_vault(&vault_path, &vault)
    }

    async fn update_secret(&self, key: &str, value: &str) -> LocalResult<()> {
        let vault_path = self.active_vault_path()?;
        let mut vault: HashMap<String, String> = load_vault(&vault_path).unwrap_or_default();

        let password = self.get_password()?;
        let envelope = encrypt_string(&password, value).map_err(SecretError::Other)?;
        drop(password);

        if vault.contains_key(key) {
            debug!("Key '{key}' exists in vault. Overwriting previous value");
            let vault_entry = vault.get_mut(key).ok_or_else(|| SecretError::NotFound {
                key: key.to_string(),
                provider: PROVIDER,
            })?;
            *vault_entry = envelope;

            return store_vault(&vault_path, &vault);
        }

        vault.insert(key.to_string(), envelope);
        store_vault(&vault_path, &vault)
    }

    async fn delete_secret(&self, key: &str) -> LocalResult<()> {
        let vault_path = self.active_vault_path()?;
        let mut vault: HashMap<String, String> = load_vault(&vault_path).unwrap_or_default();
        if !vault.contains_key(key) {
            error!("Key '{key}' does not exist in the vault.");
            return Err(SecretError::NotFound {
                key: key.to_string(),
                provider: PROVIDER,
            });
        }

        vault.remove(key);
        store_vault(&vault_path, &vault)
    }

    async fn list_secrets(&self) -> LocalResult<Vec<String>> {
        let vault_path = self.active_vault_path()?;
        let vault: HashMap<String, String> = load_vault(&vault_path).unwrap_or_default();
        let mut keys: Vec<String> = vault.keys().cloned().collect();
        keys.sort();

        Ok(keys)
    }

    async fn sync(&mut self) -> LocalResult<()> {
        let mut config_changed = false;
        let git = resolve_git(self.git_executable.as_ref())?;
        ensure_git_available(&git)?;

        if self.git_branch.is_none() {
            config_changed = true;
            debug!("Prompting user to set git_branch in config for sync");
            let branch: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter git branch to sync with")
                .default("main".into())
                .interact_text()
                .map_err(|e| cfg_err(format!("prompt failed: {}", e)))?;

            self.git_branch = Some(branch);
        }

        if self.git_remote_url.is_none() {
            config_changed = true;
            debug!("Prompting user to set git_remote in config for sync");
            let remote: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt(
                    "Enter remote git URL to sync with (e.g. 'git@github.com:user/repo.git')",
                )
                .validate_with(|s: &String| {
                    LocalProvider {
                        git_remote_url: Some(s.clone()),
                        ..LocalProvider::default()
                    }
                    .validate()
                    .map(|_| ())
                    .map_err(|e| e.to_string())
                })
                .interact_text()
                .map_err(|e| cfg_err(format!("prompt failed: {}", e)))?;

            self.git_remote_url = Some(remote);
        }

        if self.git_user_name.is_none() {
            config_changed = true;
            debug!("Prompting user git user name");
            let default_user_name = default_git_username(&git)
                .map_err(SecretError::from)?
                .trim()
                .to_string();
            let branch: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter git user name")
                .default(default_user_name)
                .interact_text()
                .map_err(|e| cfg_err(format!("prompt failed: {}", e)))?;

            self.git_user_name = Some(branch);
        }

        if self.git_user_email.is_none() {
            config_changed = true;
            debug!("Prompting user git email");
            let default_user_name = default_git_email(&git)
                .map_err(SecretError::from)?
                .trim()
                .to_string();
            let branch: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter git user email")
                .validate_with({
                    |s: &String| {
                        if s.contains('@') {
                            Ok(())
                        } else {
                            Err("not a valid email address".to_string())
                        }
                    }
                })
                .default(default_user_name)
                .interact_text()
                .map_err(|e| cfg_err(format!("prompt failed: {}", e)))?;

            self.git_user_email = Some(branch);
        }

        if config_changed {
            self.persist_git_settings_to_config()?;
        }

        let sync_opts = SyncOpts {
            remote_url: &self.git_remote_url,
            branch: &self.git_branch,
            user_name: &self.git_user_name,
            user_email: &self.git_user_email,
            git_executable: &self.git_executable,
        };

        sync_and_push(&sync_opts)?;
        Ok(())
    }
}

impl LocalProvider {
    fn persist_git_settings_to_config(&self) -> LocalResult<()> {
        debug!("Saving updated config (only current local provider)");

        let mut cfg = load_config(true)
            .map_err(|e| cfg_err(format!("failed to load existing config: {}", e)))?;

        let target_name = self.runtime_provider_name.clone();
        let mut updated = false;
        for pc in cfg.providers.iter_mut() {
            if let SupportedProvider::Local { provider_def } = &mut pc.provider_type {
                let matches_name = match (&pc.name, &target_name) {
                    (Some(n), Some(t)) => n == t,
                    (Some(_), None) => false,
                    _ => false,
                };
                if matches_name || target_name.is_none() {
                    provider_def.git_branch = self.git_branch.clone();
                    provider_def.git_remote_url = self.git_remote_url.clone();
                    provider_def.git_user_name = self.git_user_name.clone();
                    provider_def.git_user_email = self.git_user_email.clone();
                    provider_def.git_executable = self.git_executable.clone();

                    updated = true;
                    if matches_name {
                        break;
                    }
                }
            }
        }

        if !updated {
            return Err(cfg_err(
                "unable to find matching local provider in config to update",
            ));
        }

        let path = get_config_file_path()
            .map_err(|e| cfg_err(format!("failed to determine config path: {}", e)))?;
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml") {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let s = serde_yaml::to_string(&cfg)
                .map_err(|e| cfg_err(format!("serialize config: {}", e)))?;
            fs::write(&path, s)?;
        } else {
            confy::store(&calling_app_name(), "config", &cfg)
                .map_err(|e| cfg_err(format!("failed to save updated config via confy: {}", e)))?;
        }

        Ok(())
    }

    fn repo_dir_for_config(&self) -> LocalResult<Option<PathBuf>> {
        if let Some(remote) = &self.git_remote_url {
            let name = repo_name_from_url(remote);
            let dir = base_config_dir()?.join(format!(".{}", name));
            Ok(Some(dir))
        } else {
            Ok(None)
        }
    }

    fn active_vault_path(&self) -> LocalResult<PathBuf> {
        if let Some(dir) = self.repo_dir_for_config()?
            && dir.exists()
        {
            return Ok(dir.join("vault.yml"));
        }

        default_vault_path()
    }

    fn get_password(&self) -> LocalResult<SecretString> {
        if let Some(password_file) = &self.password_file {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = fs::metadata(password_file)?;
                let mode = metadata.permissions().mode();
                if mode & 0o077 != 0 {
                    return Err(cfg_err(format!(
                        "password file {:?} has insecure permissions {:o} (should be 0600 or 0400)",
                        password_file,
                        mode & 0o777
                    )));
                }
            }

            let password =
                SecretString::new(fs::read_to_string(password_file)?.trim().to_string().into());

            Ok(password)
        } else {
            let password = rpassword::prompt_password("\nPassword: ")?;
            Ok(SecretString::new(password.into()))
        }
    }
}

fn default_vault_path() -> LocalResult<PathBuf> {
    let xdg_path = env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);

    if let Some(xdg) = xdg_path {
        return Ok(xdg.join(calling_app_name()).join("vault.yml"));
    }

    confy::get_configuration_file_path(&calling_app_name(), "vault")
        .map_err(|e| cfg_err(format!("get config dir: {}", e)))
}

fn base_config_dir() -> LocalResult<PathBuf> {
    default_vault_path()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| cfg_err("Failed to determine config dir"))
}

fn load_vault(path: &Path) -> anyhow::Result<HashMap<String, String>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let s = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let map: HashMap<String, String> = serde_yaml::from_str(&s).unwrap_or_default();
    Ok(map)
}

fn store_vault(path: &Path, map: &HashMap<String, String>) -> LocalResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let s = serde_yaml::to_string(map)
        .map_err(|e| SecretError::Other(anyhow!("serialize vault: {}", e)))?;
    fs::write(path, &s)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

fn encrypt_string(password: &SecretString, plaintext: &str) -> anyhow::Result<String> {
    if password.expose_secret().is_empty() {
        anyhow::bail!("password cannot be empty");
    }

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new(&key);

    let aad = format!(
        "{};{};{};m={},t={},p={}",
        HEADER, VERSION, KDF, ARGON_M_COST_KIB, ARGON_T_COST, ARGON_P
    );

    let nonce: XNonce = nonce_bytes.into();
    let mut pt = plaintext.as_bytes().to_vec();
    let ct = cipher
        .encrypt(
            &nonce,
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
    key.zeroize();
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
) -> anyhow::Result<Key> {
    let params = Params::new(m_cost, t_cost, p, Some(KEY_LEN))
        .map_err(|e| anyhow!("argon2 params error: {:?}", e))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key_bytes)
        .map_err(|e| anyhow!("argon2 derive error: {:?}", e))?;
    let key: Key = key_bytes.into();
    key_bytes.zeroize();
    Ok(key)
}

fn derive_key(password: &SecretString, salt: &[u8]) -> anyhow::Result<Key> {
    derive_key_with_params(password, salt, ARGON_M_COST_KIB, ARGON_T_COST, ARGON_P)
}

fn try_decrypt(
    cipher: &XChaCha20Poly1305,
    nonce: &XNonce,
    ct: &[u8],
    aad: &[u8],
) -> std::result::Result<Vec<u8>, chacha20poly1305::aead::Error> {
    cipher.decrypt(nonce, chacha20poly1305::aead::Payload { msg: ct, aad })
}

type EnvelopeComponents = (u32, u32, u32, Vec<u8>, [u8; NONCE_LEN], Vec<u8>);

fn parse_envelope(envelope: &str) -> LocalResult<EnvelopeComponents> {
    let parts: Vec<&str> = envelope.trim().split(';').collect();
    if parts.len() < 7 {
        debug!("Invalid envelope format: {:?}", parts);
        return Err(SecretError::Other(anyhow!("invalid envelope format")));
    }
    if parts[0] != HEADER {
        debug!("Invalid header: {}", parts[0]);
        return Err(SecretError::Other(anyhow!("unexpected header")));
    }
    if parts[1] != VERSION {
        debug!("Unsupported version: {}", parts[1]);
        return Err(SecretError::Unsupported {
            operation: "decrypt_envelope_version",
            provider: PROVIDER,
        });
    }
    if parts[2] != KDF {
        debug!("Unsupported kdf: {}", parts[2]);
        return Err(SecretError::Unsupported {
            operation: "decrypt_kdf",
            provider: PROVIDER,
        });
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
        .ok_or_else(|| SecretError::Other(anyhow!("missing salt")))?;
    let nonce_b64 = parts[5]
        .strip_prefix("nonce=")
        .ok_or_else(|| SecretError::Other(anyhow!("missing nonce")))?;
    let ct_b64 = parts[6]
        .strip_prefix("ct=")
        .ok_or_else(|| SecretError::Other(anyhow!("missing ct")))?;

    let salt = B64
        .decode(salt_b64)
        .map_err(|e| SecretError::Other(anyhow!("bad salt b64: {}", e)))?;
    let nonce_bytes = B64
        .decode(nonce_b64)
        .map_err(|e| SecretError::Other(anyhow!("bad nonce b64: {}", e)))?;
    let ct = B64
        .decode(ct_b64)
        .map_err(|e| SecretError::Other(anyhow!("bad ct b64: {}", e)))?;

    if nonce_bytes.len() != NONCE_LEN {
        debug!("Nonce length mismatch: {}", nonce_bytes.len());
        return Err(SecretError::Other(anyhow!("nonce length mismatch")));
    }

    let nonce_arr: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| SecretError::Other(anyhow!("invalid nonce length")))?;

    Ok((m, t, p, salt, nonce_arr, ct))
}

fn decrypt_string(password: &SecretString, envelope: &str) -> LocalResult<String> {
    if password.expose_secret().is_empty() {
        return Err(cfg_err("password cannot be empty"));
    }

    let (m, t, p, mut salt, mut nonce_arr, mut ct) = parse_envelope(envelope)?;
    let nonce: XNonce = nonce_arr.into();

    let aad_current = format!("{};{};{};m={},t={},p={}", HEADER, VERSION, KDF, m, t, p);

    let mut key = derive_key_with_params(password, &salt, m, t, p).map_err(|source| {
        SecretError::AuthFailed {
            provider: PROVIDER,
            source,
        }
    })?;
    let cipher = XChaCha20Poly1305::new(&key);

    if let Ok(pt) = try_decrypt(&cipher, &nonce, &ct, aad_current.as_bytes()) {
        let s = String::from_utf8(pt.clone())
            .map_err(|e| SecretError::Other(anyhow!("plaintext not valid UTF-8: {}", e)))?;
        key.zeroize();
        salt.zeroize();
        nonce_arr.zeroize();
        ct.zeroize();
        return Ok(s);
    }

    key.zeroize();
    salt.zeroize();
    nonce_arr.zeroize();
    ct.zeroize();

    Err(SecretError::AuthFailed {
        provider: PROVIDER,
        source: anyhow!("decryption failed (wrong password or corrupted data)"),
    })
}

#[cfg(test)]
mod tests {
    use std::env as std_env;

    use pretty_assertions::assert_eq;
    use secrecy::{ExposeSecret, SecretString};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_derive_key() {
        let password = SecretString::new("test_password".to_string().into());
        let salt = [0u8; 16];
        let key = derive_key(&password, &salt).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_key_with_params() {
        let password = SecretString::new("test_password".to_string().into());
        let salt = [0u8; 16];
        let key = derive_key_with_params(&password, &salt, 10, 1, 1).unwrap();
        assert_eq!(key.len(), 32);
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
    #[cfg(unix)]
    fn get_password_reads_password_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let file = dir.path().join("pw.txt");
        fs::write(&file, "secretpw\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let provider = LocalProvider {
            password_file: Some(file),
            runtime_provider_name: None,
            ..LocalProvider::default()
        };
        let pw = provider.get_password().unwrap();
        assert_eq!(pw.expose_secret(), "secretpw");
    }

    #[test]
    #[cfg(unix)]
    fn get_password_rejects_insecure_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let file = dir.path().join("pw.txt");
        fs::write(&file, "secretpw\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let provider = LocalProvider {
            password_file: Some(file),
            runtime_provider_name: None,
            ..LocalProvider::default()
        };
        assert!(provider.get_password().is_err());
    }

    #[test]
    #[cfg(not(unix))]
    fn get_password_reads_password_file() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("pw.txt");
        fs::write(&file, "secretpw\n").unwrap();
        let provider = LocalProvider {
            password_file: Some(file),
            runtime_provider_name: None,
            ..LocalProvider::default()
        };
        let pw = provider.get_password().unwrap();
        assert_eq!(pw.expose_secret(), "secretpw");
    }

    #[test]
    fn persist_only_target_local_provider_git_settings() {
        let td = tempdir().unwrap();
        let xdg = td.path().join("xdg");
        let app_dir = xdg.join(calling_app_name());
        fs::create_dir_all(&app_dir).unwrap();
        unsafe {
            std_env::set_var("XDG_CONFIG_HOME", &xdg);
        }

        let initial_yaml = indoc::indoc! {
            "---
            default_provider: local
            providers:
              - name: local
                type: local
                password_file: /tmp/.gman_pass
                git_branch: main
                git_remote_url: null
                git_user_name: null
                git_user_email: null
                git_executable: null
              - name: other
                type: local
                git_branch: main
                git_remote_url: git@github.com:someone/else.git
            run_configs:
              - name: echo
                secrets: [API_KEY]
            "
        };
        let cfg_path = app_dir.join("config.yml");
        fs::write(&cfg_path, initial_yaml).unwrap();

        let provider = LocalProvider {
            password_file: None,
            git_branch: Some("dev".into()),
            git_remote_url: Some("git@github.com:user/repo.git".into()),
            git_user_name: Some("Test User".into()),
            git_user_email: Some("test@example.com".into()),
            git_executable: Some(PathBuf::from("/usr/bin/git")),
            runtime_provider_name: Some("local".into()),
        };

        provider
            .persist_git_settings_to_config()
            .expect("persist ok");

        let content = fs::read_to_string(&cfg_path).unwrap();
        let cfg: Config = serde_yaml::from_str(&content).unwrap();

        assert_eq!(cfg.default_provider.as_deref(), Some("local"));
        assert!(cfg.run_configs.is_some());
        assert_eq!(cfg.run_configs.as_ref().unwrap().len(), 1);

        let p0 = &cfg.providers[0];
        assert_eq!(p0.name.as_deref(), Some("local"));
        match &p0.provider_type {
            SupportedProvider::Local { provider_def } => {
                assert_eq!(provider_def.git_branch.as_deref(), Some("dev"));
                assert_eq!(
                    provider_def.git_remote_url.as_deref(),
                    Some("git@github.com:user/repo.git")
                );
                assert_eq!(provider_def.git_user_name.as_deref(), Some("Test User"));
                assert_eq!(
                    provider_def.git_user_email.as_deref(),
                    Some("test@example.com")
                );
                assert_eq!(
                    provider_def.git_executable.as_ref(),
                    Some(&PathBuf::from("/usr/bin/git"))
                );
            }
            _ => panic!("expected local provider"),
        }

        let p1 = &cfg.providers[1];
        assert_eq!(p1.name.as_deref(), Some("other"));
        match &p1.provider_type {
            SupportedProvider::Local { provider_def } => {
                assert_eq!(provider_def.git_branch.as_deref(), Some("main"));
                assert_eq!(
                    provider_def.git_remote_url.as_deref(),
                    Some("git@github.com:someone/else.git")
                );
            }
            _ => panic!("expected local provider"),
        }

        unsafe {
            std_env::remove_var("XDG_CONFIG_HOME");
        }
    }
}
