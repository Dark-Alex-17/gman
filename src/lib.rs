use anyhow::{Context, Result, anyhow, bail};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{SaltString, rand_core::RngCore},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng},
};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;
pub mod config;
pub mod providers;

pub(crate) const HEADER: &str = "$VAULT";
pub(crate) const VERSION: &str = "v1";
pub(crate) const KDF: &str = "argon2id";

pub(crate) const ARGON_M_COST_KIB: u32 = 19_456;
pub(crate) const ARGON_T_COST: u32 = 2;
pub(crate) const ARGON_P: u32 = 1;

pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const KEY_LEN: usize = 32;

fn derive_key(password: &SecretString, salt: &[u8]) -> Result<Key> {
    let params = Params::new(ARGON_M_COST_KIB, ARGON_T_COST, ARGON_P, Some(KEY_LEN))
        .map_err(|e| anyhow!("argon2 params error: {:?}", e))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key_bytes = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key_bytes)
        .map_err(|e| anyhow!("argon2 into error: {:?}", e))?;

    let cloned_key_bytes = key_bytes;
    let key = Key::from_slice(&cloned_key_bytes);
    key_bytes.zeroize();
    Ok(*key)
}

pub fn encrypt_string(password: impl Into<SecretString>, plaintext: &str) -> Result<String> {
    let password = password.into();

    let salt = SaltString::generate(&mut OsRng);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(&password, salt.as_str().as_bytes())?;
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
        salt = B64.encode(salt.as_str().as_bytes()),
        nonce = B64.encode(nonce_bytes),
        ct = B64.encode(&ct),
    );

    drop(cipher);
    let _ = key;
    nonce_bytes.zeroize();

    Ok(env)
}

pub fn decrypt_string(password: impl Into<SecretString>, envelope: &str) -> Result<String> {
    let password = password.into();

    let parts: Vec<&str> = envelope.split(';').collect();
    if parts.len() < 7 {
        bail!("invalid envelope format");
    }
    if parts[0] != HEADER {
        bail!("unexpected header");
    }
    if parts[1] != VERSION {
        bail!("unsupported version {}", parts[1]);
    }
    if parts[2] != KDF {
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

    let salt_b64 = parts[4].strip_prefix("salt=").context("missing salt")?;
    let nonce_b64 = parts[5].strip_prefix("nonce=").context("missing nonce")?;
    let ct_b64 = parts[6].strip_prefix("ct=").context("missing ct")?;

    let salt_bytes = B64.decode(salt_b64).context("bad salt b64")?;
    let mut nonce_bytes = B64.decode(nonce_b64).context("bad nonce b64")?;
    let mut ct = B64.decode(ct_b64).context("bad ct b64")?;

    if nonce_bytes.len() != NONCE_LEN {
        bail!("nonce length mismatch");
    }

    let key = derive_key(&password, &salt_bytes)?;

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

    nonce_bytes.zeroize();
    ct.zeroize();

    let s = String::from_utf8(pt).context("plaintext not valid UTF-8")?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn round_trip() {
        let pw = SecretString::new("correct horse battery staple".into());
        let msg = "swordfish";
        let env = encrypt_string(pw.clone(), msg).unwrap();
        let out = decrypt_string(pw, &env).unwrap();
        assert_eq!(msg, out);
    }

    #[test]
    fn wrong_password_fails() {
        let env = encrypt_string(SecretString::new("pw1".into()), "hello").unwrap();
        assert!(decrypt_string(SecretString::new("pw2".into()), &env).is_err());
    }

    #[test]
    fn empty_plaintext() {
        let pw = SecretString::new("password".into());
        let msg = "";
        let env = encrypt_string(pw.clone(), msg).unwrap();
        let out = decrypt_string(pw, &env).unwrap();
        assert_eq!(msg, out);
    }

    #[test]
    fn empty_password() {
        let pw = SecretString::new("".into());
        let msg = "hello";
        let env = encrypt_string(pw.clone(), msg).unwrap();
        let out = decrypt_string(pw, &env).unwrap();
        assert_eq!(msg, out);
    }

    #[test]
    fn long_plaintext() {
        let pw = SecretString::new("password".into());
        let msg = "a".repeat(1000);
        let env = encrypt_string(pw.clone(), msg.as_str()).unwrap();
        let out = decrypt_string(pw, &env).unwrap();
        assert_eq!(msg, out);
    }

    #[test]
    fn tampered_ciphertext() {
        let pw = SecretString::new("password".into());
        let msg = "hello";
        let env = encrypt_string(pw.clone(), msg).unwrap();
        let mut parts: Vec<&str> = env.split(';').collect();
        let ct_b64 = parts[6].strip_prefix("ct=").unwrap();
        let mut ct = base64::engine::general_purpose::STANDARD
            .decode(ct_b64)
            .unwrap();
        ct[0] ^= 0x01; // Flip a bit
        let new_ct_b64 = base64::engine::general_purpose::STANDARD.encode(&ct);
        let new_ct_part = format!("ct={}", new_ct_b64);
        parts[6] = &new_ct_part;
        let tampered_env = parts.join(";");
        assert!(decrypt_string(pw, &tampered_env).is_err());
    }
}
