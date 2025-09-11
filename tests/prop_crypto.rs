use base64::Engine;
use gman::{decrypt_string, encrypt_string};
use proptest::prelude::*;
use secrecy::SecretString;

proptest! {
    #[test]
    fn prop_encrypt_decrypt_roundtrip(password in ".{0,64}", msg in ".{0,2048}") {
        let pw = SecretString::new(password.into());
        let env = encrypt_string(pw.clone(), &msg).unwrap();
        let out = decrypt_string(pw, &env).unwrap();

        prop_assert_eq!(out, msg);
    }

    #[test]
    fn prop_tamper_ciphertext_detected(password in ".{0,32}", msg in ".{1,256}") {
        let pw = SecretString::new(password.into());
        let env = encrypt_string(pw.clone(), &msg).unwrap();
        // Flip a bit in the ct payload segment
        let mut parts: Vec<&str> = env.split(';').collect();
        let ct_b64 = parts[6].strip_prefix("ct=").unwrap();
        let mut ct = base64::engine::general_purpose::STANDARD.decode(ct_b64).unwrap();
        ct[0] ^= 0x1;
        let new_ct_b64 = base64::engine::general_purpose::STANDARD.encode(&ct);
        let new_ct = format!("ct={}", new_ct_b64);
        parts[6] = Box::leak(new_ct.into_boxed_str());
        let tampered = parts.join(";");

        prop_assert!(decrypt_string(pw, &tampered).is_err());
    }
}
