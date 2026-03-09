use gman::config::{Config, ProviderConfig};
use gman::providers::{SecretProvider, SupportedProvider};
use pretty_assertions::{assert_eq, assert_str_eq};
use validator::Validate;

#[test]
fn test_one_password_supported_provider_display_and_validate_from_yaml() {
    let yaml = r#"---
type: one_password
vault: Production
account: my.1password.com
"#;

    let sp: SupportedProvider = serde_yaml::from_str(yaml).expect("valid supported provider yaml");
    assert!(sp.validate().is_ok());
    assert_eq!(sp.to_string(), "one_password");
}

#[test]
fn test_one_password_supported_provider_minimal_yaml() {
    let yaml = r#"---
type: one_password
"#;

    let sp: SupportedProvider = serde_yaml::from_str(yaml).expect("valid supported provider yaml");
    assert!(sp.validate().is_ok());
    assert_eq!(sp.to_string(), "one_password");
}

#[test]
fn test_one_password_supported_provider_vault_only() {
    let yaml = r#"---
type: one_password
vault: Personal
"#;

    let sp: SupportedProvider = serde_yaml::from_str(yaml).expect("valid supported provider yaml");
    assert!(sp.validate().is_ok());
}

#[test]
fn test_one_password_supported_provider_account_only() {
    let yaml = r#"---
type: one_password
account: team.1password.com
"#;

    let sp: SupportedProvider = serde_yaml::from_str(yaml).expect("valid supported provider yaml");
    assert!(sp.validate().is_ok());
}

#[test]
fn test_one_password_supported_provider_rejects_unknown_fields() {
    let yaml = r#"---
type: one_password
vault: Production
unknown_field: bad
"#;

    let result: Result<SupportedProvider, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
}

#[test]
fn test_provider_config_with_one_password_deserialize_and_extract() {
    let yaml = r#"---
name: op
type: one_password
"#;

    let pc: ProviderConfig = serde_yaml::from_str(yaml).expect("valid provider config yaml");
    assert!(pc.validate().is_ok());

    let mut pc_owned = pc.clone();
    let provider: &mut dyn SecretProvider = pc_owned.extract_provider();
    assert_str_eq!(provider.name(), "OnePasswordProvider");

    let cfg_yaml = r#"---
default_provider: op
providers:
  - name: op
    type: one_password
    vault: Production
    account: my.1password.com
"#;
    let cfg: Config = serde_yaml::from_str(cfg_yaml).expect("valid config yaml");
    assert!(cfg.validate().is_ok());

    let extracted = cfg
        .extract_provider_config(None)
        .expect("should find default provider");
    assert_eq!(extracted.name.as_deref(), Some("op"));
}

#[test]
fn test_one_password_config_with_multiple_providers() {
    let cfg_yaml = r#"---
default_provider: local
providers:
  - name: local
    type: local
  - name: op
    type: one_password
    vault: Production
"#;
    let cfg: Config = serde_yaml::from_str(cfg_yaml).expect("valid config yaml");
    assert!(cfg.validate().is_ok());

    let extracted = cfg
        .extract_provider_config(Some("op".into()))
        .expect("should find op provider");
    assert_eq!(extracted.name.as_deref(), Some("op"));
}
