use gman::config::{Config, ProviderConfig};
use gman::providers::azure_key_vault::AzureKeyVaultProvider;
use gman::providers::{SecretProvider, SupportedProvider};
use pretty_assertions::{assert_eq, assert_str_eq};
use validator::Validate;

#[test]
fn test_azure_provider_name() {
    let provider = AzureKeyVaultProvider {
        vault_name: Some("my-vault".into()),
    };
    assert_str_eq!(provider.name(), "AzureKeyVaultProvider");
}

#[test]
fn test_azure_provider_validation_ok() {
    let provider = AzureKeyVaultProvider {
        vault_name: Some("vault-prod".into()),
    };
    assert!(provider.validate().is_ok());
}

#[test]
fn test_azure_provider_missing_vault_name() {
    let provider = AzureKeyVaultProvider { vault_name: None };
    assert!(provider.validate().is_err());
}

#[test]
fn test_supported_provider_display_and_validate() {
    let sp = SupportedProvider::AzureKeyVault {
        provider_def: AzureKeyVaultProvider {
            vault_name: Some("kv-demo".into()),
        },
    };
    assert!(sp.validate().is_ok());
    assert_eq!(sp.to_string(), "azure_key_vault");
}

#[test]
fn test_provider_config_with_azure_deserialize_and_extract() {
    // Minimal ProviderConfig YAML using the azure_key_vault variant
    let yaml = r#"---
name: azure
type: azure_key_vault
vault_name: my-vault
"#;

    let pc: ProviderConfig = serde_yaml::from_str(yaml).expect("valid provider config yaml");
    assert!(pc.validate().is_ok());

    let mut pc_owned = pc.clone();
    let provider: &mut dyn SecretProvider = pc_owned.extract_provider();
    assert_eq!(provider.name(), "AzureKeyVaultProvider");

    // Round-trip through Config with default_provider
    let cfg_yaml = r#"---
default_provider: azure
providers:
  - name: azure
    type: azure_key_vault
    vault_name: my-vault
"#;
    let cfg: Config = serde_yaml::from_str(cfg_yaml).expect("valid config yaml");
    assert!(cfg.validate().is_ok());

    let extracted = cfg
        .extract_provider_config(None)
        .expect("should find default provider");
    assert_eq!(extracted.name.as_deref(), Some("azure"));
}
