use gman::config::{Config, ProviderConfig};
use gman::providers::gcp_secret_manager::GcpSecretManagerProvider;
use gman::providers::{SecretProvider, SupportedProvider};
use pretty_assertions::{assert_eq, assert_str_eq};
use validator::Validate;

#[test]
fn test_gcp_provider_name() {
    let provider = GcpSecretManagerProvider {
        gcp_project_id: Some("my-project".into()),
    };
    assert_str_eq!(provider.name(), "GcpSecretManagerProvider");
}

#[test]
fn test_gcp_provider_validation_ok() {
    let provider = GcpSecretManagerProvider {
        gcp_project_id: Some("demo-project".into()),
    };
    assert!(provider.validate().is_ok());
}

#[test]
fn test_gcp_provider_missing_project() {
    let provider = GcpSecretManagerProvider { gcp_project_id: None };
    assert!(provider.validate().is_err());
}

#[test]
fn test_supported_provider_display_and_validate() {
    let sp = SupportedProvider::GcpSecretManager {
        provider_def: GcpSecretManagerProvider {
            gcp_project_id: Some("prod-123".into()),
        },
    };
    // Validate delegates to inner provider
    assert!(sp.validate().is_ok());
    // Display string for this variant
    assert_eq!(sp.to_string(), "gcp_secret_manager");
}

#[test]
fn test_provider_config_with_gcp_deserialize_and_extract() {
    // Minimal ProviderConfig YAML using the gcp_secret_manager variant
    let yaml = r#"---
name: gcp
type: gcp_secret_manager
gcp_project_id: my-project
"#;

    let pc: ProviderConfig = serde_yaml::from_str(yaml).expect("valid provider config yaml");
    assert!(pc.validate().is_ok());

    let mut pc_owned = pc.clone();
    let provider: &mut dyn SecretProvider = pc_owned.extract_provider();
    assert_eq!(provider.name(), "GcpSecretManagerProvider");

    // Round-trip through Config with default_provider
    let cfg_yaml = r#"---
default_provider: gcp
providers:
  - name: gcp
    type: gcp_secret_manager
    gcp_project_id: my-project
"#;
    let cfg: Config = serde_yaml::from_str(cfg_yaml).expect("valid config yaml");
    assert!(cfg.validate().is_ok());

    let extracted = cfg
        .extract_provider_config(None)
        .expect("should find default provider");
    assert_eq!(extracted.name.as_deref(), Some("gcp"));
}

