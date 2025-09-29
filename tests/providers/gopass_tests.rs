use gman::config::{Config, ProviderConfig};
use gman::providers::{SecretProvider, SupportedProvider};
use pretty_assertions::{assert_eq, assert_str_eq};
use validator::Validate;

#[test]
fn test_gopass_supported_provider_display_and_validate_from_yaml() {
    // Build a SupportedProvider via YAML to avoid direct type import
    let yaml = r#"---
type: gopass
store: personal
"#;

    let sp: SupportedProvider = serde_yaml::from_str(yaml).expect("valid supported provider yaml");
    // Validate delegates to inner provider (no required fields)
    assert!(sp.validate().is_ok());
    // Display formatting for the enum variant
    assert_eq!(sp.to_string(), "gopass");
}

#[test]
fn test_provider_config_with_gopass_deserialize_and_extract() {
    // Minimal ProviderConfig YAML using the gopass variant
    let yaml = r#"---
name: gopass
type: gopass
"#;

    let pc: ProviderConfig = serde_yaml::from_str(yaml).expect("valid provider config yaml");
    // Gopass has no required fields, so validation should pass
    assert!(pc.validate().is_ok());

    // Extract the provider and inspect its name via the trait
    let mut pc_owned = pc.clone();
    let provider: &mut dyn SecretProvider = pc_owned.extract_provider();
    assert_str_eq!(provider.name(), "GopassProvider");

    // Round-trip through Config with default_provider
    let cfg_yaml = r#"---
default_provider: gopass
providers:
  - name: gopass
    type: gopass
    store: personal
"#;
    let cfg: Config = serde_yaml::from_str(cfg_yaml).expect("valid config yaml");
    assert!(cfg.validate().is_ok());

    let extracted = cfg
        .extract_provider_config(None)
        .expect("should find default provider");
    assert_eq!(extracted.name.as_deref(), Some("gopass"));
}
