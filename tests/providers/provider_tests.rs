use gman::config::ProviderConfig;
use validator::Validate;

#[test]
fn test_provider_config_missing_name() {
    let config = ProviderConfig {
        name: None,
        ..Default::default()
    };

    assert!(config.validate().is_err());
}
