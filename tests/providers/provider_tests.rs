use gman::config::ProviderConfig;
use gman::providers::ParseProviderError;
use pretty_assertions::assert_eq;
use validator::Validate;

#[test]
fn test_parse_provider_error_display() {
    let err = ParseProviderError::Unsupported("test".to_string());
    assert_eq!(err.to_string(), "unsupported provider 'test'");
}

#[test]
fn test_provider_config_missing_name() {
    let config = ProviderConfig {
        name: None,
        ..Default::default()
    };

    assert!(config.validate().is_err());
}
