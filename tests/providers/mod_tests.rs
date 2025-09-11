use gman::providers::local::LocalProvider;
use gman::providers::{ParseProviderError, SupportedProvider};
use std::str::FromStr;

#[test]
fn test_supported_provider_from_str_valid() {
    assert_eq!(
        SupportedProvider::from_str("local").unwrap(),
        SupportedProvider::Local(LocalProvider)
    );
    assert_eq!(
        SupportedProvider::from_str("LOCAL").unwrap(),
        SupportedProvider::Local(LocalProvider)
    );
}

#[test]
fn test_supported_provider_from_str_invalid() {
    let err = SupportedProvider::from_str("invalid").unwrap_err();
    assert_eq!(err.to_string(), "unsupported provider 'invalid'");
}

#[test]
fn test_supported_provider_display() {
    let provider = SupportedProvider::Local(LocalProvider);
    assert_eq!(provider.to_string(), "local");
}

#[test]
fn test_parse_provider_error_display() {
    let err = ParseProviderError::Unsupported("test".to_string());
    assert_eq!(err.to_string(), "unsupported provider 'test'");
}
