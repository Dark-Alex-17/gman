use gman::providers::local::LocalProviderConfig;


#[test]
fn test_local_provider_config_default() {
    let config = LocalProviderConfig::default();
    let expected_path = dirs::home_dir()
        .map(|p| p.join(".gman_vault"))
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .unwrap_or_else(|| ".gman_vault".into());
    assert_eq!(config.vault_path, expected_path);
}
