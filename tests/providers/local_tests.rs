use gman::config::{Config, ProviderConfig};
use gman::providers::local::LocalProvider;
use gman::providers::{SecretProvider, SupportedProvider};
use pretty_assertions::assert_eq;
use pretty_assertions::assert_str_eq;
use validator::Validate;

#[test]
fn test_local_provider_name() {
    use gman::providers::SecretProvider;
    use gman::providers::local::LocalProvider;

    let provider = LocalProvider::default();
    assert_str_eq!(provider.name(), "LocalProvider");
}

#[test]
fn test_local_provider_display_and_validate() {
    let sp = SupportedProvider::Local {
        provider_def: LocalProvider::default(),
    };
    // Validate delegates to inner provider
    assert!(sp.validate().is_ok());
    // Display formatting for the enum variant
    assert_eq!(sp.to_string(), "local");
}

#[test]
fn test_local_provider_valid() {
    let provider = LocalProvider {
        password_file: None,
        git_branch: None,
        git_remote_url: None,
        git_user_name: None,
        git_user_email: Some("test@example.com".to_string()),
        git_executable: None,
        runtime_provider_name: None,
    };

    assert!(provider.validate().is_ok());
}

#[test]
fn test_local_provider_invalid_email() {
    let config = LocalProvider {
        password_file: None,
        git_branch: None,
        git_remote_url: None,
        git_user_name: None,
        git_user_email: Some("test".to_string()),
        git_executable: None,
        runtime_provider_name: None,
    };

    assert!(config.validate().is_err());
}

#[test]
fn test_local_provider_default() {
    let provider = LocalProvider::default();
    let expected_pw = {
        let p = Config::local_provider_password_file();
        if p.exists() { Some(p) } else { None }
    };
    assert_eq!(provider.password_file, expected_pw);
    assert_eq!(provider.git_branch, Some("main".into()));
    assert_eq!(provider.git_remote_url, None);
    assert_eq!(provider.git_user_name, None);
    assert_eq!(provider.git_user_email, None);
    assert_eq!(provider.git_executable, None);
}

#[test]
fn test_provider_config_with_local_deserialize_and_extract() {
    // Minimal ProviderConfig YAML using the local variant
    let yaml = r#"---
name: local
type: local
"#;

    let pc: ProviderConfig = serde_yaml::from_str(yaml).expect("valid provider config yaml");
    assert!(pc.validate().is_ok());

    let mut pc_owned = pc.clone();
    let provider: &mut dyn SecretProvider = pc_owned.extract_provider();
    assert_eq!(provider.name(), "LocalProvider");

    // Round-trip through Config to ensure flattening works in a real list
    let cfg_yaml = r#"---
default_provider: local
providers:
  - name: local
    type: local
    password_file: /tmp/.gman_pass
    git_branch: main
    git_remote_url: git@github.com:username/repo.git
"#;
    let cfg: Config = serde_yaml::from_str(cfg_yaml).expect("valid config yaml");
    assert!(cfg.validate().is_ok());

    let extracted = cfg
        .extract_provider_config(None)
        .expect("should find default provider");
    assert_eq!(extracted.name.as_deref(), Some("local"));
}
