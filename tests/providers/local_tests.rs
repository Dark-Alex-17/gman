use gman::config::Config;
use gman::providers::local::LocalProvider;
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
fn test_local_provider_valid() {
    let provider = LocalProvider {
        password_file: None,
        git_branch: None,
        git_remote_url: None,
        git_user_name: None,
        git_user_email: Some("test@example.com".to_string()),
        git_executable: None,
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
    };

    assert!(config.validate().is_err());
}

#[test]
fn test_local_provider_default() {
    let provider = LocalProvider::default();
    assert_eq!(
        provider.password_file,
        Config::local_provider_password_file()
    );
    assert_eq!(provider.git_branch, Some("main".into()));
    assert_eq!(provider.git_remote_url, None);
    assert_eq!(provider.git_user_name, None);
    assert_eq!(provider.git_user_email, None);
    assert_eq!(provider.git_executable, None);
}
