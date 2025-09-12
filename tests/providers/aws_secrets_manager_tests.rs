use gman::config::{Config, ProviderConfig};
use gman::providers::aws_secrets_manager::AwsSecretsManagerProvider;
use gman::providers::{SecretProvider, SupportedProvider};
use pretty_assertions::{assert_eq, assert_str_eq};
use validator::Validate;

#[test]
fn test_aws_provider_name() {
    let provider = AwsSecretsManagerProvider {
        aws_profile: Some("default".into()),
        aws_region: Some("us-east-1".into()),
    };
    assert_str_eq!(provider.name(), "AwsSecretsManagerProvider");
}

#[test]
fn test_aws_provider_validation_ok() {
    let provider = AwsSecretsManagerProvider {
        aws_profile: Some("default".into()),
        aws_region: Some("us-west-2".into()),
    };
    assert!(provider.validate().is_ok());
}

#[test]
fn test_aws_provider_missing_profile() {
    let provider = AwsSecretsManagerProvider {
        aws_profile: None,
        aws_region: Some("us-west-2".into()),
    };
    assert!(provider.validate().is_err());
}

#[test]
fn test_aws_provider_missing_region() {
    let provider = AwsSecretsManagerProvider {
        aws_profile: Some("default".into()),
        aws_region: None,
    };
    assert!(provider.validate().is_err());
}

#[test]
fn test_aws_secrets_manager_provider_display_and_validate() {
    let sp = SupportedProvider::AwsSecretsManager {
        provider_def: AwsSecretsManagerProvider {
            aws_profile: Some("default".into()),
            aws_region: Some("eu-central-1".into()),
        },
    };
    // Validate delegates to inner provider
    assert!(sp.validate().is_ok());
    // Display formatting for the enum variant
    assert_eq!(sp.to_string(), "aws_secrets_manager");
}

#[test]
fn test_provider_config_with_aws_deserialize_and_extract() {
    // Minimal ProviderConfig YAML using the aws_secrets_manager variant
    let yaml = r#"---
name: aws
type: aws_secrets_manager
aws_profile: default
aws_region: us-east-1
"#;

    let pc: ProviderConfig = serde_yaml::from_str(yaml).expect("valid provider config yaml");
    // It should validate (both fields present)
    assert!(pc.validate().is_ok());

    // Extract the provider and inspect its name via the trait
    let mut pc_owned = pc.clone();
    let provider: &mut dyn SecretProvider = pc_owned.extract_provider();
    assert_eq!(provider.name(), "AwsSecretsManagerProvider");

    // Round-trip through Config to ensure flattening works in a real list
    let cfg_yaml = r#"---
default_provider: aws
providers:
  - name: aws
    type: aws_secrets_manager
    aws_profile: default
    aws_region: us-east-1
"#;
    let cfg: Config = serde_yaml::from_str(cfg_yaml).expect("valid config yaml");
    assert!(cfg.validate().is_ok());

    let extracted = cfg
        .extract_provider_config(None)
        .expect("should find default provider");
    assert_eq!(extracted.name.as_deref(), Some("aws"));
}
