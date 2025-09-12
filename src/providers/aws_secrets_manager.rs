use crate::providers::SecretProvider;
use anyhow::Context;
use anyhow::Result;
use aws_config::Region;
use aws_sdk_secretsmanager::Client;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use validator::Validate;

#[skip_serializing_none]
/// Configuration for AWS Secrets Manager provider
/// See [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
/// for more information.
///
/// This provider stores secrets in AWS Secrets Manager. It requires
/// AWS credentials to be configured in the AWS configuration
/// files for different AWS profiles.
///
/// Example
/// ```no_run
/// use gman::providers::{SecretProvider, SupportedProvider};
/// use gman::config::{Config, ProviderConfig};
/// use gman::providers::aws_secrets_manager::AwsSecretsManagerProvider;
///
/// let provider = AwsSecretsManagerProvider {
/// 	aws_profile: Some("prod".to_string()),
/// 	aws_region: Some("us-west-2".to_string()),
/// };
///	let _ =	provider.set_secret("MY_SECRET", "value");
/// ```
#[derive(Debug, Clone, Validate, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AwsSecretsManagerProvider {
    #[validate(required)]
    pub aws_profile: Option<String>,
    #[validate(required)]
    pub aws_region: Option<String>,
}

#[async_trait::async_trait]
impl SecretProvider for AwsSecretsManagerProvider {
    fn name(&self) -> &'static str {
        "AwsSecretsManagerProvider"
    }

    async fn get_secret(&self, key: &str) -> Result<String> {
        self.get_client()
            .await?
            .get_secret_value()
            .secret_id(key)
            .send()
            .await?
            .secret_string
            .with_context(|| format!("Secret '{key}' not found"))
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        self.get_client()
            .await?
            .create_secret()
            .name(key)
            .secret_string(value)
            .send()
            .await
            .with_context(|| format!("Failed to set secret '{key}'"))?;

        Ok(())
    }

    async fn update_secret(&self, key: &str, value: &str) -> Result<()> {
        self.get_client()
            .await?
            .update_secret()
            .secret_id(key)
            .secret_string(value)
            .send()
            .await
            .with_context(|| format!("Failed to update secret '{key}'"))?;

        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        self.get_client()
            .await?
            .delete_secret()
            .secret_id(key)
            .force_delete_without_recovery(true)
            .send()
            .await
            .with_context(|| format!("Failed to delete secret '{key}'"))?;
        Ok(())
    }

    async fn list_secrets(&self) -> Result<Vec<String>> {
        self.get_client()
            .await?
            .list_secrets()
            .send()
            .await?
            .secret_list
            .with_context(|| "No secrets found")
            .map(|secrets| secrets.into_iter().filter_map(|s| s.name).collect())
    }
}

impl AwsSecretsManagerProvider {
    async fn get_client(&self) -> Result<Client> {
        let region = self
            .aws_region
            .clone()
            .with_context(|| "aws_region is required")?;
        let profile = self
            .aws_profile
            .clone()
            .with_context(|| "aws_profile is required")?;

        let config = aws_config::from_env()
            .region(Region::new(region))
            .profile_name(profile)
            .load()
            .await;

        Ok(Client::new(&config))
    }
}
