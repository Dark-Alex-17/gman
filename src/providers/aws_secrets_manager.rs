use aws_config::Region;
use aws_sdk_secretsmanager::Client;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use validator::Validate;

use crate::providers::error::{SecretError, classify_aws_error};
use crate::providers::SecretProvider;

const PROVIDER: &str = "aws_secrets_manager";

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
/// use gman::config::Config;
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

    async fn get_secret(&self, key: &str) -> Result<String, SecretError> {
        let client = self.get_client().await?;
        let resp = client
            .get_secret_value()
            .secret_id(key)
            .send()
            .await
            .map_err(|e| classify_aws_error(e.into(), Some(key), "get_secret"))?;
        resp.secret_string.ok_or_else(|| SecretError::NotFound {
            key: key.to_string(),
            provider: PROVIDER,
        })
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<(), SecretError> {
        self.get_client()
            .await?
            .create_secret()
            .name(key)
            .secret_string(value)
            .send()
            .await
            .map_err(|e| classify_aws_error(e.into(), Some(key), "set_secret"))?;

        Ok(())
    }

    async fn update_secret(&self, key: &str, value: &str) -> Result<(), SecretError> {
        self.get_client()
            .await?
            .update_secret()
            .secret_id(key)
            .secret_string(value)
            .send()
            .await
            .map_err(|e| classify_aws_error(e.into(), Some(key), "update_secret"))?;

        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> Result<(), SecretError> {
        self.get_client()
            .await?
            .delete_secret()
            .secret_id(key)
            .force_delete_without_recovery(true)
            .send()
            .await
            .map_err(|e| classify_aws_error(e.into(), Some(key), "delete_secret"))?;
        Ok(())
    }

    async fn list_secrets(&self) -> Result<Vec<String>, SecretError> {
        let resp = self
            .get_client()
            .await?
            .list_secrets()
            .send()
            .await
            .map_err(|e| classify_aws_error(e.into(), None, "list_secrets"))?;
        Ok(resp
            .secret_list
            .unwrap_or_default()
            .into_iter()
            .filter_map(|s| s.name)
            .collect())
    }
}

impl AwsSecretsManagerProvider {
    async fn get_client(&self) -> Result<Client, SecretError> {
        let region = self.aws_region.clone().ok_or_else(|| SecretError::Config {
            provider: PROVIDER,
            message: "aws_region is required".to_string(),
        })?;
        let profile = self.aws_profile.clone().ok_or_else(|| SecretError::Config {
            provider: PROVIDER,
            message: "aws_profile is required".to_string(),
        })?;

        let config = aws_config::from_env()
            .region(Region::new(region))
            .profile_name(profile)
            .load()
            .await;

        Ok(Client::new(&config))
    }
}
