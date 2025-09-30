use crate::config::deserialize_optional_env_var;
use crate::providers::SecretProvider;
use anyhow::{Context, Result};
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault_secrets::models::SetSecretParameters;
use azure_security_keyvault_secrets::{ResourceExt, SecretClient};
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use validator::Validate;

#[skip_serializing_none]
/// Configuration for Azure Key Vault provider
/// See [Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/)
/// for more information.
///
/// This provider stores secrets in Azure Key Vault. It requires
/// a vault name to be specified.
///
/// Example
/// ```no_run
/// use gman::providers::{SecretProvider, SupportedProvider};
/// use gman::config::{Config, ProviderConfig};
/// use gman::providers::azure_key_vault::AzureKeyVaultProvider;
///
/// let provider = AzureKeyVaultProvider {
/// 	vault_name: Some("my-vault-name".to_string()),
/// };
///	let _ =	provider.set_secret("MY_SECRET", "value");
#[derive(Debug, Clone, Validate, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AzureKeyVaultProvider {
    #[validate(required)]
    #[serde(default, deserialize_with = "deserialize_optional_env_var")]
    pub vault_name: Option<String>,
}

#[async_trait::async_trait]
impl SecretProvider for AzureKeyVaultProvider {
    fn name(&self) -> &'static str {
        "AzureKeyVaultProvider"
    }

    async fn get_secret(&self, key: &str) -> Result<String> {
        let body = self
            .get_client()?
            .get_secret(key, "", None)
            .await?
            .into_body()
            .await?;

        body.value
            .with_context(|| format!("Secret '{}' not found", key))
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        let params = SetSecretParameters {
            value: Some(value.to_string()),
            ..Default::default()
        };

        self.get_client()?
            .set_secret(key, params.try_into()?, None)
            .await?
            .into_body()
            .await?;

        Ok(())
    }

    async fn update_secret(&self, key: &str, value: &str) -> Result<()> {
        self.set_secret(key, value).await
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        self.get_client()?.delete_secret(key, None).await?;

        Ok(())
    }

    async fn list_secrets(&self) -> Result<Vec<String>> {
        let mut pager = self
            .get_client()?
            .list_secret_properties(None)?
            .into_stream();
        let mut secrets = Vec::new();
        while let Some(props) = pager.try_next().await? {
            let name = props.resource_id()?.name;
            secrets.push(name);
        }

        Ok(secrets)
    }
}

impl AzureKeyVaultProvider {
    fn get_client(&self) -> Result<SecretClient> {
        let credential = DefaultAzureCredential::new()?;
        let client = SecretClient::new(
            format!(
                "https://{}.vault.azure.net",
                self.vault_name.as_ref().unwrap()
            )
            .as_str(),
            credential,
            None,
        )?;

        Ok(client)
    }
}
