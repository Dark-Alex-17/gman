use std::sync::Arc;

use azure_core::credentials::TokenCredential;
use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_secrets::models::SetSecretParameters;
use azure_security_keyvault_secrets::{ResourceExt, SecretClient};
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use validator::Validate;

use crate::providers::SecretProvider;
use crate::providers::error::{SecretError, classify_azure_error};

const PROVIDER: &str = "azure_key_vault";

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
    pub vault_name: Option<String>,
}

#[async_trait::async_trait]
impl SecretProvider for AzureKeyVaultProvider {
    fn name(&self) -> &'static str {
        "AzureKeyVaultProvider"
    }

    async fn get_secret(&self, key: &str) -> Result<String, SecretError> {
        let response = self
            .get_client()?
            .get_secret(key, None)
            .await
            .map_err(|e| classify_azure_error(e.into(), Some(key), "get_secret"))?;
        let body = response
            .into_model()
            .map_err(|e| SecretError::Other(e.into()))?;

        body.value.ok_or_else(|| SecretError::NotFound {
            key: key.to_string(),
            provider: PROVIDER,
        })
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<(), SecretError> {
        let params = SetSecretParameters {
            value: Some(value.to_string()),
            ..Default::default()
        };

        let body = params.try_into().map_err(|e: azure_core::Error| {
            classify_azure_error(e.into(), Some(key), "set_secret")
        })?;

        self.get_client()?
            .set_secret(key, body, None)
            .await
            .map_err(|e| classify_azure_error(e.into(), Some(key), "set_secret"))?
            .into_model()
            .map_err(|e| SecretError::Other(e.into()))?;

        Ok(())
    }

    async fn update_secret(&self, key: &str, value: &str) -> Result<(), SecretError> {
        self.set_secret(key, value).await
    }

    async fn delete_secret(&self, key: &str) -> Result<(), SecretError> {
        self.get_client()?
            .delete_secret(key, None)
            .await
            .map_err(|e| classify_azure_error(e.into(), Some(key), "delete_secret"))?;

        Ok(())
    }

    async fn list_secrets(&self) -> Result<Vec<String>, SecretError> {
        let mut pager = self
            .get_client()?
            .list_secret_properties(None)
            .map_err(|e| classify_azure_error(e.into(), None, "list_secrets"))?;
        let mut secrets = Vec::new();
        while let Some(props) = pager
            .try_next()
            .await
            .map_err(|e| classify_azure_error(e.into(), None, "list_secrets"))?
        {
            let name = props
                .resource_id()
                .map_err(|e| SecretError::Other(e.into()))?
                .name;
            secrets.push(name);
        }

        Ok(secrets)
    }
}

impl AzureKeyVaultProvider {
    fn get_client(&self) -> Result<SecretClient, SecretError> {
        let credential: Arc<dyn TokenCredential> =
            DeveloperToolsCredential::new(None).map_err(|e| SecretError::AuthFailed {
                provider: PROVIDER,
                source: e.into(),
            })?;
        let vault_name = self
            .vault_name
            .as_ref()
            .ok_or_else(|| SecretError::Config {
                provider: PROVIDER,
                message: "vault_name is required".to_string(),
            })?;
        let client = SecretClient::new(
            format!("https://{}.vault.azure.net", vault_name).as_str(),
            credential,
            None,
        )
        .map_err(|e| SecretError::Config {
            provider: PROVIDER,
            message: format!("failed to create Azure Key Vault client: {}", e),
        })?;

        Ok(client)
    }
}
