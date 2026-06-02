use anyhow::anyhow;
use gcloud_sdk::google::cloud::secretmanager::v1;
use gcloud_sdk::google::cloud::secretmanager::v1::replication::Automatic;
use gcloud_sdk::google::cloud::secretmanager::v1::secret_manager_service_client::SecretManagerServiceClient;
use gcloud_sdk::google::cloud::secretmanager::v1::{
    AccessSecretVersionRequest, AddSecretVersionRequest, CreateSecretRequest, ListSecretsRequest,
    Replication, Secret, replication,
};
use gcloud_sdk::proto_ext::secretmanager::SecretPayload;
use gcloud_sdk::tonic::Code;
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use v1::DeleteSecretRequest;
use validator::Validate;

use crate::providers::SecretProvider;
use crate::providers::error::{SecretError, classify_gcp_error};

type SecretsManagerClient = GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>>;

const PROVIDER: &str = "gcp_secret_manager";

#[skip_serializing_none]
/// Configuration for GCP Secret Manager provider
/// See [GCP Secret Manager](https://cloud.google.com/secret-manager)
/// for more information.
///
/// This provider stores secrets in GCP Secret Manager. It requires
/// a GCP project ID to be specified.
///
/// Example
/// ```no_run
/// use gman::providers::{SecretProvider, SupportedProvider};
/// use gman::config::{Config, ProviderConfig};
/// use gman::providers::gcp_secret_manager::GcpSecretManagerProvider;
///
/// let provider = GcpSecretManagerProvider {
/// 	gcp_project_id: Some("my-gcp-project".to_string()),
/// };
///	let _ =	provider.set_secret("MY_SECRET", "value");
#[derive(Debug, Clone, Validate, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GcpSecretManagerProvider {
    #[validate(required)]
    pub gcp_project_id: Option<String>,
}

#[async_trait::async_trait]
impl SecretProvider for GcpSecretManagerProvider {
    fn name(&self) -> &'static str {
        "GcpSecretManagerProvider"
    }

    async fn get_secret(&self, key: &str) -> Result<String, SecretError> {
        let response = self
            .get_client()
            .await?
            .get()
            .access_secret_version(AccessSecretVersionRequest {
                name: format!(
                    "projects/{}/secrets/{}/versions/latest",
                    self.gcp_project_id.as_ref().unwrap(),
                    key
                ),
            })
            .await
            .map_err(|e| classify_gcp_error(e.into(), Some(key), "get_secret"))?
            .into_inner();
        let payload = response.payload.ok_or_else(|| SecretError::NotFound {
            key: key.to_string(),
            provider: PROVIDER,
        })?;
        let secret_value = payload.data.ref_sensitive_value().to_vec();
        let secret_string = String::from_utf8(secret_value)
            .map_err(|_| SecretError::Other(anyhow!("secret value is not valid UTF-8")))?;

        Ok(secret_string)
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<(), SecretError> {
        let parent = format!("projects/{}", self.gcp_project_id.as_ref().unwrap());
        let secret_name = format!("{}/secrets/{}", parent, key);
        let secret = Secret {
            replication: Some(Replication {
                replication: Some(replication::Replication::Automatic(Automatic {
                    customer_managed_encryption: None,
                })),
            }),
            ..Default::default()
        };
        let client = self.get_client().await?;

        client
            .get()
            .create_secret(CreateSecretRequest {
                parent: parent.clone(),
                secret_id: key.to_string(),
                secret: Some(secret),
            })
            .await
            .map_err(|e| {
                if e.code() == Code::AlreadyExists {
                    SecretError::AlreadyExists {
                        key: key.to_string(),
                        provider: PROVIDER,
                    }
                } else {
                    classify_gcp_error(e.into(), Some(key), "set_secret")
                }
            })?;

        let bytes = value.as_ref();
        let crc32c = crc32c::crc32c(bytes) as i64;
        client
            .get()
            .add_secret_version(AddSecretVersionRequest {
                parent: secret_name,
                payload: Some(SecretPayload {
                    data: bytes.to_vec().into(),
                    data_crc32c: Some(crc32c),
                }),
            })
            .await
            .map_err(|e| classify_gcp_error(e.into(), Some(key), "set_secret"))?;

        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> Result<(), SecretError> {
        let name = format!(
            "projects/{}/secrets/{}",
            self.gcp_project_id.as_ref().unwrap(),
            key
        );
        self.get_client()
            .await?
            .get()
            .delete_secret(DeleteSecretRequest {
                name,
                etag: "".to_string(),
            })
            .await
            .map_err(|e| classify_gcp_error(e.into(), Some(key), "delete_secret"))?;
        Ok(())
    }

    async fn update_secret(&self, key: &str, value: &str) -> Result<(), SecretError> {
        let parent = format!(
            "projects/{}/secrets/{}",
            self.gcp_project_id.as_ref().unwrap(),
            key
        );
        let bytes = value.as_ref();
        let crc32c = crc32c::crc32c(bytes) as i64;

        self.get_client()
            .await?
            .get()
            .add_secret_version(AddSecretVersionRequest {
                parent,
                payload: Some(SecretPayload {
                    data: bytes.to_vec().into(),
                    data_crc32c: Some(crc32c),
                }),
            })
            .await
            .map_err(|e| classify_gcp_error(e.into(), Some(key), "update_secret"))?;

        Ok(())
    }

    async fn list_secrets(&self) -> Result<Vec<String>, SecretError> {
        let request = ListSecretsRequest {
            parent: format!("projects/{}", self.gcp_project_id.as_ref().unwrap()),
            ..Default::default()
        };
        let secrets = self
            .get_client()
            .await?
            .get()
            .list_secrets(request)
            .await
            .map_err(|e| classify_gcp_error(e.into(), None, "list_secrets"))?
            .into_inner()
            .secrets
            .iter()
            .map(|s| {
                let full_secret_name = &s.name;

                if let Some(secret_name) = full_secret_name.split("/secrets/").nth(1) {
                    secret_name.to_string()
                } else {
                    full_secret_name.to_string()
                }
            })
            .collect();
        Ok(secrets)
    }
}

impl GcpSecretManagerProvider {
    async fn get_client(&self) -> Result<SecretsManagerClient, SecretError> {
        let client = GoogleApi::from_function(
            SecretManagerServiceClient::new,
            "https://secretmanager.googleapis.com",
            None,
        )
        .await
        .map_err(|e| SecretError::AuthFailed {
            provider: PROVIDER,
            source: e.into(),
        })?;

        Ok(client)
    }
}
