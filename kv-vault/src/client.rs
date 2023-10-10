//! Hashicorp vault client
//!
use std::{string::ToString, sync::Arc};

use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration as StdDuration;
use tokio::sync::oneshot::{Receiver, Sender};
use tracing::{debug, error, info};
use vaultrs::api::kv2::responses::SecretVersionMetadata;
use vaultrs::client::{Client as ClientTrait, VaultClient, VaultClientSettings};

use crate::{config::Config, error::VaultError};

/// Vault HTTP api version. As of Vault 1.9.x (Feb 2022), all http api calls use version 1
const API_VERSION: u8 = 1;

/// Default TTL for tokens used by this provider. Defaults to 72 hours.
const TOKEN_INCREMENT_TTL: &str = "72h";
pub const TOKEN_REFRESH_INTERVAL: StdDuration = StdDuration::from_secs(60 * 60 * 12); // 12 hours

/// Vault client connection information.
#[derive(Clone)]
pub struct Client {
    inner: Arc<vaultrs::client::VaultClient>,
    namespace: String,
    token_increment_ttl: String,
    token_refresh_interval: StdDuration,
    sender: Arc<Sender<()>>,
}

impl Client {
    /// Creates a new Vault client. See [config](./config.rs) for explanation of parameters.
    ///
    /// Note that this constructor does not attempt to connect to the vault server,
    /// so the vault server does not need to be running at the time a LinkDefinition to this provider is created.
    pub fn new(config: Config) -> Result<Self, VaultError> {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let client = Client {
            inner: Arc::new(VaultClient::new(VaultClientSettings {
                token: config.token,
                address: config.addr,
                ca_certs: config.certs,
                verify: false,
                version: API_VERSION,
                wrapping: false,
                timeout: None,
            })?),
            namespace: config.mount,
            token_increment_ttl: config
                .token_increment_ttl
                .unwrap_or(TOKEN_INCREMENT_TTL.into()),
            token_refresh_interval: config
                .token_refresh_interval
                .unwrap_or(TOKEN_REFRESH_INTERVAL.into()),
            sender: Arc::new(tx),
        };
        client.run_renewal(rx);
        Ok(client)
    }

    /// Reads value of secret using namespace and key path
    pub async fn read_secret<D: DeserializeOwned>(&self, path: &str) -> Result<D, VaultError> {
        match vaultrs::kv2::read(self.inner.as_ref(), &self.namespace, path).await {
            Err(vaultrs::error::ClientError::APIError { code, errors: _ }) if code == 404 => {
                Err(VaultError::NotFound {
                    namespace: self.namespace.clone(),
                    path: path.to_string(),
                })
            }
            Err(e) => Err(e.into()),
            Ok(val) => Ok(val),
        }
    }

    /// Writes value of secret using namespace and key path
    pub async fn write_secret<T: Serialize>(
        &self,
        path: &str,
        data: &T,
    ) -> Result<SecretVersionMetadata, VaultError> {
        vaultrs::kv2::set(self.inner.as_ref(), &self.namespace, path, data)
            .await
            .map_err(VaultError::from)
    }

    /// Deletes the latest version of the secret. Note that if versions are in use, only the latest is deleted
    /// Returns Ok if the key was deleted, or Err for any other error including key not found
    pub async fn delete_latest<T: Serialize>(&self, path: &str) -> Result<(), VaultError> {
        vaultrs::kv2::delete_latest(self.inner.as_ref(), &self.namespace, path)
            .await
            .map_err(VaultError::from)
    }

    /// Lists keys at the path
    pub async fn list_secrets(&self, path: &str) -> Result<Vec<String>, VaultError> {
        match vaultrs::kv2::list(self.inner.as_ref(), &self.namespace, path).await {
            Err(vaultrs::error::ClientError::APIError { code, errors: _ }) if code == 404 => {
                Err(VaultError::NotFound {
                    namespace: self.namespace.clone(),
                    path: path.to_string(),
                })
            }
            Err(e) => Err(e.into()),
            Ok(secret_list) => Ok(secret_list),
        }
    }

    async fn run_renewal(&self, reciever: Receiver<()>) {
        // need to shut down
        let client = self.inner.to_owned();
        let interval = self.token_refresh_interval;
        let ttl = self.token_increment_ttl.clone();

        tokio::spawn(async move {
            let mut next_interval = tokio::time::interval(interval);
            tokio::select! {
            _ = async {
                     loop {
                         next_interval.tick().await;
                         let _ = renew_self(&client, ttl.as_str()).await;
                     }
                 } => {}
            _ =  reciever => {
                     info!("stopping token renewal loop");
                     return
                 }
             }
        });
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.sender.send(());
    }
}

async fn renew_self(client: &VaultClient, interval: &str) -> Result<(), VaultError> {
    debug!("renewing token");
    client.renew(Some(interval)).await.map_err(|e| {
        error!("error renewing self token: {}", e);
        VaultError::from(e)
    })?;

    let info = client.lookup().await.map_err(|e| {
        error!("error looking up self token: {}", e);
        VaultError::from(e)
    })?;

    let expire_time = info.expire_time.unwrap_or_else(|| "None".to_string());
    info!(%expire_time, accessor = %info.accessor, "renewed token");
    Ok(())
}
