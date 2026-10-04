//! `ConnectedApplicationStore`: clients and SAML service providers as one
//! read-only list of applications. It reads the configuration store, so
//! disabled applications are included, as storage-backed stores
//! include them.

use std::sync::Arc;

use rustid_core::clients::Client;
use rustid_core::stores::{ConfigurationStore, EntityKind, StoreError, StoredEntity};

use crate::model::ServiceProvider;

/// The connected application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedApplication {
    /// The client id, or the SP's entity id.
    pub identifier: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    /// `oidc` for clients (their `protocolType`), `saml2p` for SPs.
    pub protocol_type: String,
    /// Always false for SPs.
    pub require_consent: bool,
}

pub const SAML2P: &str = "saml2p";

fn parse<T: serde::de::DeserializeOwned>(entity: &StoredEntity) -> Result<T, StoreError> {
    serde_json::from_value(entity.data.clone())
        .map_err(|e| StoreError::Backend(format!("stored {}: {e}", entity.key)))
}

fn client(entity: &StoredEntity) -> Result<ConnectedApplication, StoreError> {
    let client: Client = parse(entity)?;
    Ok(ConnectedApplication {
        identifier: client.client_id,
        display_name: client.client_name,
        description: client.description,
        enabled: client.enabled,
        protocol_type: client.protocol_type,
        require_consent: client.require_consent,
    })
}

fn service_provider(entity: &StoredEntity) -> Result<ConnectedApplication, StoreError> {
    let sp: ServiceProvider = parse(entity)?;
    Ok(ConnectedApplication {
        identifier: sp.entity_id,
        display_name: sp.display_name,
        description: sp.description,
        enabled: sp.enabled,
        protocol_type: SAML2P.to_owned(),
        require_consent: false,
    })
}

pub struct ConnectedApplicationStore {
    configuration: Arc<dyn ConfigurationStore>,
}

impl ConnectedApplicationStore {
    pub fn new(configuration: Arc<dyn ConfigurationStore>) -> Self {
        ConnectedApplicationStore { configuration }
    }

    /// The client with this id, else the SP with this entity id.
    pub async fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<ConnectedApplication>, StoreError> {
        if let Some(entity) = self
            .configuration
            .read_by_key(EntityKind::Client, identifier)
            .await?
        {
            return client(&entity).map(Some);
        }
        self.configuration
            .read_by_key(EntityKind::SamlServiceProvider, identifier)
            .await?
            .as_ref()
            .map(service_provider)
            .transpose()
    }

    /// Every client, then every SP.
    pub async fn get_all(&self) -> Result<Vec<ConnectedApplication>, StoreError> {
        let mut all = Vec::new();
        for entity in self.configuration.list(EntityKind::Client).await? {
            all.push(client(&entity)?);
        }
        for entity in self
            .configuration
            .list(EntityKind::SamlServiceProvider)
            .await?
        {
            all.push(service_provider(&entity)?);
        }
        Ok(all)
    }
}
