//! RFC 7592 client management (read and delete only): a
//! registered client read or deleted with its registration access token.

use serde_json::{Map, Value};

use crate::admin::secrets::{HashAlgorithm, hash_secret};
use crate::clients::Client;

/// The client property holding the SHA-256 of its registration access token.
pub const TOKEN_PROPERTY: &str = "dcr_registration_token_sha256";
/// The client property holding the registration response a read returns
/// (without the secret or the management members).
pub const METADATA_PROPERTY: &str = "dcr_metadata";

/// Whether `token` is `client`'s registration access token. A client
/// registered without management (or a static one) has none.
pub fn authorize_management(client: &Client, token: &str) -> bool {
    let Some(expected) = client.properties.get(TOKEN_PROPERTY) else {
        return false;
    };
    let actual = hash_secret(token, HashAlgorithm::Sha256);
    aws_lc_rs::constant_time::verify_slices_are_equal(expected.as_bytes(), actual.as_bytes())
        .is_ok()
}

/// The client's registration metadata, with `registration_client_uri`
/// after `client_id`.
pub fn read(client: &Client, registration_client_uri: &str) -> Option<Map<String, Value>> {
    let stored = client.properties.get(METADATA_PROPERTY)?;
    let Ok(Value::Object(metadata)) = serde_json::from_str::<Value>(stored) else {
        return None;
    };
    let mut out = Map::new();
    for (key, value) in metadata {
        if key == "registration_client_uri" || key == "registration_access_token" {
            continue;
        }
        let is_id = key == "client_id";
        out.insert(key, value);
        if is_id {
            out.insert(
                "registration_client_uri".into(),
                Value::String(registration_client_uri.to_owned()),
            );
        }
    }
    Some(out)
}
