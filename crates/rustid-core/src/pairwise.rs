//! Pairwise subject identifiers (OpenID Connect Core 1.0 §8): for a client
//! that asks for them, the subject it sees is made from its sector and the
//! user's own subject, so clients in different sectors can't match users
//! by `sub`. Only id tokens, userinfo answers and back-channel logout
//! tokens carry them; access tokens keep the user's own subject, which
//! rustid reads back from them.

use aws_lc_rs::digest;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::clients::{Client, SubjectType};
use crate::options::ProtocolOptions;

/// The distinct hosts of the client's redirect URIs, lower-cased.
pub fn redirect_hosts(client: &Client) -> Vec<String> {
    let mut hosts: Vec<String> = client
        .redirect_uris
        .iter()
        .filter_map(|uri| url::Url::parse(uri).ok())
        .filter_map(|u| u.host_str().map(str::to_ascii_lowercase))
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// The client's sector: the host of `sectorIdentifierUri`, else the host
/// its redirect URIs share, else (no redirect URIs) its client id.
pub fn sector(client: &Client) -> String {
    if let Some(host) = client
        .sector_identifier_uri
        .as_deref()
        .and_then(|uri| url::Url::parse(uri).ok())
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
    {
        return host;
    }
    match redirect_hosts(client).as_slice() {
        [host, ..] => host.clone(),
        [] => client.client_id.clone(),
    }
}

/// The pairwise subject the client sees for the user `local`, or `None`
/// for a public client or a server without a salt.
pub fn subject(options: &ProtocolOptions, client: &Client, local: &str) -> Option<String> {
    if client.subject_type != SubjectType::Pairwise {
        return None;
    }
    let salt = options.pairwise.salt.as_deref()?;
    let mut input = Vec::new();
    for part in [sector(client).as_str(), local, salt] {
        if !input.is_empty() {
            input.push(0);
        }
        input.extend_from_slice(part.as_bytes());
    }
    if let Some(client_salt) = client.pair_wise_subject_salt.as_deref() {
        input.push(0);
        input.extend_from_slice(client_salt.as_bytes());
    }
    Some(URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, &input)))
}

/// Whether the client wants pairwise subjects the server can't make (no
/// salt here: a deployment that lost it). Callers fail closed rather than
/// hand such a client the user's own subject.
pub fn unavailable(options: &ProtocolOptions, client: &Client) -> bool {
    client.subject_type == SubjectType::Pairwise && options.pairwise.salt.is_none()
}

/// The error for [`unavailable`].
pub fn unavailable_message(client: &Client) -> String {
    format!(
        "client {} is pairwise, but the server has no pairwise salt",
        client.client_id
    )
}

/// The subject the client sees for the user `local`: pairwise when it asks
/// for that, the user's own otherwise.
pub fn subject_for(options: &ProtocolOptions, client: &Client, local: &str) -> String {
    subject(options, client, local).unwrap_or_else(|| local.to_owned())
}
