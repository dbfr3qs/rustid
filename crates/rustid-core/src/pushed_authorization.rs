//! Pushed authorization requests (RFC 9126): the pushed authorization request validator,
//! the pushed authorization response generator and the pushed authorization service.
//! Pushed parameters are persisted grants keyed by the reference value's
//! hash, so the reference itself is never stored.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::authorize::validation::{AuthorizeContext, AuthorizeFailure, validate_pushed};
use crate::clients::Client;
use crate::data_protection::DataProtector;
use crate::dpop;
use crate::grants::{PersistedGrant, hashed_key, new_handle};
use crate::params::Params;
use crate::replay::ReplayCache;
use crate::stores::{PersistedGrantStore, StoreError};

/// Grant type of pushed requests (rustid's own).
pub const PUSHED_AUTHORIZATION_REQUEST: &str = "pushed_authorization_request";

/// The `request_uri` prefix of pushed authorization requests (RFC 9126).
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri";

/// What was pushed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushedRequest {
    /// The pushed parameters as a query string.
    pub parameters: String,
    pub expires_at: DateTime<Utc>,
}

/// A refused push: HTTP 400 with `error` and `error_description`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushError {
    pub error: String,
    pub description: Option<String>,
    /// A DPoP server nonce for the `DPoP-Nonce` header.
    pub dpop_nonce: Option<String>,
}

impl PushError {
    fn new(error: &str, description: Option<String>) -> Self {
        PushError {
            error: error.to_owned(),
            description,
            dpop_nonce: None,
        }
    }
}

/// A DPoP proof sent with a push, and what validating it needs.
pub struct PushProof<'a> {
    pub proof: &'a str,
    /// The pushed authorization endpoint's URL, which `htu` must name.
    pub url: &'a str,
    pub replay: &'a dyn ReplayCache,
    pub protector: &'a DataProtector,
}

/// The pushed authorization request validator then
/// Refuses a `request_uri`, binds
/// the code to a DPoP proof's key, validates the parameters as the
/// authorize endpoint would for `client`, and stores them. Returns the
/// `request_uri` and its lifetime in seconds.
pub async fn push(
    ctx: &AuthorizeContext<'_>,
    client: &Client,
    parameters: Params,
    dpop: Option<&PushProof<'_>>,
) -> Result<(String, i64), PushError> {
    if parameters
        .get("request_uri")
        .is_some_and(|u| !u.trim().is_empty())
    {
        return Err(PushError::new(
            "invalid_request",
            Some("Pushed authorization cannot use request_uri".into()),
        ));
    }
    let mut parameters = parameters;
    // RFC 9126 §3: a push carrying a request object comes from the client
    // that authenticated, so a form without client_id is that client's (as
    // FAPI 2 Message Signing clients send it); the request object's
    // client_id is still checked.
    let has_object = parameters
        .get("request")
        .is_some_and(|r| !r.trim().is_empty());
    if has_object && parameters.get("client_id").is_none() {
        parameters.add("client_id", &client.client_id);
    }
    let thumbprint = match dpop {
        Some(dpop) => Some(validate_proof(ctx, client, &parameters, dpop).await?),
        None => None,
    };
    // The proof binds the code: its thumbprint becomes dpop_jkt. With a
    // request object that may carry dpop_jkt itself, it's checked after the
    // object is merged, so it isn't a duplicate of the form's parameters.
    if let Some(jkt) = &thumbprint
        && !has_object
        && parameters.get("dpop_jkt").is_none()
    {
        parameters.add("dpop_jkt", jkt);
    }
    let request = match validate_pushed(ctx, parameters.clone()).await {
        Ok(request) => request,
        Err(AuthorizeFailure::Invalid(e)) => {
            return Err(PushError::new(e.error, e.description));
        }
        Err(AuthorizeFailure::Server(message)) => {
            return Err(PushError::new("server_error", Some(message)));
        }
    };
    if let Some(jkt) = &thumbprint
        && has_object
    {
        match request.raw.get("dpop_jkt") {
            Some(object_jkt) if object_jkt != *jkt => return Err(jkt_mismatch()),
            Some(_) => {}
            None => parameters.add("dpop_jkt", jkt),
        }
    }
    // The authenticated client is the one pushing, whatever the form says.
    if request.client_id.as_deref() != Some(client.client_id.as_str()) {
        return Err(PushError::new(
            "invalid_request",
            Some("client_id does not match the authenticated client".into()),
        ));
    }
    let lifetime = client
        .pushed_authorization_lifetime
        .map(i64::from)
        .unwrap_or(ctx.options.pushed_authorization.lifetime);
    let reference = new_handle();
    // The client's credentials are never stored (nor shown to the UI in
    // the authorization context later): they are stripped here, and
    // nothing at the authorize endpoint reads them.
    for credential in ["client_secret", "client_assertion", "client_assertion_type"] {
        parameters.remove(credential);
    }
    let pushed = PushedRequest {
        parameters: parameters.to_query_string(),
        expires_at: ctx.now + Duration::seconds(lifetime),
    };
    store(
        ctx.stores.grants.as_ref(),
        &reference,
        &client.client_id,
        &pushed,
        ctx.now,
    )
    .await
    .map_err(|e| PushError::new("server_error", Some(e.to_string())))?;
    Ok((format!("{REQUEST_URI_PREFIX}:{reference}"), lifetime))
}

/// Validates the push's DPoP proof and returns its key's thumbprint, which
/// must match a `dpop_jkt` the form sends too.
async fn validate_proof(
    ctx: &AuthorizeContext<'_>,
    client: &Client,
    parameters: &Params,
    dpop: &PushProof<'_>,
) -> Result<String, PushError> {
    if crate::params::utf16_len(dpop.proof) > ctx.options.input_length_restrictions.dpop_proof_token
    {
        tracing::error!("DPoP proof token is too long");
        return Err(PushError::new(
            dpop::INVALID_DPOP_PROOF,
            Some("DPoP proof token is too long".into()),
        ));
    }
    let proof = dpop::validate(&dpop::ProofRequest {
        proof: dpop.proof,
        method: "POST",
        url: dpop.url,
        mode: client.dpop_validation_mode,
        client_clock_skew: client.dpop_clock_skew.0,
        options: &ctx.options.dpop,
        replay: dpop.replay,
        protector: dpop.protector,
        now: ctx.now.timestamp(),
        access_token: None,
    })
    .await
    .map_err(|e| {
        PushError::new(
            "server_error",
            Some(format!("the replay cache failed: {e}")),
        )
    })?
    .map_err(|e| match e.nonce {
        // An empty description.
        Some(nonce) => PushError {
            error: dpop::USE_DPOP_NONCE.to_owned(),
            description: Some(String::new()),
            dpop_nonce: Some(nonce),
        },
        None => PushError::new(
            e.error,
            Some(e.description.unwrap_or("Invalid DPoP Proof").to_owned()),
        ),
    })?;
    match parameters.get("dpop_jkt") {
        Some(jkt) if jkt != proof.thumbprint => Err(jkt_mismatch()),
        _ => Ok(proof.thumbprint),
    }
}

fn jkt_mismatch() -> PushError {
    PushError::new(
        "invalid_request",
        Some(
            "Mismatch between thumbprint of JWK in DPoP HTTP header and dpop_jkt parameter".into(),
        ),
    )
}

fn key(reference: &str) -> String {
    hashed_key(reference, PUSHED_AUTHORIZATION_REQUEST)
}

/// The pushed request under its reference's hash.
pub async fn store(
    grants: &dyn PersistedGrantStore,
    reference: &str,
    client_id: &str,
    pushed: &PushedRequest,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    grants
        .store(PersistedGrant {
            key: key(reference),
            grant_type: PUSHED_AUTHORIZATION_REQUEST.to_owned(),
            client_id: client_id.to_owned(),
            subject_id: None,
            session_id: None,
            description: None,
            creation_time: now,
            expiration: Some(pushed.expires_at),
            consumed_time: None,
            data: serde_json::to_string(pushed).expect("a pushed request serialises"),
        })
        .await
}

pub async fn get(
    grants: &dyn PersistedGrantStore,
    reference: &str,
) -> Result<Option<PushedRequest>, StoreError> {
    Ok(grants
        .get(&key(reference))
        .await?
        .filter(|g| g.grant_type == PUSHED_AUTHORIZATION_REQUEST)
        .and_then(|g| serde_json::from_str(&g.data).ok()))
}

/// A pushed request is used once.
pub async fn consume(grants: &dyn PersistedGrantStore, reference: &str) -> Result<(), StoreError> {
    grants.remove(&key(reference)).await
}
