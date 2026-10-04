//! A protected resource on the server itself (the local API authentication handler
//! in `DPoPAndBearer` mode), for conformance runs:
//! A bearer token, or a DPoP-bound token with a proof bound to it.

use crate::access_tokens::{ValidationContext, validate};
use crate::data_protection::DataProtector;
use crate::dpop::{self, BoundToken, INVALID_DPOP_PROOF};
use crate::stores::{StoreError, find_enabled_client};

/// The request as the resource sees it.
#[derive(Debug, Clone, Copy)]
pub struct ResourceRequest<'a> {
    /// The `Authorization` header.
    pub authorization: Option<&'a str>,
    /// The `DPoP` headers.
    pub dpop_proofs: &'a [String],
    pub method: &'a str,
    /// The resource's URL, which a proof's `htu` must name.
    pub url: &'a str,
    /// The client certificate the connection presented, which a token
    /// bound to a certificate (`cnf` `x5t#S256`) must match.
    pub client_certificate: Option<&'a crate::client_certificate::ClientCertificate>,
}

/// Why the request was refused: what `WWW-Authenticate` says, and a nonce
/// the client must use.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub bearer_error: Option<(String, Option<String>)>,
    pub dpop_error: Option<(String, Option<String>)>,
    pub dpop_nonce: Option<String>,
}

impl Challenge {
    /// Both schemes, each with its error.
    pub fn www_authenticate(&self) -> String {
        let scheme = |name: &str, error: &Option<(String, Option<String>)>| {
            let mut value = name.to_owned();
            if let Some((error, description)) = error {
                value.push_str(&format!(" error=\"{error}\""));
                if let Some(description) = description {
                    value.push_str(&format!(", error_description=\"{description}\""));
                }
            }
            value
        };
        format!(
            "{}, {}",
            scheme("Bearer", &self.bearer_error),
            scheme("DPoP", &self.dpop_error)
        )
    }
}

/// The token's subject (or client id) when the
/// request may be served. The outer error is a store failure.
pub async fn authenticate(
    ctx: &ValidationContext<'_>,
    request: &ResourceRequest<'_>,
    protector: &DataProtector,
) -> Result<Result<String, Challenge>, StoreError> {
    let refused = || Ok(Err(Challenge::default()));
    let Some(authorization) = request.authorization.filter(|a| !a.is_empty()) else {
        return refused();
    };
    let scheme = |name: &str| {
        authorization
            .get(..name.len())
            .filter(|s| s.eq_ignore_ascii_case(name))
            .map(|_| authorization[name.len()..].trim())
    };
    let (token, dpop) = match (scheme("Bearer "), scheme("DPoP ")) {
        (Some(token), _) => (token, false),
        (_, Some(token)) => (token, true),
        _ => return refused(),
    };
    if token.is_empty() {
        return refused();
    }
    let validated = match validate(ctx, token).await? {
        Ok(validated) => validated,
        Err(_) => return refused(),
    };
    let cnf = validated
        .first("cnf")
        .map(|c| serde_json::Value::String(c.to_owned()));
    if dpop {
        let client = match validated.first("client_id") {
            Some(id) => find_enabled_client(ctx.stores.clients.as_ref(), id).await?,
            None => None,
        };
        let Some(client) = client else {
            return refused();
        };
        let dpop_error = |description: &str, nonce: Option<String>| {
            Ok(Err(Challenge {
                dpop_error: Some((INVALID_DPOP_PROOF.to_owned(), Some(description.to_owned()))),
                dpop_nonce: nonce,
                ..Challenge::default()
            }))
        };
        if request.dpop_proofs.len() > 1 {
            return dpop_error("Too many DPoP headers provided.", None);
        }
        let proof = request
            .dpop_proofs
            .first()
            .map(String::as_str)
            .unwrap_or("");
        let verdict = dpop::validate(&dpop::ProofRequest {
            proof,
            method: request.method,
            url: request.url,
            mode: client.dpop_validation_mode,
            client_clock_skew: client.dpop_clock_skew.0,
            options: &ctx.options.dpop,
            replay: ctx.stores.replay.as_ref(),
            protector,
            now: ctx.now.timestamp(),
            access_token: Some(BoundToken {
                token,
                cnf: cnf.as_ref(),
            }),
        })
        .await?;
        if let Err(e) = verdict {
            return Ok(Err(Challenge {
                dpop_error: Some((e.error.to_owned(), e.description.map(str::to_owned))),
                dpop_nonce: e.nonce,
                ..Challenge::default()
            }));
        }
    } else if let Some(bound) = cnf.as_ref().and_then(certificate_thumbprint) {
        // RFC 8705: a certificate-bound token is a bearer token over a
        // connection presenting that certificate.
        if request.client_certificate.map(|c| c.x5t_s256.as_str()) != Some(bound.as_str()) {
            return Ok(Err(Challenge {
                bearer_error: Some((
                    crate::access_tokens::INVALID_TOKEN.to_owned(),
                    Some("The access token is bound to another client certificate".to_owned()),
                )),
                ..Challenge::default()
            }));
        }
    } else if cnf.is_some() {
        return Ok(Err(Challenge {
            bearer_error: Some((
                crate::access_tokens::INVALID_TOKEN.to_owned(),
                Some("Must use DPoP when using an access token with a 'cnf' claim".to_owned()),
            )),
            ..Challenge::default()
        }));
    }
    Ok(Ok(validated
        .first("sub")
        .or(validated.first("client_id"))
        .unwrap_or_default()
        .to_owned()))
}

/// The `x5t#S256` of a `cnf` claim (as JSON text), when it binds the token
/// to a certificate.
fn certificate_thumbprint(cnf: &serde_json::Value) -> Option<String> {
    let text = cnf.as_str()?;
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value.get("x5t#S256")?.as_str().map(str::to_owned)
}
