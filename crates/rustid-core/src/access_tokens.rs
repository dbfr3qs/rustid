//! JWT access tokens are checked
//! as `JsonWebTokenHandler` checks them, reference tokens are
//! looked up in the grant store.

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::claims;
use crate::jwt::Jws;
use crate::key_service::KeyService;
use crate::keys::LoadedKey;
use crate::options::ProtocolOptions;
use crate::reference_tokens;
use crate::stores::{StoreError, Stores, find_enabled_client};
use crate::tokens::{CLAIM_VALUE_INTEGER64, Claim};

pub const INVALID_TOKEN: &str = "invalid_token";
pub const EXPIRED_TOKEN: &str = "expired_token";

pub struct ValidationContext<'a> {
    pub options: &'a ProtocolOptions,
    pub stores: &'a Stores,
    pub keys: &'a KeyService,
    pub issuer: &'a str,
    pub now: DateTime<Utc>,
}

/// A valid access token's claims, in a fixed order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedToken {
    pub claims: Vec<Claim>,
}

impl ValidatedToken {
    pub fn first(&self, claim_type: &str) -> Option<&str> {
        self.claims
            .iter()
            .find(|c| c.claim_type == claim_type)
            .map(|c| c.value.as_str())
    }
}

/// Validates an access token. The verdict's error is `invalid_token` or
/// `expired_token`, as `ProtectedResourceErrors`; the outer error is a store
/// failure.
#[tracing::instrument(name = "access_token.validate", skip_all)]
pub async fn validate(
    ctx: &ValidationContext<'_>,
    token: &str,
) -> Result<Result<ValidatedToken, &'static str>, StoreError> {
    let limits = &ctx.options.input_length_restrictions;
    let verdict = if token.contains('.') {
        if token.len() > limits.jwt {
            return Ok(Err(INVALID_TOKEN));
        }
        let keys = ctx.keys.validation_keys().await?;
        validate_jwt(ctx, &keys, token)
    } else {
        if token.len() > limits.token_handle {
            return Ok(Err(INVALID_TOKEN));
        }
        validate_reference(ctx, token).await?
    };
    let validated = match verdict {
        Ok(validated) => validated,
        Err(error) => return Ok(Err(error)),
    };
    let client = match validated.first("client_id") {
        Some(client_id) => match find_enabled_client(ctx.stores.clients.as_ref(), client_id).await?
        {
            Some(client) => Some(client),
            None => return Ok(Err(INVALID_TOKEN)),
        },
        None => None,
    };
    // A user's token is only good while the user is active.
    if let (Some(client), Some(sub)) = (&client, validated.first("sub")) {
        let subject_claims: Vec<Claim> = validated
            .claims
            .iter()
            .filter(|c| c.claim_type != "sub")
            .cloned()
            .collect();
        let active = ctx
            .stores
            .profile
            .is_active(&crate::profile::ActiveRequest {
                caller: crate::profile::active_callers::ACCESS_TOKEN,
                client,
                subject_id: sub,
                subject_claims: &subject_claims,
            })
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        if !active {
            tracing::error!(subject = sub, "User marked as not active");
            return Ok(Err(INVALID_TOKEN));
        }
        if let Some(sid) = validated.first("sid")
            && !crate::server_side_sessions::validate_session(ctx, client, sub, Some(sid)).await?
        {
            tracing::error!(subject = sub, "Server-side session invalid");
            return Ok(Err(INVALID_TOKEN));
        }
    }
    Ok(Ok(validated))
}

/// Validate jwt without an audience: signature against the validation
/// keys, issuer, lifetime with clock skew, and the access token `typ`.
fn validate_jwt(
    ctx: &ValidationContext<'_>,
    keys: &[std::sync::Arc<LoadedKey>],
    token: &str,
) -> Result<ValidatedToken, &'static str> {
    let jws = Jws::decode(token).ok_or(INVALID_TOKEN)?;
    let typ = ctx.options.access_token_jwt_type.as_str();
    if !typ.is_empty() && jws.header_str("typ") != Some(typ) {
        return Err(INVALID_TOKEN);
    }
    if !signature_is_valid(keys, &jws) {
        return Err(INVALID_TOKEN);
    }
    if jws.claim_str("iss") != Some(ctx.issuer) {
        return Err(INVALID_TOKEN);
    }
    // NumericDates must read as integers; the claims carry the values read.
    let mut payload = jws.payload.clone();
    let mut dates = [None; 3];
    for (slot, name) in dates.iter_mut().zip(["exp", "nbf", "iat"]) {
        *slot = jws.numeric_date(name).map_err(|_| INVALID_TOKEN)?;
        if let Some(value) = *slot {
            payload.insert(name.to_owned(), Value::from(value));
        }
    }
    let [exp, nbf, _] = dates;
    let now = ctx.now.timestamp();
    let skew = ctx.options.jwt_validation_clock_skew.0;
    let exp = exp.ok_or(INVALID_TOKEN)?;
    if let Some(nbf) = nbf
        && (nbf > exp || nbf > now.saturating_add(skew))
    {
        return Err(INVALID_TOKEN);
    }
    if exp < now.saturating_sub(skew) {
        return Err(EXPIRED_TOKEN);
    }
    let mut claims = claims::from_jwt_payload(&payload);
    // Space-delimited scope strings are split, the parts appended at the end.
    let joined: Vec<Claim> = claims
        .iter()
        .filter(|c| c.claim_type == "scope" && c.value.contains(' '))
        .cloned()
        .collect();
    for scope in joined {
        claims.retain(|c| c != &scope);
        claims.extend(
            scope
                .value
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(|s| Claim::string("scope", s)),
        );
    }
    Ok(ValidatedToken { claims })
}

/// `JsonWebTokenHandler` key selection: the key named by `kid` when there is
/// one, otherwise every validation key.
fn signature_is_valid(keys: &[std::sync::Arc<LoadedKey>], jws: &Jws) -> bool {
    let named = jws
        .header_str("kid")
        .and_then(|kid| keys.iter().find(|k| k.kid == kid));
    match named {
        Some(key) => jws.verify(&key.public_jwk()),
        None => keys.iter().any(|k| jws.verify(&k.public_jwk())),
    }
}

/// An expired token is removed.
async fn validate_reference(
    ctx: &ValidationContext<'_>,
    handle: &str,
) -> Result<Result<ValidatedToken, &'static str>, StoreError> {
    let grants = ctx.stores.grants.as_ref();
    let Some(token) = reference_tokens::get(grants, handle).await? else {
        return Ok(Err(INVALID_TOKEN));
    };
    if token.has_expired(ctx.now) {
        reference_tokens::remove(grants, handle).await?;
        return Ok(Err(EXPIRED_TOKEN));
    }
    if find_enabled_client(ctx.stores.clients.as_ref(), &token.client_id)
        .await?
        .is_none()
    {
        return Ok(Err(INVALID_TOKEN));
    }
    let created = token.creation_time.timestamp().to_string();
    let integer = |claim_type: &str, value: String| Claim {
        claim_type: claim_type.to_owned(),
        value,
        value_type: CLAIM_VALUE_INTEGER64.to_owned(),
    };
    let mut claims = vec![
        Claim::string("iss", &token.issuer),
        integer("nbf", created.clone()),
        integer("iat", created),
        integer("exp", token.expiration().timestamp().to_string()),
    ];
    if let Some(cnf) = token.confirmation.as_deref().filter(|c| !c.is_empty()) {
        claims.push(Claim {
            claim_type: "cnf".to_owned(),
            value: cnf.to_owned(),
            value_type: crate::tokens::CLAIM_VALUE_JSON.to_owned(),
        });
    }
    claims.extend(token.audiences.iter().map(|aud| Claim::string("aud", aud)));
    claims.extend(
        token
            .claims
            .into_iter()
            .filter(|c| !matches!(c.claim_type.as_str(), "iat" | "iss" | "nbf" | "exp")),
    );
    Ok(Ok(ValidatedToken { claims }))
}
