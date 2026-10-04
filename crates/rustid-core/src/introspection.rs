//! The introspection endpoint's protocol logic (RFC 7662):
//! `IntrospectionEndpoint`, the introspection request validator and
//! the introspection response generator, without HTTP types.

use std::sync::Arc;

use serde_json::{Map, Value};
use tracing::Instrument;

use crate::access_tokens::{self, ValidationContext};
use crate::claims::to_dictionary;
use crate::client_auth::{authenticate_api, authenticate_client};
use crate::clients::Client;
use crate::events::{Event, EventDetails, obfuscate};
use crate::form::Form;
use crate::refresh_tokens;
use crate::resources::ApiResource;
use crate::stores::StoreError;
use crate::telemetry;
use crate::token::TokenContext;
use crate::tokens::Claim;

/// Recognised token type hints.
pub const SUPPORTED_TOKEN_TYPE_HINTS: &[&str] = &["refresh_token", "access_token"];

#[derive(Debug, Clone, PartialEq)]
pub enum Introspection {
    /// Neither an API resource nor a client authenticated: HTTP 401.
    Unauthorized,
    /// A request error such as `missing_token`: HTTP 400.
    Invalid(&'static str),
    /// The response entries and the caller's name, the audience of a JWT
    /// response.
    Response {
        entries: Map<String, Value>,
        caller: String,
    },
}

enum Caller {
    Api(ApiResource),
    Client(Arc<Client>),
}

pub async fn process(
    ctx: &TokenContext<'_>,
    authorization: Option<&str>,
    form: &Form,
) -> Result<Introspection, StoreError> {
    let caller = match authenticate_api(ctx, authorization, form).await? {
        Some(api) => Caller::Api(api),
        None => match authenticate_client(ctx, authorization, form).await? {
            Ok(client) => Caller::Client(client),
            Err(_) => return Ok(Introspection::Unauthorized),
        },
    };
    let caller_name = match &caller {
        Caller::Api(api) => api.name.clone(),
        Caller::Client(client) => client.client_id.clone(),
    };
    let Some(token) = form.get("token") else {
        const MISSING: &str = "missing_token";
        ctx.events.raise(
            ctx.request,
            ctx.now,
            Event::token_introspection_failure(
                MISSING,
                EventDetails::TokenIntrospectionFailure {
                    api_name: caller_name.clone(),
                    token: None,
                    api_scopes: None,
                    token_scopes: None,
                },
            ),
        );
        telemetry::introspection_failure(&caller_name, MISSING);
        return Ok(Introspection::Invalid(MISSING));
    };
    // An unsupported hint is discarded.
    let hint = form
        .get("token_type_hint")
        .filter(|h| SUPPORTED_TOKEN_TYPE_HINTS.contains(&h.as_str()));
    let claims = validate_request(ctx, &caller, &token, hint.as_deref())
        .instrument(tracing::info_span!(
            "IntrospectionRequestValidator.Validate"
        ))
        .await?;
    let entries = {
        let _span = tracing::info_span!("introspection.respond").entered();
        generate(ctx, &caller, &caller_name, &token, claims)
    };
    Ok(Introspection::Response {
        entries,
        caller: caller_name,
    })
}

/// The token's claims when it is active for
/// this caller. APIs see access tokens only. Clients see their own access
/// and refresh tokens: the hint picks which is tried first, and the other
/// is tried when that fails, as RFC 7662 asks.
async fn validate_request(
    ctx: &TokenContext<'_>,
    caller: &Caller,
    token: &str,
    hint: Option<&str>,
) -> Result<Option<Vec<Claim>>, StoreError> {
    match caller {
        Caller::Api(_) => access_token_claims(ctx, None, token).await,
        Caller::Client(client) => {
            if hint == Some("refresh_token") {
                match refresh_token_claims(ctx, client, token).await? {
                    Some(claims) => Ok(Some(claims)),
                    None => access_token_claims(ctx, Some(client), token).await,
                }
            } else {
                match access_token_claims(ctx, Some(client), token).await? {
                    Some(claims) => Ok(Some(claims)),
                    None => refresh_token_claims(ctx, client, token).await,
                }
            }
        }
    }
}

/// An active access token's claims; a
/// client sees only tokens issued to it, marked `token_type`.
async fn access_token_claims(
    ctx: &TokenContext<'_>,
    client: Option<&Client>,
    token: &str,
) -> Result<Option<Vec<Claim>>, StoreError> {
    let validation = ValidationContext {
        options: ctx.options,
        stores: ctx.stores,
        keys: ctx.keys,
        issuer: ctx.issuer,
        now: ctx.now,
    };
    let Ok(validated) = access_tokens::validate(&validation, token).await? else {
        return Ok(None);
    };
    let Some(client) = client else {
        return Ok(Some(validated.claims));
    };
    let mut ids = validated
        .claims
        .iter()
        .filter(|c| c.claim_type == "client_id");
    let owner = ids.next().map(|c| c.value.as_str());
    if ids.next().is_some() || owner != Some(client.client_id.as_str()) {
        return Ok(None);
    }
    let mut claims = validated.claims;
    claims.push(Claim::string("token_type", "access_token"));
    Ok(Some(claims))
}

/// A valid refresh token of this client as
/// `client_id`, `token_type`, `iat`, `exp`, `sub` and its scopes.
async fn refresh_token_claims(
    ctx: &TokenContext<'_>,
    client: &Client,
    handle: &str,
) -> Result<Option<Vec<Claim>>, StoreError> {
    let Some(token) = refresh_tokens::validate(ctx.stores, client, handle, ctx.now).await? else {
        return Ok(None);
    };
    if !crate::server_side_sessions::validate_session(
        &ctx.validation(),
        client,
        &token.subject.subject_id,
        token.session_id.as_deref(),
    )
    .await?
    {
        return Ok(None);
    }
    let iat = token.creation_time.timestamp();
    let integer = |name: &str, value: i64| Claim {
        claim_type: name.to_owned(),
        value: value.to_string(),
        value_type: crate::tokens::CLAIM_VALUE_INTEGER.to_owned(),
    };
    let mut claims = vec![
        Claim::string("client_id", &client.client_id),
        Claim::string("token_type", "refresh_token"),
        integer("iat", iat),
        integer("exp", iat + token.lifetime),
        Claim::string("sub", &token.subject.subject_id),
    ];
    claims.extend(
        token
            .authorized_scopes
            .iter()
            .map(|s| Claim::string("scope", s)),
    );
    Ok(Some(claims))
}

/// The response entries, raising the
/// introspection events and recording `tokenservice.introspection`.
fn generate(
    ctx: &TokenContext<'_>,
    caller: &Caller,
    caller_name: &str,
    token: &str,
    claims: Option<Vec<Claim>>,
) -> Map<String, Value> {
    let (api_name, client_name) = match caller {
        Caller::Api(api) => (Some(api.name.clone()), None),
        Caller::Client(client) => (None, client.client_name.clone()),
    };
    let success = |active: bool, claims: Option<&[Claim]>| {
        telemetry::introspection(caller_name, active);
        let mut claim_types: Vec<String> = Vec::new();
        for claim in claims.unwrap_or_default() {
            if !claim_types.contains(&claim.claim_type) {
                claim_types.push(claim.claim_type.clone());
            }
        }
        ctx.events.raise(
            ctx.request,
            ctx.now,
            Event::token_introspection_success(EventDetails::TokenIntrospectionSuccess {
                api_name: api_name.clone(),
                client_name: client_name.clone(),
                is_active: active,
                token: Some(obfuscate(token)),
                claim_types: claims.map(|_| claim_types),
                token_scopes: claims.map(|c| scopes(c).map(str::to_owned).collect()),
            }),
        );
    };
    let Some(claims) = claims else {
        success(false, None);
        return inactive();
    };
    let token_scopes: Vec<&str> = scopes(&claims).collect();
    let visible: Vec<&str> = match caller {
        // An API sees the token only when it carries one of the API's
        // scopes, and only those scopes.
        Caller::Api(api) => {
            let visible: Vec<&str> = token_scopes
                .iter()
                .copied()
                .filter(|s| api.scopes.iter().any(|a| a == s))
                .collect();
            if visible.is_empty() {
                const MISSING: &str = "Expected scopes are missing";
                telemetry::introspection_failure(caller_name, MISSING);
                ctx.events.raise(
                    ctx.request,
                    ctx.now,
                    Event::token_introspection_failure(
                        MISSING,
                        EventDetails::TokenIntrospectionFailure {
                            api_name: api.name.clone(),
                            token: Some(obfuscate(token)),
                            api_scopes: Some(api.scopes.clone()),
                            token_scopes: Some(
                                token_scopes.iter().map(|s| (*s).to_owned()).collect(),
                            ),
                        },
                    ),
                );
                return inactive();
            }
            visible
        }
        Caller::Client(_) => token_scopes,
    };
    success(true, Some(&claims));
    active(&claims, &visible)
}

fn inactive() -> Map<String, Value> {
    let mut entries = Map::new();
    entries.insert("active".into(), Value::Bool(false));
    entries
}

fn scopes(claims: &[Claim]) -> impl Iterator<Item = &str> {
    claims
        .iter()
        .filter(|c| c.claim_type == "scope")
        .map(|c| c.value.as_str())
}

fn active(claims: &[Claim], scopes: &[&str]) -> Map<String, Value> {
    let without_scope: Vec<Claim> = claims
        .iter()
        .filter(|c| c.claim_type != "scope")
        .cloned()
        .collect();
    let mut entries = to_dictionary(&without_scope);
    entries.insert("active".into(), Value::Bool(true));
    entries.insert("scope".into(), Value::String(scopes.join(" ")));
    entries
}

/// The `typ` of a JWT introspection response (RFC 9701).
pub const JWT_RESPONSE_TYPE: &str = "token-introspection+jwt";

/// The introspection http writer for `Accept: application/token-introspection+jwt`:
/// The entries signed as a JWT with `iss`, `iat`, `aud` (the caller) and
/// `token_introspection`.
pub async fn jwt_response(
    ctx: &TokenContext<'_>,
    entries: &Map<String, Value>,
    caller: &str,
) -> Result<String, String> {
    let key = ctx
        .keys
        .signing_key(&[])
        .await
        .map_err(|e| e.to_string())?
        .ok_or("no signing key is configured")?;
    let mut payload = Map::new();
    payload.insert("iss".into(), Value::String(ctx.issuer.to_owned()));
    payload.insert("iat".into(), Value::from(ctx.now.timestamp()));
    payload.insert("aud".into(), Value::String(caller.to_owned()));
    payload.insert("token_introspection".into(), Value::Object(entries.clone()));
    crate::jwt::encode(&key, &[("typ", JWT_RESPONSE_TYPE)], &payload).map_err(|e| e.to_string())
}
