//! Tokens issued at the authorize endpoint: create implicit flow response
//! and create hybrid flow response.

use super::request::ValidatedAuthorizeRequest;
use crate::issuance::Issuer;
use crate::params::Params;
use crate::token::TokenFailure;
use crate::tokens::{IdentityTokenRequest, hash_claim_value};

/// What an implicit or hybrid response carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserTokens {
    pub code: Option<String>,
    pub id_token: Option<String>,
    pub access_token: Option<String>,
    pub expires_in: i64,
    /// The requested scopes, sent with an access token.
    pub scope: String,
}

/// Issues the access token (`token`) and identity token (`id_token`) the
/// response type asks for, for a request with a signed-in user. `code` is
/// the hybrid flow's code, hashed into `c_hash`. The identity token carries
/// every requested identity claim only for `response_type=id_token`.
pub async fn browser_tokens(
    issuer: &Issuer<'_>,
    request: &ValidatedAuthorizeRequest,
    code: Option<&str>,
) -> Result<BrowserTokens, TokenFailure> {
    let client = request
        .client
        .as_deref()
        .expect("validated request has a client");
    let session = request
        .subject
        .as_ref()
        .expect("browser tokens are issued to signed-in users");
    let resources = request.resources.clone().unwrap_or_default();
    let response_types: Vec<&str> = request
        .response_type
        .unwrap_or_default()
        .split(' ')
        .collect();
    let session_id = request.session_id.as_deref().filter(|s| !s.is_empty());
    let access_token = if response_types.contains(&"token") {
        Some(
            issuer
                .user_access_token(client, &resources, session, session_id, None)
                .await?,
        )
    } else {
        None
    };
    let id_token = if response_types.contains(&"id_token") {
        let state_hash = match request.state.as_deref().filter(|s| !s.trim().is_empty()) {
            Some(state) if issuer.options.emit_state_hash => Some(hash_claim_value(
                state,
                &issuer.identity_token_algorithm(client).await?,
            )),
            _ => None,
        };
        let nonce = request.raw.get("nonce");
        let token_request = IdentityTokenRequest {
            nonce: nonce.as_deref().filter(|n| !n.is_empty()),
            access_token: access_token.as_deref(),
            authorization_code: code,
            state_hash: state_hash.as_deref(),
            session_id,
            // An access token is requested by every response type but a
            // bare `id_token`: a code can still be redeemed for one.
            include_all_identity_claims: request.response_type == Some("id_token"),
        };
        Some(
            issuer
                .identity_token(client, &resources, session, &token_request)
                .await?,
        )
    } else {
        None
    };
    Ok(BrowserTokens {
        code: code.map(str::to_owned),
        id_token,
        access_token,
        expires_in: i64::from(client.access_token_lifetime),
        scope: resources.scopes.join(" "),
    })
}

/// The parameters of implicit and hybrid
/// responses: `code`, `id_token`, then `access_token`, `token_type`,
/// `expires_in` and `scope`, then `state` and `session_state`. Nothing sets
/// issuer on these responses, so there is no `iss`.
pub fn browser_response_parameters(
    request: &ValidatedAuthorizeRequest,
    tokens: &BrowserTokens,
) -> Params {
    let mut params = Params::default();
    if let Some(code) = &tokens.code {
        params.add("code", code);
    }
    if let Some(id_token) = &tokens.id_token {
        params.add("id_token", id_token);
    }
    if let Some(access_token) = &tokens.access_token {
        params.add("access_token", access_token);
        params.add("token_type", "Bearer");
        params.add("expires_in", &tokens.expires_in.to_string());
        if !tokens.scope.trim().is_empty() {
            params.add("scope", &tokens.scope);
        }
    }
    if let Some(state) = request.state.as_deref().filter(|s| !s.trim().is_empty()) {
        params.add("state", state);
    }
    if let Some(session_state) = request.session_state_value() {
        params.add("session_state", &session_state);
    }
    params
}
