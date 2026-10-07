//! The token endpoint's protocol logic: client authentication, request
//! validation and token issuance, without HTTP types.
//!
//! The client credentials grant issues JWT or reference access tokens. Other grants return
//! `unsupported_grant_type` with a description saying so, after the
//! client-permission check performed first; later phases replace these.

use chrono::{DateTime, Utc};

use crate::authorize::code::{AUTHORIZATION_CODE, AuthorizationCode, sha256_base64};
use crate::client_auth::authenticate;
use crate::clients::{AccessTokenType, Client};
use crate::dpop;
use crate::events::{Event, EventDetails, EventService, IssuedToken, RequestInfo, obfuscate};
use crate::form::Form;
use crate::grants::hashed_key;
use crate::key_service::KeyService;
use crate::options::InputLengthRestrictions;
use crate::options::ProtocolOptions;
use crate::params::utf16_len;
use crate::reference_tokens::{self, ReferenceToken};
use crate::refresh_tokens::ProofType;
use crate::refresh_tokens::{self, RefreshToken};
use crate::replay::ReplayCache;
use crate::scopes::{
    ResourceValidationError, ValidatedResources, parse_scopes_string, validate_requested_resources,
};
use crate::secrets::constant_time_eq;
use crate::stores::{StoreError, Stores};
use crate::telemetry;
use crate::tokens::{Claim, IdentityTokenRequest, client_access_token, new_jwt_id};
use base64::Engine;

mod ciba;
mod device;
mod grants;

/// Per-request context for the token, introspection and revocation
/// endpoints.
pub struct TokenContext<'a> {
    pub options: &'a ProtocolOptions,
    pub stores: &'a Stores,
    pub keys: &'a KeyService,
    pub replay: &'a dyn ReplayCache,
    pub events: &'a EventService,
    /// Where the request came from, for events.
    pub request: &'a RequestInfo,
    /// `private_key_jwt` client authentication is enabled.
    pub private_key_jwt: bool,
    /// Extension grant types with a registered validator.
    pub extension_grants: &'a [String],
    pub issuer: &'a str,
    /// Origin plus path base, without a trailing slash.
    pub base_url: &'a str,
    /// The request's `DPoP` header values.
    pub dpop_proofs: &'a [&'a str],
    /// The request's TLS client certificate.
    pub client_certificate: Option<&'a crate::client_certificate::ClientCertificate>,
    /// Seals DPoP server nonces.
    pub protector: &'a crate::data_protection::DataProtector,
    pub now: DateTime<Utc>,
}

impl<'a> TokenContext<'a> {
    /// What token validation needs from this context.
    pub fn validation(&self) -> crate::access_tokens::ValidationContext<'a> {
        crate::access_tokens::ValidationContext {
            options: self.options,
            stores: self.stores,
            keys: self.keys,
            issuer: self.issuer,
            now: self.now,
        }
    }
}

impl TokenContext<'_> {
    /// The context as a token issuer.
    pub fn issuer(&self) -> crate::issuance::Issuer<'_> {
        crate::issuance::Issuer {
            options: self.options,
            stores: self.stores,
            keys: self.keys,
            issuer: self.issuer,
            now: self.now,
        }
    }
}

/// An OAuth error response: HTTP 400 with `error`, an optional
/// description, and fields a token request hook adds after them.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenError {
    pub error: std::borrow::Cow<'static, str>,
    pub description: Option<String>,
    pub custom: serde_json::Map<String, serde_json::Value>,
    /// A DPoP server nonce for the `DPoP-Nonce` header.
    pub dpop_nonce: Option<String>,
}

impl TokenError {
    pub fn new(error: &'static str) -> Self {
        TokenError {
            error: error.into(),
            description: None,
            custom: Default::default(),
            dpop_nonce: None,
        }
    }

    fn described(error: &'static str, description: &str) -> Self {
        TokenError {
            error: error.into(),
            description: Some(description.to_owned()),
            custom: Default::default(),
            dpop_nonce: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TokenFailure {
    /// A protocol error returned to the client.
    Protocol(TokenError),
    /// A server-side fault (misconfiguration); HTTP 500.
    Server(String),
}

impl From<StoreError> for TokenFailure {
    fn from(e: StoreError) -> Self {
        TokenFailure::Server(e.to_string())
    }
}

impl From<TokenError> for TokenFailure {
    fn from(e: TokenError) -> Self {
        TokenFailure::Protocol(e)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TokenResponse {
    /// For OpenID authorization code and refresh token requests.
    pub id_token: Option<String>,
    pub access_token: String,
    pub expires_in: i64,
    pub token_type: &'static str,
    /// With `offline_access`, and on every refresh.
    pub refresh_token: Option<String>,
    pub scope: String,
    /// Fields a token request hook adds after the standard ones.
    pub custom: serde_json::Map<String, serde_json::Value>,
}

pub const INVALID_REQUEST: &str = "invalid_request";
pub const INVALID_CLIENT: &str = "invalid_client";
pub const UNAUTHORIZED_CLIENT: &str = "unauthorized_client";
pub const UNSUPPORTED_GRANT_TYPE: &str = "unsupported_grant_type";
pub const INVALID_SCOPE: &str = "invalid_scope";
pub const INVALID_TARGET: &str = "invalid_target";
pub const INVALID_GRANT: &str = "invalid_grant";
pub const INVALID_DPOP_PROOF: &str = "invalid_dpop_proof";

/// A requested resource indicator the grant's authorize request didn't name.
const NOT_ORIGINALLY_REQUESTED: &str =
    "Resource indicator does not match any resource indicator in the original authorize request.";

/// A request that passed validation, by grant.
#[derive(Debug)]
enum Validated {
    ClientCredentials(ValidatedResources),
    /// With the requested resource indicator, for the refresh token.
    AuthorizationCode(Box<AuthorizationCode>, ValidatedResources, Option<String>),
    RefreshToken {
        token: Box<RefreshToken>,
        handle: String,
        resources: ValidatedResources,
        /// The requested resource indicator: which access token to reissue.
        resource: Option<String>,
    },
    /// A completed backchannel authentication request, with the requested
    /// resource indicator.
    Ciba(
        Box<crate::ciba::CibaRequest>,
        ValidatedResources,
        Option<String>,
    ),
    /// An approved device authorization.
    DeviceCode(Box<crate::device_flow::DeviceCode>, ValidatedResources),
    /// The password grant or an extension grant.
    Grant {
        /// `None`: an extension grant without a user.
        subject: Option<Box<crate::session::UserSession>>,
        resources: ValidatedResources,
        /// The validator's custom response parameters.
        custom: serde_json::Map<String, serde_json::Value>,
        changes: crate::grant_validation::RequestChanges,
        resource: Option<String>,
    },
}

/// Handles a token request whose body has already been parsed, raising the
/// token issued events and recording `tokenservice.token_issued`.
pub async fn process(
    ctx: &TokenContext<'_>,
    authorization: Option<&str>,
    form: &Form,
) -> Result<TokenResponse, TokenFailure> {
    let (client, confirmation) = match authenticate(ctx, authorization, form).await? {
        Ok(authenticated) => (authenticated.client, authenticated.confirmation),
        Err(error) => {
            telemetry::token_issued_failure(None, None, error);
            return Err(TokenError::new(error).into());
        }
    };
    // One DPoP header at most.
    if ctx.dpop_proofs.len() > 1 {
        telemetry::token_issued_failure(Some(&client.client_id), None, INVALID_REQUEST);
        return Err(
            TokenError::described(INVALID_REQUEST, "Too many DPoP headers provided.").into(),
        );
    }
    // The validated request's grant type: the parameter once it passed its
    // length check.
    let grant_type = form
        .get("grant_type")
        .filter(|g| g.len() <= ctx.options.input_length_restrictions.grant_type);
    // Whose code was presented, once validation has loaded it, for the
    // failure event.
    let mut subject_id = None;
    let (validated, proof) =
        match validate_request(ctx, &client, confirmation, form, &mut subject_id).await {
            Ok(validated) => validated,
            // A nonce challenge is the normal DPoP flow, not a failure event.
            Err(TokenFailure::Protocol(error)) if error.error == dpop::USE_DPOP_NONCE => {
                tracing::debug!("Token request returned an error with a server issued nonce");
                telemetry::token_issued_failure(
                    Some(&client.client_id),
                    grant_type.as_deref(),
                    &error.error,
                );
                return Err(TokenFailure::Protocol(error));
            }
            Err(TokenFailure::Protocol(error)) => {
                ctx.events.raise(
                    ctx.request,
                    ctx.now,
                    Event::token_issued_failure(EventDetails::TokenIssuedFailure {
                        client_id: Some(client.client_id.clone()),
                        client_name: client.client_name.clone(),
                        endpoint: "Token",
                        redirect_uri: None,
                        subject_id: subject_id.clone(),
                        // Requested scopes are only set by grants that take a
                        // scope parameter.
                        scopes: (grant_type.as_deref() != Some("authorization_code"))
                            .then(|| form.get("scope"))
                            .flatten(),
                        grant_type: grant_type.clone(),
                        error: error.error.to_string(),
                        error_description: error.description.clone(),
                    }),
                );
                telemetry::token_issued_failure(
                    Some(&client.client_id),
                    grant_type.as_deref(),
                    &error.error,
                );
                return Err(TokenFailure::Protocol(error));
            }
            Err(server) => return Err(server),
        };
    // The custom validator, after the standard one.
    let custom =
        match custom_validation(ctx, &client, form, grant_type.as_deref(), &validated).await? {
            Ok(custom) => custom,
            Err(error) => {
                ctx.events.raise(
                    ctx.request,
                    ctx.now,
                    Event::token_issued_failure(EventDetails::TokenIssuedFailure {
                        client_id: Some(client.client_id.clone()),
                        client_name: client.client_name.clone(),
                        endpoint: "Token",
                        redirect_uri: None,
                        subject_id: subject_id.clone(),
                        scopes: (grant_type.as_deref() != Some("authorization_code"))
                            .then(|| form.get("scope"))
                            .flatten(),
                        grant_type: grant_type.clone(),
                        error: error.error.to_string(),
                        error_description: error.description.clone(),
                    }),
                );
                telemetry::token_issued_failure(
                    Some(&client.client_id),
                    grant_type.as_deref(),
                    &error.error,
                );
                return Err(TokenFailure::Protocol(error));
            }
        };
    let (response, subject_id, event_scopes) = match validated {
        Validated::ClientCredentials(resources) => {
            let response = issue(ctx, &client, &resources, None, &proof).await?;
            let scopes = response.scope.clone();
            (response, None, scopes)
        }
        Validated::AuthorizationCode(code, resources, resource) => (
            issue_for_code(ctx, &client, &code, &resources, resource.as_deref(), &proof).await?,
            Some(code.subject.subject_id.clone()),
            code.requested_scopes.join(" "),
        ),
        Validated::Ciba(request, resources, resource) => {
            let response = ciba::issue_for_ciba(
                ctx,
                &client,
                &request,
                &resources,
                resource.as_deref(),
                &proof,
            )
            .await?;
            let scopes = response.scope.clone();
            (response, Some(request.subject.subject_id.clone()), scopes)
        }
        Validated::DeviceCode(code, resources) => {
            let response =
                device::issue_for_device(ctx, &client, &code, &resources, &proof).await?;
            let scopes = response.scope.clone();
            (
                response,
                code.subject.as_ref().map(|s| s.subject_id.clone()),
                scopes,
            )
        }
        Validated::RefreshToken {
            mut token,
            handle,
            resources,
            resource,
        } => {
            let subject = token.subject.subject_id.clone();
            let scopes = token.authorized_scopes.join(" ");
            (
                issue_for_refresh(
                    ctx,
                    &client,
                    &mut token,
                    &handle,
                    &resources,
                    resource.as_deref(),
                    &proof,
                )
                .await?,
                Some(subject),
                scopes,
            )
        }
        Validated::Grant {
            subject,
            resources,
            custom: grant_custom,
            changes,
            resource,
        } => {
            let mut response = grants::issue_for_grant(
                ctx,
                &client,
                subject.as_deref(),
                &resources,
                &changes,
                resource.as_deref(),
                &proof,
            )
            .await?;
            response.custom = grant_custom;
            let scopes = response.scope.clone();
            (response, subject.map(|s| s.subject_id.clone()), scopes)
        }
    };
    // The validator's custom parameters, then the custom token request
    // validator's on top.
    let mut response = response;
    response.custom.extend(custom);
    if proof.proof_type == ProofType::DPoP {
        response.token_type = dpop::TOKEN_TYPE;
    }
    let grant_type = grant_type.unwrap_or_default();
    // The token issued success event lists the identity token first.
    let mut tokens = Vec::new();
    if let Some(id_token) = &response.id_token {
        tokens.push(IssuedToken {
            token_type: "id_token",
            token_value: obfuscate(id_token),
        });
    }
    if let Some(refresh_token) = &response.refresh_token {
        tokens.push(IssuedToken {
            token_type: "refresh_token",
            token_value: obfuscate(refresh_token),
        });
    }
    tokens.push(IssuedToken {
        token_type: "access_token",
        token_value: obfuscate(&response.access_token),
    });
    ctx.events.raise(
        ctx.request,
        ctx.now,
        Event::token_issued_success(EventDetails::TokenIssuedSuccess {
            client_id: client.client_id.clone(),
            client_name: client.client_name.clone(),
            redirect_uri: None,
            endpoint: "Token",
            subject_id,
            scopes: event_scopes,
            grant_type: grant_type.clone(),
            tokens,
        }),
    );
    telemetry::token_issued(&telemetry::TokenIssued {
        client: &client.client_id,
        grant_type: &grant_type,
        access_token_issued: true,
        access_token_type: Some(match client.access_token_type {
            AccessTokenType::Jwt => "Jwt",
            AccessTokenType::Reference => "Reference",
        }),
        refresh_token_issued: response.refresh_token.is_some(),
        proof_type: match proof.proof_type {
            ProofType::DPoP => "DPoP",
            ProofType::ClientCertificate => "ClientCertificate",
            ProofType::None => "None",
        },
        id_token_issued: response.id_token.is_some(),
    });
    Ok(response)
}

/// Asks the custom token request validator about a validated request:
/// The custom fields to add, or the error refusing it.
async fn custom_validation(
    ctx: &TokenContext<'_>,
    client: &Client,
    form: &Form,
    grant_type: Option<&str>,
    validated: &Validated,
) -> Result<Result<serde_json::Map<String, serde_json::Value>, TokenError>, TokenFailure> {
    let (subject_id, scopes) = match validated {
        Validated::ClientCredentials(resources) => (None, &resources.scopes),
        Validated::AuthorizationCode(code, resources, _) => {
            (Some(code.subject.subject_id.as_str()), &resources.scopes)
        }
        Validated::DeviceCode(code, resources) => (
            code.subject.as_ref().map(|s| s.subject_id.as_str()),
            &resources.scopes,
        ),
        Validated::Ciba(request, resources, _) => {
            (Some(request.subject.subject_id.as_str()), &resources.scopes)
        }
        Validated::RefreshToken {
            token, resources, ..
        } => (Some(token.subject.subject_id.as_str()), &resources.scopes),
        Validated::Grant {
            subject, resources, ..
        } => (
            subject.as_ref().map(|s| s.subject_id.as_str()),
            &resources.scopes,
        ),
    };
    let parameters: Vec<(String, String)> = form
        .pairs()
        .filter(|(k, _)| !crate::token_request::WITHHELD_PARAMETERS.contains(k))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    let verdict = ctx
        .stores
        .token_request
        .validate(&crate::token_request::TokenRequest {
            grant_type: grant_type.unwrap_or_default(),
            client,
            subject_id,
            scopes,
            parameters: &parameters,
        })
        .await
        .map_err(|e| TokenFailure::Server(e.to_string()))?;
    Ok(match verdict {
        crate::token_request::TokenRequestVerdict::Accept { custom } => Ok(custom),
        crate::token_request::TokenRequestVerdict::Reject {
            error,
            description,
            custom,
        } => Err(TokenError {
            error: error.into(),
            description,
            custom,
            dpop_nonce: None,
        }),
    })
}

/// The token request's resource indicator (RFC 8707): one at most,
/// within the length limit, an absolute URI without a fragment. An empty
/// value is none.
pub fn requested_resource_indicator(
    form: &Form,
    limits: &crate::options::InputLengthRestrictions,
) -> Result<Option<String>, TokenError> {
    let values: Vec<&str> = form.values("resource").filter(|v| !v.is_empty()).collect();
    let invalid = |description: &'static str| TokenError::described(INVALID_TARGET, description);
    if values
        .iter()
        .any(|v| crate::params::utf16_len(v) > limits.resource_indicator_max_length)
    {
        return Err(invalid("Resource indicator maximum length exceeded"));
    }
    if values
        .iter()
        .any(|v| !crate::authorize::validation::is_uri(v) || v.contains('#'))
    {
        return Err(invalid("Invalid resource indicator format"));
    }
    if values.len() > 1 {
        return Err(invalid(
            "Multiple resource indicators not supported on token endpoint.",
        ));
    }
    Ok(values.first().map(|v| (*v).to_owned()))
}

/// Token request validation.
#[tracing::instrument(name = "token.validate_request", skip_all)]
async fn validate_request(
    ctx: &TokenContext<'_>,
    client: &Client,
    confirmation: Option<String>,
    form: &Form,
    subject_id: &mut Option<String>,
) -> Result<(Validated, RequestProof), TokenFailure> {
    let limits = &ctx.options.input_length_restrictions;
    if client.protocol_type != "oidc" {
        return Err(TokenError::new(INVALID_CLIENT).into());
    }
    let grant_type = form
        .get("grant_type")
        .ok_or(TokenError::new(UNSUPPORTED_GRANT_TYPE))?;
    if grant_type.len() > limits.grant_type {
        return Err(TokenError::new(UNSUPPORTED_GRANT_TYPE).into());
    }
    let resource = requested_resource_indicator(form, limits)?;
    let proof = validate_proof(ctx, client, confirmation).await?;
    let validated = match grant_type.as_str() {
        "client_credentials" => validate_client_credentials(ctx, client, form, resource.as_deref())
            .await
            .map(Validated::ClientCredentials),
        "authorization_code" => {
            validate_authorization_code(ctx, client, form, subject_id, resource, &proof).await
        }
        "password" => grants::validate_password(ctx, client, form, resource).await,
        crate::device_flow::GRANT_TYPE => {
            device::validate_device_code(ctx, client, form, subject_id, resource.as_deref()).await
        }
        crate::ciba::GRANT_TYPE => {
            ciba::validate_ciba(ctx, client, form, subject_id, resource).await
        }
        "refresh_token" => {
            validate_refresh_token(ctx, client, form, subject_id, resource, &proof).await
        }
        extension => grants::validate_extension(ctx, client, form, extension, resource).await,
    }?;
    Ok((validated, proof))
}

/// How the request proved possession of a key: the proof type, the key's
/// thumbprint and the confirmation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RequestProof {
    pub proof_type: ProofType,
    /// The DPoP key's or the certificate's SHA-256 thumbprint.
    pub thumbprint: Option<String>,
    /// The `cnf` tokens are bound to.
    pub confirmation: Option<String>,
}

/// A client certificate (binding the token when it
/// authenticated the client, always with `always_emit_confirmation_claim`,
/// or when the client requires certificate-bound tokens, which also needs
/// a certificate), then a DPoP proof, which takes precedence; a client that
/// requires DPoP must send one.
async fn validate_proof(
    ctx: &TokenContext<'_>,
    client: &Client,
    confirmation: Option<String>,
) -> Result<RequestProof, TokenFailure> {
    if client.require_certificate_bound_tokens {
        if ctx.client_certificate.is_none() {
            return Err(TokenError::described(
                INVALID_REQUEST,
                "Client requires certificate-bound tokens and no client certificate was presented.",
            )
            .into());
        }
        // A DPoP proof would bind the tokens to its key instead.
        if !ctx.dpop_proofs.is_empty() {
            return Err(TokenError::described(
                INVALID_REQUEST,
                "Client requires certificate-bound tokens; DPoP proofs aren't accepted.",
            )
            .into());
        }
    }
    let mut proof = RequestProof {
        confirmation,
        ..Default::default()
    };
    if let Some(cert) = ctx.client_certificate
        && ctx.dpop_proofs.is_empty()
    {
        let bind = ctx.options.mutual_tls.always_emit_confirmation_claim
            || client.require_certificate_bound_tokens;
        if bind && proof.confirmation.is_none() {
            proof.confirmation = Some(cert.cnf());
        }
        proof.proof_type = ProofType::ClientCertificate;
        proof.thumbprint = Some(cert.x5t_s256.clone());
    }
    let Some(dpop_proof) = ctx.dpop_proofs.first() else {
        if client.require_dpop {
            return Err(TokenError::described(
                INVALID_REQUEST,
                "Client requires DPoP and a DPoP header value was not provided.",
            )
            .into());
        }
        return Ok(proof);
    };
    if crate::params::utf16_len(dpop_proof) > ctx.options.input_length_restrictions.dpop_proof_token
    {
        tracing::error!("DPoP proof token is too long");
        return Err(TokenError::new(INVALID_DPOP_PROOF).into());
    }
    let url = match ctx.client_certificate {
        Some(_) => crate::client_certificate::mtls_endpoint(
            &ctx.options.mutual_tls,
            ctx.base_url,
            "connect/token",
        ),
        None => format!("{}/connect/token", ctx.base_url),
    };
    let valid = dpop::validate(&dpop::ProofRequest {
        proof: dpop_proof,
        method: "POST",
        url: &url,
        mode: client.dpop_validation_mode,
        client_clock_skew: client.dpop_clock_skew.0,
        options: &ctx.options.dpop,
        replay: ctx.replay,
        protector: ctx.protector,
        now: ctx.now.timestamp(),
        access_token: None,
    })
    .await
    .map_err(|e| TokenFailure::Server(format!("the replay cache failed: {e}")))?
    .map_err(|e| {
        tracing::error!(error = e.error, description = ?e.description, "invalid DPoP proof");
        TokenError {
            error: e.error.into(),
            description: e.description.map(str::to_owned),
            custom: Default::default(),
            dpop_nonce: e.nonce,
        }
    })?;
    Ok(RequestProof {
        proof_type: ProofType::DPoP,
        thumbprint: Some(valid.thumbprint),
        confirmation: Some(valid.cnf),
    })
}

/// Validate authorization code request. The code is looked up first and
/// consumed only once it belongs to the client, removed after
/// the client check; the removal is an atomic take, so of two concurrent
/// redemptions only one proceeds.
async fn validate_authorization_code(
    ctx: &TokenContext<'_>,
    client: &Client,
    form: &Form,
    subject_id: &mut Option<String>,
    resource: Option<String>,
    proof: &RequestProof,
) -> Result<Validated, TokenFailure> {
    let invalid_grant = || TokenFailure::Protocol(TokenError::new(INVALID_GRANT));
    if !client.allows_grant("authorization_code") && !client.allows_grant("hybrid") {
        return Err(TokenError::new(UNAUTHORIZED_CLIENT).into());
    }
    let handle = form
        .get("code")
        .filter(|c| !c.trim().is_empty())
        .ok_or_else(invalid_grant)?;
    if utf16_len(&handle) > ctx.options.input_length_restrictions.authorization_code {
        return Err(invalid_grant());
    }
    let key = hashed_key(&handle, AUTHORIZATION_CODE);
    let grant = ctx
        .stores
        .grants
        .get(&key)
        .await?
        .ok_or_else(invalid_grant)?;
    let code: AuthorizationCode = serde_json::from_str(&grant.data).map_err(|_| invalid_grant())?;
    if code.client_id != client.client_id {
        return Err(invalid_grant());
    }
    if let Some(jkt) = &code.dpop_key_thumbprint {
        if proof.proof_type != ProofType::DPoP {
            return Err(TokenError::described(
                INVALID_DPOP_PROOF,
                "DPoP must be used on the token endpoint when a DPoP key thumbprint is used on the authorize endpoint.",
            )
            .into());
        }
        if proof.thumbprint.as_ref() != Some(jkt) {
            return Err(TokenError::described(
                INVALID_DPOP_PROOF,
                "The DPoP proof token used on the token endpoint does not match the original used on the authorize endpoint.",
            )
            .into());
        }
    }
    if ctx.stores.grants.take(&key).await?.is_none() {
        return Err(invalid_grant());
    }
    let expired =
        |seconds: i32| ctx.now > code.creation_time + chrono::Duration::seconds(i64::from(seconds));
    if expired(code.lifetime) || expired(client.authorization_code_lifetime) {
        return Err(invalid_grant());
    }
    *subject_id = Some(code.subject.subject_id.clone());
    let Some(redirect_uri) = form.get("redirect_uri").filter(|r| !r.trim().is_empty()) else {
        return Err(TokenError::new(UNAUTHORIZED_CLIENT).into());
    };
    if redirect_uri != code.redirect_uri {
        return Err(invalid_grant());
    }
    if code.requested_scopes.is_empty() {
        return Err(TokenError::new(INVALID_REQUEST).into());
    }
    if let Some(requested) = &resource
        && !code.requested_resource_indicators.is_empty()
        && !code.requested_resource_indicators.contains(requested)
    {
        return Err(TokenError::described(INVALID_TARGET, NOT_ORIGINALLY_REQUESTED).into());
    }
    let enabled = ctx.stores.resources.get_all_enabled_resources().await?;
    let resources = validate_requested_resources(
        client,
        &enabled,
        &code.requested_scopes,
        &code.requested_resource_indicators,
    )
    .map_err(|e| match e {
        ResourceValidationError::InvalidResourceIndicator(_) => {
            TokenError::described(INVALID_TARGET, "Invalid resource indicator.")
        }
        ResourceValidationError::InvalidScope(_) => {
            TokenError::described(INVALID_SCOPE, "Invalid scope.")
        }
    })?
    .filter_by_resource_indicator(resource.as_deref());
    let verifier = form.get("code_verifier").filter(|v| !v.trim().is_empty());
    if client.require_pkce || code.code_challenge.is_some() {
        if !pkce_matches(verifier.as_deref(), &code) {
            return Err(invalid_grant());
        }
    } else if verifier.is_some() {
        return Err(invalid_grant());
    }
    let active = ctx
        .stores
        .profile
        .is_active(&crate::profile::ActiveRequest {
            caller: crate::profile::active_callers::AUTHORIZATION_CODE,
            client,
            subject_id: &code.subject.subject_id,
            subject_claims: &code.subject.claims,
        })
        .await
        .map_err(|e| TokenFailure::Server(e.to_string()))?;
    if !active {
        tracing::error!(subject_id = %code.subject.subject_id, "User has been disabled");
        return Err(invalid_grant());
    }
    Ok(Validated::AuthorizationCode(
        Box::new(code),
        resources,
        resource,
    ))
}

/// The verifier is
/// present, 43 to 128 characters, and transforms to the stored challenge
/// (compared, as stored, as base64 SHA-256 in constant time).
fn pkce_matches(verifier: Option<&str>, code: &AuthorizationCode) -> bool {
    let (Some(challenge), Some(method)) = (&code.code_challenge, &code.code_challenge_method)
    else {
        return false;
    };
    let Some(verifier) = verifier else {
        return false;
    };
    let len = utf16_len(verifier);
    if !(InputLengthRestrictions::CODE_VERIFIER_MIN_LENGTH
        ..=InputLengthRestrictions::CODE_VERIFIER_MAX_LENGTH)
        .contains(&len)
    {
        return false;
    }
    let transformed = match method.as_str() {
        "plain" => verifier.to_owned(),
        "S256" => {
            let ascii: Vec<u8> = verifier
                .chars()
                .map(|c| if c.is_ascii() { c as u8 } else { b'?' })
                .collect();
            let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &ascii);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_ref())
        }
        _ => return false,
    };
    constant_time_eq(sha256_base64(&transformed).as_bytes(), challenge.as_bytes())
}

async fn validate_client_credentials(
    ctx: &TokenContext<'_>,
    client: &Client,
    form: &Form,
    resource: Option<&str>,
) -> Result<ValidatedResources, TokenFailure> {
    if !client.allows_grant("client_credentials") {
        return Err(TokenError::new(UNAUTHORIZED_CLIENT).into());
    }
    let enabled = ctx.stores.resources.get_all_enabled_resources().await?;
    let scopes = match form.get("scope") {
        Some(scopes) => scopes,
        None => {
            // No scope parameter: every allowed API scope (identity scopes
            // and offline_access are never implied for this grant).
            if client.allowed_scopes.is_empty() {
                return Err(TokenError::new(INVALID_SCOPE).into());
            }
            let mut defaults: Vec<&str> = Vec::new();
            for scope in enabled
                .api_scopes
                .iter()
                .filter(|s| client.allowed_scopes.contains(&s.name))
            {
                if !defaults.contains(&scope.name.as_str()) {
                    defaults.push(&scope.name);
                }
            }
            defaults.join(" ")
        }
    };
    if scopes.len() > ctx.options.input_length_restrictions.scope {
        return Err(TokenError::new(INVALID_SCOPE).into());
    }
    let requested = parse_scopes_string(&scopes).ok_or(TokenError::new(INVALID_SCOPE))?;
    let indicators: Vec<String> = resource.iter().map(|r| (*r).to_owned()).collect();
    let resources = validate_requested_resources(client, &enabled, &requested, &indicators)
        .map_err(|e| match e {
            ResourceValidationError::InvalidResourceIndicator(_) => TokenError::new(INVALID_TARGET),
            ResourceValidationError::InvalidScope(_) => TokenError::new(INVALID_SCOPE),
        })?;
    if !resources.identity_resources.is_empty() || resources.offline_access {
        return Err(TokenError::new(INVALID_SCOPE).into());
    }
    Ok(resources.filter_by_resource_indicator(resource))
}

/// The token response generator for client credentials.
#[tracing::instrument(name = "token.respond", skip_all)]
/// `owner`, when set, is the client the token belongs to if not `client`
/// (an impersonating extension grant's requester); `cnf` binds it to a
/// proof key.
async fn issue(
    ctx: &TokenContext<'_>,
    client: &Client,
    resources: &ValidatedResources,
    owner: Option<&str>,
    proof: &RequestProof,
) -> Result<TokenResponse, TokenFailure> {
    let mut token = client_access_token(ctx.options, ctx.issuer, client, resources);
    if let Some(owner) = owner {
        token.client_id = owner.to_owned();
    }
    token.confirmation.clone_from(&proof.confirmation);
    // Computed for both token types: the request fails when the API
    // resources share no signing algorithm even if nothing is signed.
    let allowed = resources
        .allowed_signing_algorithms()
        .map_err(|e| TokenFailure::Server(e.to_string()))?;
    let jti = client.include_jwt_id.then(new_jwt_id);
    let access_token = if client.access_token_type == AccessTokenType::Reference {
        let mut claims = token.claims;
        if let Some(jti) = jti {
            claims.push(Claim::string("jti", &jti));
        }
        reference_tokens::store(
            ctx.stores.grants.as_ref(),
            &ReferenceToken {
                issuer: token.issuer,
                client_id: token.client_id,
                audiences: token.audiences,
                creation_time: ctx.now,
                lifetime: token.lifetime,
                claims,
                confirmation: token.confirmation.clone(),
                subject_id: None,
                session_id: None,
                description: None,
            },
        )
        .await?
    } else {
        ctx.issuer()
            .sign_access_token(&token, &allowed, jti.as_deref())
            .await?
    };
    Ok(TokenResponse {
        id_token: None,
        access_token,
        expires_in: i64::from(client.access_token_lifetime),
        token_type: "Bearer",
        refresh_token: None,
        scope: resources.scopes.join(" "),
        custom: Default::default(),
    })
}

/// The
/// access token, an identity token for OpenID codes, and a refresh token
/// when `offline_access` was granted.
async fn issue_for_code(
    ctx: &TokenContext<'_>,
    client: &Client,
    code: &AuthorizationCode,
    resources: &ValidatedResources,
    resource: Option<&str>,
    proof: &RequestProof,
) -> Result<TokenResponse, TokenFailure> {
    let issuer = ctx.issuer();
    let session_id = Some(code.session_id.as_str()).filter(|s| !s.is_empty());
    let mut record = issuer
        .user_access_token_record(client, resources, &code.subject, session_id)
        .await?;
    record.token.confirmation.clone_from(&proof.confirmation);
    let access_token = issuer
        .serialize_access_token(
            client,
            resources,
            &record,
            &code.subject.subject_id,
            session_id,
            code.description.as_deref(),
        )
        .await?;
    let refresh_token = if resources.offline_access {
        let mut token = RefreshToken {
            client_id: client.client_id.clone(),
            subject: code.subject.clone(),
            session_id: session_id.map(str::to_owned),
            description: code.description.clone(),
            authorized_scopes: code.requested_scopes.clone(),
            // The authorize request's list, even an empty one: a later
            // refresh can't name a resource it didn't.
            authorized_resource_indicators: Some(code.requested_resource_indicators.clone()),
            access_token: None,
            resource_access_tokens: Default::default(),
            creation_time: ctx.now,
            lifetime: refresh_tokens::initial_lifetime(client),
            consumed_time: None,
            proof_type: Some(proof.proof_type),
        };
        token.set_access_token(record, resource);
        Some(refresh_tokens::create(ctx.stores.grants.as_ref(), &token).await?)
    } else {
        None
    };
    let id_token = if code.is_open_id {
        let request = IdentityTokenRequest {
            subject: None,
            nonce: code.nonce.as_deref(),
            access_token: Some(&access_token),
            authorization_code: None,
            state_hash: code.state_hash.as_deref(),
            session_id,
            include_all_identity_claims: false,
        };
        Some(
            issuer
                .identity_token(client, resources, &code.subject, &request)
                .await?,
        )
    } else {
        None
    };
    Ok(TokenResponse {
        id_token,
        access_token,
        expires_in: i64::from(client.access_token_lifetime),
        token_type: "Bearer",
        refresh_token,
        scope: resources.scopes.join(" "),
        custom: Default::default(),
    })
}

/// Validate refresh token request with the refresh token service's
/// Validate refresh token, then the authorized scopes validated again.
/// The `scope` parameter is ignored.
async fn validate_refresh_token(
    ctx: &TokenContext<'_>,
    client: &Client,
    form: &Form,
    subject_id: &mut Option<String>,
    resource: Option<String>,
    proof: &RequestProof,
) -> Result<Validated, TokenFailure> {
    let invalid_grant = || TokenFailure::Protocol(TokenError::new(INVALID_GRANT));
    let handle = form
        .get("refresh_token")
        .filter(|t| !t.trim().is_empty())
        .ok_or(TokenError::new(INVALID_REQUEST))?;
    if handle.len() > ctx.options.input_length_restrictions.refresh_token {
        return Err(invalid_grant());
    }
    let token = refresh_tokens::validate(ctx.stores, client, &handle, ctx.now)
        .await?
        .ok_or_else(invalid_grant)?;
    // A coordinated client's token
    // needs its user's session.
    if !crate::server_side_sessions::validate_session(
        &ctx.validation(),
        client,
        &token.subject.subject_id,
        token.session_id.as_deref(),
    )
    .await?
    {
        return Err(invalid_grant());
    }
    *subject_id = Some(token.subject.subject_id.clone());
    check_refresh_proof(client, &token, proof)?;
    let enabled = ctx.stores.resources.get_all_enabled_resources().await?;
    // Within the authorize request's indicators when it named any; else the
    // requested one alone.
    let indicators = match &token.authorized_resource_indicators {
        Some(authorized) => {
            if let Some(requested) = &resource
                && !authorized.contains(requested)
            {
                return Err(TokenError::described(INVALID_TARGET, NOT_ORIGINALLY_REQUESTED).into());
            }
            authorized.clone()
        }
        None => resource.iter().cloned().collect(),
    };
    let resources =
        validate_requested_resources(client, &enabled, &token.authorized_scopes, &indicators)
            .map_err(|e| match e {
                ResourceValidationError::InvalidResourceIndicator(_) => {
                    TokenError::described(INVALID_TARGET, "Invalid resource indicator.")
                }
                ResourceValidationError::InvalidScope(_) => {
                    TokenError::described(INVALID_SCOPE, "Invalid scope.")
                }
            })?
            .filter_by_resource_indicator(resource.as_deref());
    Ok(Validated::RefreshToken {
        token: Box::new(token),
        handle,
        resources,
        resource,
    })
}

/// The refresh token's proof of possession rules: a token issued with a
/// proof needs one of the same kind; one issued without can't start using
/// one; a public client must keep its key (a confidential client may
/// present a new one).
fn check_refresh_proof(
    client: &Client,
    token: &RefreshToken,
    proof: &RequestProof,
) -> Result<(), TokenError> {
    let invalid = |description| TokenError::described(INVALID_REQUEST, description);
    let prior = token.effective_proof_type();
    let current = proof.proof_type;
    if prior != ProofType::None && current == ProofType::None {
        return Err(invalid(
            "Proof of possession was used to obtain the initial refresh token and is required for subsequent token requests.",
        ));
    }
    if prior == ProofType::None && current != ProofType::None {
        return Err(invalid(
            "Proof of possession can't be used on subsequent token requests unless used when requesting the initial refresh token.",
        ));
    }
    if prior != current {
        return Err(invalid(
            "Different proof of possession styles can't be mixed.",
        ));
    }
    // Public clients must use the same proof as before; confidential
    // clients may present a new one. (A record whose tokens carry no
    // thumbprint, as an ephemeral certificate leaves, has nothing to keep.)
    if prior != ProofType::None
        && !client.require_client_secret
        && let Some(original) = token.proof_thumbprints().first()
        && proof.thumbprint.as_ref() != Some(original)
    {
        return Err(match current {
            ProofType::ClientCertificate => invalid(
                "The client certificate in the refresh token request does not match the original used.",
            ),
            _ => TokenError::described(
                INVALID_DPOP_PROOF,
                "The DPoP proof token in the refresh token request does not match the original used.",
            ),
        });
    }
    Ok(())
}

/// The stored access token reissued (or
/// a new one built from the refresh token's subject when the client
/// updates claims on refresh), an identity token when `openid` was
/// authorized, and the refresh token rotated or kept.
async fn issue_for_refresh(
    ctx: &TokenContext<'_>,
    client: &Client,
    token: &mut RefreshToken,
    handle: &str,
    resources: &ValidatedResources,
    resource: Option<&str>,
    proof: &RequestProof,
) -> Result<TokenResponse, TokenFailure> {
    let issuer = ctx.issuer();
    let session_id = token.session_id.clone();
    // A new access token when claims are refreshed, or when none was
    // issued yet for this resource indicator.
    let stored = token.access_token_for(resource).cloned();
    let mut must_update = client.update_access_token_claims_on_refresh || stored.is_none();
    let record = match stored.filter(|_| !client.update_access_token_claims_on_refresh) {
        Some(mut record) => {
            record.token.lifetime = i64::from(client.access_token_lifetime);
            // Always the current request's confirmation (a confidential
            // client's proof key may have changed).
            if let Some(cnf) = &proof.confirmation
                && record.token.confirmation.as_ref() != Some(cnf)
            {
                record.token.confirmation = Some(cnf.clone());
                must_update = true;
            }
            record
        }
        None => {
            let mut record = issuer
                .user_access_token_record(client, resources, &token.subject, session_id.as_deref())
                .await?;
            record.token.confirmation.clone_from(&proof.confirmation);
            record
        }
    };
    token.set_access_token(record.clone(), resource);
    let access_token = issuer
        .serialize_access_token(
            client,
            resources,
            &record,
            &token.subject.subject_id,
            session_id.as_deref(),
            token.description.as_deref(),
        )
        .await?;
    let refresh_token = refresh_tokens::update(
        ctx.stores.grants.as_ref(),
        &ctx.options.persistent_grants,
        client,
        handle,
        token,
        must_update,
        ctx.now,
    )
    .await?
    .ok_or(TokenError::new(INVALID_GRANT))?;
    let id_token = if token.authorized_scopes.iter().any(|s| s == "openid") {
        let request = IdentityTokenRequest {
            subject: None,
            nonce: None,
            access_token: Some(&access_token),
            authorization_code: None,
            state_hash: None,
            session_id: session_id.as_deref(),
            include_all_identity_claims: false,
        };
        Some(
            issuer
                .identity_token(client, resources, &token.subject, &request)
                .await?,
        )
    } else {
        None
    };
    Ok(TokenResponse {
        id_token,
        access_token,
        expires_in: i64::from(client.access_token_lifetime),
        token_type: "Bearer",
        refresh_token: Some(refresh_token),
        scope: resources.scopes.join(" "),
        custom: Default::default(),
    })
}
