//! Caller authentication shared by the token, introspection and revocation
//! endpoints: the client secret validator and the API secret validator.
//!
//! The outer `Result` carries store failures; the inner one the verdict.

use std::sync::Arc;

use crate::client_assertion::{self, AssertionContext};
use crate::clients::{Client, Secret, validate_client};
use crate::events::Event;
use crate::form::Form;
use crate::resources::ApiResource;
use crate::secrets::{self, ParsedSecret};
use crate::stores::StoreError;
use crate::telemetry;
use crate::token::{INVALID_CLIENT, INVALID_REQUEST, TokenContext};

/// An authenticated client, and the `cnf` its credential binds tokens to
/// (a client certificate's).
#[derive(Debug, Clone)]
pub struct Authenticated {
    pub client: Arc<Client>,
    pub confirmation: Option<String>,
}

/// [`authenticate`], for callers that only need the client.
pub async fn authenticate_client(
    ctx: &TokenContext<'_>,
    authorization: Option<&str>,
    form: &Form,
) -> Result<Result<Arc<Client>, &'static str>, StoreError> {
    Ok(authenticate(ctx, authorization, form)
        .await?
        .map(|authenticated| authenticated.client))
}

/// The client secret validator. The error is the OAuth error code
/// is reported: `invalid_request` when no credentials were found,
/// `invalid_client` otherwise. Raises the client authentication events and
/// records the secret and configuration validation metrics.
#[tracing::instrument(name = "client.authenticate", skip_all)]
pub async fn authenticate(
    ctx: &TokenContext<'_>,
    authorization: Option<&str>,
    form: &Form,
) -> Result<Result<Authenticated, &'static str>, StoreError> {
    let fail = |client_id: &str, message: &str| {
        telemetry::client_secret_validation_failure(client_id, message);
        ctx.events.raise(
            ctx.request,
            ctx.now,
            Event::client_authentication_failure(client_id, message),
        );
    };
    let Some(parsed) = parse(ctx, authorization, form) else {
        fail("unknown", "No client id found");
        return Ok(Err(INVALID_REQUEST));
    };
    // The validating client store wraps the lookup: a missing client counts as a
    // validation failure, any found client (enabled or not) is validated,
    // and find enabled client by id then drops disabled ones.
    let Some(client) = ctx.stores.clients.find_client_by_id(&parsed.id).await? else {
        telemetry::client_validation_failure(&parsed.id, "Client not found");
        fail(&parsed.id, "Unknown client");
        return Ok(Err(INVALID_CLIENT));
    };
    if let Err(problem) = validate_client(
        &client,
        ctx.options
            .pushed_authorization
            .allow_unregistered_pushed_redirect_uris,
    ) {
        tracing::error!(client_id = %client.client_id, %problem, "invalid client configuration");
        telemetry::client_validation_failure(&client.client_id, &problem);
        ctx.events.raise(
            ctx.request,
            ctx.now,
            Event::invalid_client_configuration(
                &client.client_id,
                client.client_name.as_deref(),
                &problem,
            ),
        );
        fail(&parsed.id, "Unknown client");
        return Ok(Err(INVALID_CLIENT));
    }
    telemetry::client_validation(&client.client_id);
    if !client.enabled {
        fail(&parsed.id, "Unknown client");
        return Ok(Err(INVALID_CLIENT));
    }
    let mut confirmation = None;
    if client.require_client_secret && !client.is_implicit_only() {
        match validate_secrets(ctx, &client.client_secrets, &parsed).await? {
            Some(cnf) => confirmation = cnf,
            None => {
                fail(&client.client_id, "Invalid client secret");
                return Ok(Err(INVALID_CLIENT));
            }
        }
    }
    let method = parsed.kind.as_str();
    telemetry::client_secret_validation(&client.client_id, method);
    ctx.events.raise(
        ctx.request,
        ctx.now,
        Event::client_authentication_success(&client.client_id, method),
    );
    Ok(Ok(Authenticated {
        client,
        confirmation,
    }))
}

/// The credentials name exactly one
/// enabled API resource whose secrets accept them. Raises the API
/// authentication events and records `tokenservice.api.secret_validation`.
#[tracing::instrument(name = "api_resource.authenticate", skip_all)]
pub async fn authenticate_api(
    ctx: &TokenContext<'_>,
    authorization: Option<&str>,
    form: &Form,
) -> Result<Option<ApiResource>, StoreError> {
    let fail = |name: &str, message: &str| {
        telemetry::api_secret_validation_failure(name, message);
        ctx.events.raise(
            ctx.request,
            ctx.now,
            Event::api_authentication_failure(name, message),
        );
    };
    let Some(parsed) = parse(ctx, authorization, form) else {
        fail("unknown", "No API id or secret found");
        return Ok(None);
    };
    let named = ctx
        .stores
        .resources
        .find_api_resources_by_name(std::slice::from_ref(&parsed.id))
        .await?;
    let api = match named.as_slice() {
        [] => {
            fail(&parsed.id, "Unknown API resource");
            return Ok(None);
        }
        [api] => api,
        _ => {
            fail(&parsed.id, "Invalid API resource");
            return Ok(None);
        }
    };
    if !api.enabled {
        fail(&parsed.id, "API resource not enabled");
        return Ok(None);
    }
    if validate_secrets(ctx, &api.api_secrets, &parsed)
        .await?
        .is_none()
    {
        fail(&api.name, "Invalid API secret");
        return Ok(None);
    }
    let method = parsed.kind.as_str();
    telemetry::api_secret_validation(&api.name, method);
    ctx.events.raise(
        ctx.request,
        ctx.now,
        Event::api_authentication_success(&api.name, method),
    );
    Ok(Some(api.clone()))
}

/// The first parser that finds a secret; a client id
/// without one (NoSecret) lets the certificate parser, registered last,
/// look for a client certificate.
fn parse(ctx: &TokenContext<'_>, authorization: Option<&str>, form: &Form) -> Option<ParsedSecret> {
    let parsed = secrets::parse(
        authorization,
        form,
        &ctx.options.input_length_restrictions,
        ctx.private_key_jwt,
    );
    if parsed
        .as_ref()
        .is_some_and(|p| p.kind != secrets::ParsedSecretKind::NoSecret)
    {
        return parsed;
    }
    parse_certificate(ctx, form).or(parsed)
}

/// The form's client id, with the request's
/// certificate.
fn parse_certificate(ctx: &TokenContext<'_>, form: &Form) -> Option<ParsedSecret> {
    let id = form.get("client_id").filter(|id| !id.trim().is_empty())?;
    if id.len() > ctx.options.input_length_restrictions.client_id {
        tracing::error!("Client ID exceeds maximum length.");
        return None;
    }
    ctx.client_certificate?;
    Some(ParsedSecret {
        id,
        credential: None,
        kind: secrets::ParsedSecretKind::X509Certificate,
    })
}

/// The x 509 thumbprint secret validator and the X.509 name secret validator: the
/// certificate's `cnf` when a thumbprint secret names it, or a name secret
/// names its subject and its chain is trusted.
fn validate_certificate(ctx: &TokenContext<'_>, secrets: &[&Secret]) -> Option<String> {
    let cert = ctx.client_certificate?;
    if !cert.valid_at(ctx.now) {
        tracing::debug!("the client certificate is outside its validity period");
        return None;
    }
    let by_thumbprint = secrets.iter().any(|s| {
        s.secret_type == crate::clients::SECRET_TYPE_X509_THUMBPRINT
            && s.value.eq_ignore_ascii_case(&cert.thumbprint)
    });
    let by_name = cert.trusted
        && secrets.iter().any(|s| {
            s.secret_type == crate::clients::SECRET_TYPE_X509_NAME && s.value == cert.subject
        });
    (by_thumbprint || by_name).then(|| cert.cnf())
}

/// Unexpired secrets, tried by each registered
/// validator. `Some` on success, with the `cnf` a certificate binds; an
/// error only when the replay store fails.
async fn validate_secrets(
    ctx: &TokenContext<'_>,
    secrets: &[Secret],
    parsed: &ParsedSecret,
) -> Result<Option<Option<String>>, StoreError> {
    let current = secrets::current_secrets(secrets, ctx.now);
    if parsed.kind == secrets::ParsedSecretKind::X509Certificate {
        return Ok(validate_certificate(ctx, &current).map(Some));
    }
    let valid = secrets::validate_shared_secret(&current, parsed)
        || (ctx.private_key_jwt
            && client_assertion::validate(
                &current,
                parsed,
                &AssertionContext {
                    options: ctx.options,
                    issuer: ctx.issuer,
                    base_url: ctx.base_url,
                    replay: ctx.replay,
                    now: ctx.now.timestamp(),
                },
            )
            .await?);
    Ok(valid.then_some(None))
}
