//! Whether a valid request needs
//! the create-account, login or consent page, an error back to the client,
//! or can be answered straight away.

use chrono::{DateTime, Utc};

use super::request::ValidatedAuthorizeRequest;
use super::validation::AuthorizeContext;
use super::{CONSENT_REQUIRED, INTERACTION_REQUIRED, LOGIN_REQUIRED};
use crate::consent::{self, ConsentResponse, InteractionError};
use crate::profile::{ActiveRequest, active_callers};
use crate::session::LOCAL_IDP;
use crate::stores::{PersistedGrantStore, StoreError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Interaction {
    /// Redirect to `user_interaction.create_account_url`.
    CreateAccount,
    /// Redirect to `user_interaction.login_url`.
    Login,
    /// Redirect to `user_interaction.consent_url`.
    Consent,
    /// Return this error (and description) to the client: `prompt=none`
    /// needed a page, or the consent page refused.
    Error(&'static str, Option<String>),
    /// A prompt value the default interaction service can't act on (a
    /// custom value added to `prompt_values_supported`); that's an unhandled failure, so
    /// the endpoint answers 500.
    UnsupportedPromptMode,
    /// No interaction: issue the response.
    None,
}

/// A refusal made before login goes straight
/// back to the client; otherwise create-account, then login, then consent
/// (applying the consent page's response when there is one), and
/// `prompt=none` turns any page into an error. Processed prompt and
/// `max_age` markers are added to the request's raw parameters, which the
/// return URL carries.
pub async fn process_interaction(
    request: &mut ValidatedAuthorizeRequest,
    ctx: &AuthorizeContext<'_>,
    consent: Option<&ConsentResponse>,
) -> Result<Interaction, StoreError> {
    if let Some(error) = consent.filter(|c| !c.granted()).and_then(|c| c.error) {
        return Ok(Interaction::Error(
            error.error_code(),
            consent.and_then(|c| c.error_description.clone()),
        ));
    }
    let mut result = if request.prompt_modes.iter().any(|p| p == "create") {
        request.remove_prompt();
        Interaction::CreateAccount
    } else if process_login(request, ctx).await? {
        Interaction::Login
    } else {
        process_consent(request, ctx.stores.grants.as_ref(), consent, ctx.now).await?
    };
    if matches!(
        result,
        Interaction::Login | Interaction::Consent | Interaction::CreateAccount
    ) && request.prompt_modes.iter().any(|p| p == "none")
    {
        result = Interaction::Error(
            match result {
                Interaction::Login => LOGIN_REQUIRED,
                Interaction::Consent => CONSENT_REQUIRED,
                _ => INTERACTION_REQUIRED,
            },
            None,
        );
    }
    Ok(result)
}

/// Whether the login page is needed. `prompt=login`,
/// `prompt=select_account` and `max_age=0` force it (and are marked
/// processed); otherwise an anonymous user, a tenant or `idp` other than
/// the session's, an expired `max_age`, a local session for a client
/// without local login, an identity provider the client doesn't allow, or
/// a session older than the client's SSO lifetime.
async fn process_login(
    request: &mut ValidatedAuthorizeRequest,
    ctx: &AuthorizeContext<'_>,
) -> Result<bool, StoreError> {
    let (options, now) = (ctx.options, ctx.now);
    let mut forced = false;
    if request
        .prompt_modes
        .iter()
        .any(|p| p == "login" || p == "select_account")
    {
        request.remove_prompt();
        forced = true;
    }
    if request.max_age == Some(0) {
        request.remove_max_age();
        forced = true;
    }
    if forced {
        return Ok(true);
    }
    let Some(session) = &request.subject else {
        return Ok(true);
    };
    let client = request
        .client
        .as_ref()
        .expect("validated request has a client");
    let active = ctx
        .stores
        .profile
        .is_active(&ActiveRequest {
            caller: active_callers::AUTHORIZE_ENDPOINT,
            client,
            subject_id: &session.subject_id,
            subject_claims: &session.claims,
        })
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    if !active {
        return Ok(true);
    }
    if options.validate_tenant_on_authorization
        && let Some(tenant) = request.tenant()
        && Some(tenant) != session.claim("tenant")
    {
        return Ok(true);
    }
    if let Some(idp) = request.idp()
        && idp != session.idp
    {
        return Ok(true);
    }
    if let Some(max_age) = request.max_age
        && now.timestamp() > session.auth_time.saturating_add(i64::from(max_age))
    {
        return Ok(true);
    }
    if session.idp == LOCAL_IDP {
        if !client.enable_local_login {
            return Ok(true);
        }
    } else if !client.identity_provider_restrictions.is_empty()
        && !client.identity_provider_restrictions.contains(&session.idp)
    {
        return Ok(true);
    }
    if let Some(sso) = client.user_sso_lifetime
        && now.timestamp() - session.auth_time > i64::from(sso)
    {
        return Ok(true);
    }
    Ok(false)
}

/// Remaining prompt values other than `none` and
/// `consent` are unsupported; consent is needed for `prompt=consent` or
/// when requires consent says so. With the consent page's response, a
/// refusal is an error for the client, a grant missing a required scope is
/// `access_denied`, and a grant narrows the request to the granted scopes
/// and updates the remembered consent.
async fn process_consent(
    request: &mut ValidatedAuthorizeRequest,
    grants: &dyn PersistedGrantStore,
    consent: Option<&ConsentResponse>,
    now: DateTime<Utc>,
) -> Result<Interaction, StoreError> {
    if !request.prompt_modes.is_empty()
        && !request
            .prompt_modes
            .iter()
            .any(|p| p == "none" || p == "consent")
    {
        return Ok(Interaction::UnsupportedPromptMode);
    }
    let client = request
        .client
        .clone()
        .expect("validated request has a client");
    let subject_id = request
        .subject
        .as_ref()
        .expect("consent is decided for signed-in users")
        .subject_id
        .clone();
    let scopes = request
        .resources
        .as_ref()
        .map(|r| r.scopes.clone())
        .unwrap_or_default();
    let consent_required =
        consent::requires_consent(grants, &client, &subject_id, &scopes, now).await?;
    if consent_required && request.prompt_modes.iter().any(|p| p == "none") {
        return Ok(Interaction::Error(CONSENT_REQUIRED, None));
    }
    if !consent_required && !request.prompt_modes.iter().any(|p| p == "consent") {
        return Ok(Interaction::None);
    }
    let Some(consent) = consent else {
        return Ok(Interaction::Consent);
    };
    request.was_consent_shown = true;
    if !consent.granted() {
        let error = consent.error.unwrap_or(InteractionError::AccessDenied);
        return Ok(Interaction::Error(
            error.error_code(),
            consent.error_description.clone(),
        ));
    }
    let resources = request.resources.clone().unwrap_or_default();
    let consented = &consent.scopes_values_consented;
    if !resources
        .required_scope_values()
        .iter()
        .all(|s| consented.contains(s))
    {
        return Ok(Interaction::Error(
            InteractionError::AccessDenied.error_code(),
            None,
        ));
    }
    request.description = consent.description.clone();
    let narrowed = resources.filter(consented);
    if client.allow_remember_consent {
        let remembered = if consent.remember_consent {
            narrowed.scopes.clone()
        } else {
            Vec::new()
        };
        consent::update_consent(grants, &client, &subject_id, &remembered, now).await?;
    }
    request.resources = Some(narrowed);
    Ok(Interaction::None)
}
