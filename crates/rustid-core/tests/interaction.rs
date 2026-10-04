//! The authorize interaction response generator decisions on hand-built
//! requests: login, create-account, consent and `prompt=none`.

mod support;

use std::sync::Arc;

use chrono::{DateTime, Utc};
use rustid_core::authorize::{
    CONSENT_REQUIRED, Interaction, LOGIN_REQUIRED, PROCESSED_MAX_AGE, PROCESSED_PROMPT,
    ValidatedAuthorizeRequest, process_interaction,
};
use rustid_core::clients::Client;
use rustid_core::options::ProtocolOptions;
use rustid_core::params::Params;
use rustid_core::scopes::ValidatedResources;
use rustid_core::session::{SignIn, UserSession};
use support::Fixture;

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000, 0).unwrap()
}

fn request(prompts: &[&str], max_age: Option<i32>, signed_in: bool) -> ValidatedAuthorizeRequest {
    ValidatedAuthorizeRequest {
        prompt_modes: prompts.iter().map(|p| (*p).to_owned()).collect(),
        max_age,
        client: Some(Arc::new(Client {
            client_id: "web".into(),
            ..Default::default()
        })),
        resources: Some(ValidatedResources {
            scopes: vec!["openid".into()],
            ..Default::default()
        }),
        subject: signed_in.then(|| {
            UserSession::sign_in(
                SignIn {
                    subject_id: "1".into(),
                    auth_time: Some(now().timestamp() - 100),
                    ..Default::default()
                },
                None,
                now(),
                3600,
            )
        }),
        ..Default::default()
    }
}

async fn decide(r: &mut ValidatedAuthorizeRequest) -> Interaction {
    decide_with(r, &ProtocolOptions::default()).await
}

async fn decide_with(r: &mut ValidatedAuthorizeRequest, options: &ProtocolOptions) -> Interaction {
    let mut f = Fixture::new();
    f.options = options.clone();
    let ctx = f.authorize_ctx(now());
    process_interaction(r, &ctx, None).await.unwrap()
}

#[tokio::test]
async fn anonymous_users_log_in_without_markers() {
    let mut r = request(&[], Some(10), false);
    assert_eq!(decide(&mut r).await, Interaction::Login);
    assert!(!r.raw.contains(PROCESSED_PROMPT));
    assert!(!r.raw.contains(PROCESSED_MAX_AGE));
}

#[tokio::test]
async fn prompt_login_and_max_age_zero_are_marked_processed() {
    let mut r = request(&["login"], Some(0), true);
    assert_eq!(decide(&mut r).await, Interaction::Login);
    assert_eq!(
        r.raw.to_query_string(),
        "suppressed_prompt=login&suppressed_max_age=0"
    );
}

#[tokio::test]
async fn a_fresh_session_needs_no_interaction_and_max_age_counts_from_auth_time() {
    assert_eq!(
        decide(&mut request(&[], None, true)).await,
        Interaction::None
    );
    assert_eq!(
        decide(&mut request(&[], Some(100), true)).await,
        Interaction::None
    );
    assert_eq!(
        decide(&mut request(&[], Some(99), true)).await,
        Interaction::Login
    );
}

#[tokio::test]
async fn idp_tenant_local_login_and_sso_lifetime_force_login() {
    let mut r = request(&[], None, true);
    r.raw = Params::from_pairs([("acr_values", "idp:google")]);
    r.acr_values = vec!["idp:google".into()];
    assert_eq!(decide(&mut r).await, Interaction::Login);

    let mut r = request(&[], None, true);
    r.acr_values = vec!["tenant:t1".into()];
    assert_eq!(
        decide(&mut r).await,
        Interaction::None,
        "tenant ignored by default"
    );
    let options = ProtocolOptions {
        validate_tenant_on_authorization: true,
        ..Default::default()
    };
    assert_eq!(decide_with(&mut r, &options).await, Interaction::Login);

    let mut r = request(&[], None, true);
    r.client = Some(Arc::new(Client {
        enable_local_login: false,
        ..Default::default()
    }));
    assert_eq!(decide(&mut r).await, Interaction::Login);

    let mut r = request(&[], None, true);
    r.client = Some(Arc::new(Client {
        user_sso_lifetime: Some(99),
        ..Default::default()
    }));
    assert_eq!(decide(&mut r).await, Interaction::Login);
}

#[tokio::test]
async fn consent_is_needed_for_consent_clients_and_prompt_consent() {
    let mut r = request(&[], None, true);
    r.client = Some(Arc::new(Client {
        require_consent: true,
        ..Default::default()
    }));
    assert_eq!(decide(&mut r).await, Interaction::Consent);
    assert_eq!(
        decide(&mut request(&["consent"], None, true)).await,
        Interaction::Consent
    );
    let mut r = request(&["none"], None, true);
    r.client = Some(Arc::new(Client {
        require_consent: true,
        ..Default::default()
    }));
    assert_eq!(
        decide(&mut r).await,
        Interaction::Error(CONSENT_REQUIRED, None)
    );
}

#[tokio::test]
async fn prompt_none_turns_pages_into_errors() {
    assert_eq!(
        decide(&mut request(&["none"], None, false)).await,
        Interaction::Error(LOGIN_REQUIRED, None)
    );
    assert_eq!(
        decide(&mut request(&["none"], None, true)).await,
        Interaction::None
    );
}

#[tokio::test]
async fn prompt_create_shows_create_account() {
    let mut r = request(&["create"], None, true);
    assert_eq!(decide(&mut r).await, Interaction::CreateAccount);
    assert_eq!(r.raw.get(PROCESSED_PROMPT).as_deref(), Some("create"));
}

#[tokio::test]
async fn custom_prompt_values_are_unsupported_for_a_signed_in_user() {
    assert_eq!(
        decide(&mut request(&["custom-prompt"], None, true)).await,
        Interaction::UnsupportedPromptMode
    );
    assert_eq!(
        decide(&mut request(&["custom-prompt"], None, false)).await,
        Interaction::Login
    );
}
