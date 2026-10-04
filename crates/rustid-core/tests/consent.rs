mod support;

use chrono::{DateTime, Duration, Utc};
use rustid_core::authorize::{Interaction, process_interaction, validate};
use rustid_core::consent::{
    self, ConsentResponse, InteractionError, USER_CONSENT, consent_request_id,
};
use rustid_core::params::Params;
use rustid_core::session::{SignIn, UserSession};
use support::Fixture;

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000, 0).unwrap()
}

fn session() -> UserSession {
    UserSession::sign_in(
        SignIn {
            subject_id: "1".into(),
            auth_time: Some(now().timestamp() - 10),
            ..Default::default()
        },
        None,
        now(),
        3600,
    )
}

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn query(client: &str, scope: &str, extra: &str) -> Params {
    Params::parse_query(&format!(
        "client_id={client}&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code\
         &scope={scope}&state=s&nonce=n&code_challenge={CHALLENGE}&code_challenge_method=S256{extra}"
    ))
}

/// Validates the request for the signed-in session and decides.
async fn decide(
    f: &Fixture,
    params: Params,
    consent: Option<&ConsentResponse>,
) -> (Interaction, Vec<String>) {
    let ctx = f.authorize_ctx(now());
    let session = session();
    let mut request = validate(&ctx, params, Some(&session)).await.unwrap();
    let interaction = process_interaction(&mut request, &ctx, consent)
        .await
        .unwrap();
    let scopes = request.resources.map(|r| r.scopes).unwrap_or_default();
    (interaction, scopes)
}

fn granted(scopes: &[&str], remember: bool) -> ConsentResponse {
    ConsentResponse {
        scopes_values_consented: scopes.iter().map(|s| (*s).to_owned()).collect(),
        remember_consent: remember,
        ..Default::default()
    }
}

#[test]
fn consent_request_ids_are_stable() {
    // SHA-256 of "client2:bob:123_nonce:api1,api2,openid", base64url.
    assert_eq!(
        consent_request_id(
            "client2",
            Some("bob"),
            Some("123_nonce"),
            Some("openid api2 api1 api2")
        ),
        "yBnT5LGtZEFBUIulXKZRPA86VrPsVxgZA3U9upkNW5g"
    );
    // A missing subject and nonce interpolate as empty strings.
    assert_eq!(
        consent_request_id("client2", None, None, Some("openid")),
        "miwvOeeddeiNEE4Z-GousIe4GmtmetFNw4oOBupgMTQ"
    );
}

#[tokio::test]
async fn a_consent_client_shows_the_consent_page_until_consent_is_given() {
    let f = Fixture::new();
    let (interaction, _) = decide(&f, query("web-consent", "openid%20api1", ""), None).await;
    assert_eq!(interaction, Interaction::Consent);
    let (interaction, scopes) = decide(
        &f,
        query("web-consent", "openid%20profile%20api1", ""),
        Some(&granted(&["openid", "api1"], false)),
    )
    .await;
    assert_eq!(interaction, Interaction::None);
    assert_eq!(
        scopes,
        ["openid", "api1"],
        "the granted subset, in request order"
    );
}

#[tokio::test]
async fn missing_required_scopes_and_refusals_are_errors_for_the_client() {
    let f = Fixture::new();
    let (interaction, _) = decide(
        &f,
        query("web-consent", "openid%20api1", ""),
        Some(&granted(&["api1"], false)),
    )
    .await;
    assert_eq!(interaction, Interaction::Error("access_denied", None));

    for (error, code) in [
        (InteractionError::AccessDenied, "access_denied"),
        (
            InteractionError::TemporarilyUnavailable,
            "temporarily_unavailable",
        ),
        (
            InteractionError::UnmetAuthenticationRequirements,
            "unmet_authentication_requirements",
        ),
        (InteractionError::ConsentRequired, "consent_required"),
        (InteractionError::LoginRequired, "login_required"),
        (
            InteractionError::InteractionRequired,
            "interaction_required",
        ),
        (
            InteractionError::AccountSelectionRequired,
            "account_selection_required",
        ),
    ] {
        let refused = ConsentResponse {
            error: Some(error),
            error_description: Some("some description".into()),
            ..Default::default()
        };
        let (interaction, _) = decide(&f, query("web-consent", "openid", ""), Some(&refused)).await;
        assert_eq!(
            interaction,
            Interaction::Error(code, Some("some description".into()))
        );
    }

    // No scopes and no error is a refusal too.
    let (interaction, _) = decide(
        &f,
        query("web-consent", "openid", ""),
        Some(&ConsentResponse::default()),
    )
    .await;
    assert_eq!(interaction, Interaction::Error("access_denied", None));
}

#[tokio::test]
async fn a_denial_before_login_is_returned_without_a_login() {
    let f = Fixture::new();
    let ctx = f.authorize_ctx(now());
    let mut request = validate(&ctx, query("web", "openid", ""), None)
        .await
        .unwrap();
    let denied = ConsentResponse {
        error: Some(InteractionError::AccessDenied),
        ..Default::default()
    };
    let interaction = process_interaction(&mut request, &ctx, Some(&denied))
        .await
        .unwrap();
    assert_eq!(interaction, Interaction::Error("access_denied", None));
}

#[tokio::test]
async fn remembered_consent_skips_the_page_for_the_same_or_fewer_scopes() {
    let f = Fixture::new();
    let (interaction, _) = decide(
        &f,
        query("web-consent", "openid%20api1", ""),
        Some(&granted(&["openid", "api1"], true)),
    )
    .await;
    assert_eq!(interaction, Interaction::None);

    // Stored under the consent key, in the stored JSON shape.
    // Upper-case hex SHA-256 of "web-consent|1-1:user_consent".
    let key = "278E7CE7312349754FAE4963718E9CF9FBE67CF652F0C709ED8DB34597D9A4D1".to_owned();
    assert_eq!(
        key,
        rustid_core::grants::hashed_key("web-consent|1-1", USER_CONSENT)
    );
    let grant = f.stores.grants.get(&key).await.unwrap().unwrap();
    assert_eq!(grant.grant_type, "user_consent");
    let data: serde_json::Value = serde_json::from_str(&grant.data).unwrap();
    assert_eq!(data["SubjectId"], "1");
    assert_eq!(data["ClientId"], "web-consent");
    assert_eq!(data["Scopes"], serde_json::json!(["openid", "api1"]));

    let (interaction, _) = decide(&f, query("web-consent", "openid", ""), None).await;
    assert_eq!(interaction, Interaction::None, "fewer scopes are covered");
    let (interaction, _) = decide(
        &f,
        query("web-consent", "openid%20profile%20api1", ""),
        None,
    )
    .await;
    assert_eq!(interaction, Interaction::Consent, "more scopes are not");
    let (interaction, _) =
        decide(&f, query("web-consent", "openid", "&prompt=consent"), None).await;
    assert_eq!(
        interaction,
        Interaction::Consent,
        "prompt=consent always asks"
    );

    // Consenting again without remembering forgets the record.
    let (interaction, _) = decide(
        &f,
        query("web-consent", "openid", "&prompt=consent"),
        Some(&granted(&["openid"], false)),
    )
    .await;
    assert_eq!(interaction, Interaction::None);
    assert!(f.stores.grants.get(&key).await.unwrap().is_none());
}

#[tokio::test]
async fn offline_access_always_asks_and_expired_consent_is_removed() {
    let mut f = Fixture::new();
    f.edit_clients(|clients| {
        let web = clients
            .iter_mut()
            .find(|c| c.client_id == "web-consent")
            .unwrap();
        web.consent_lifetime = Some(60);
    });
    let (interaction, _) = decide(
        &f,
        query("web-consent", "openid%20offline_access", ""),
        Some(&granted(&["openid", "offline_access"], true)),
    )
    .await;
    assert_eq!(interaction, Interaction::None);
    let (interaction, _) = decide(
        &f,
        query("web-consent", "openid%20offline_access", ""),
        None,
    )
    .await;
    assert_eq!(
        interaction,
        Interaction::Consent,
        "offline_access always asks"
    );

    let client = f
        .clients
        .clients
        .iter()
        .find(|c| c.client_id == "web-consent")
        .unwrap();
    let scopes = vec!["openid".to_owned()];
    assert!(
        !consent::requires_consent(f.stores.grants.as_ref(), client, "1", &scopes, now())
            .await
            .unwrap()
    );
    let later = now() + Duration::seconds(61);
    assert!(
        consent::requires_consent(f.stores.grants.as_ref(), client, "1", &scopes, later)
            .await
            .unwrap()
    );
    let key = rustid_core::grants::hashed_key("web-consent|1-1", USER_CONSENT);
    assert!(
        f.stores.grants.get(&key).await.unwrap().is_none(),
        "expired consent is removed"
    );
}

#[tokio::test]
async fn a_client_that_cannot_remember_always_asks() {
    let mut f = Fixture::new();
    f.edit_clients(|clients| {
        let web = clients
            .iter_mut()
            .find(|c| c.client_id == "web-consent")
            .unwrap();
        web.allow_remember_consent = false;
    });
    let (interaction, _) = decide(
        &f,
        query("web-consent", "openid", ""),
        Some(&granted(&["openid"], true)),
    )
    .await;
    assert_eq!(interaction, Interaction::None);
    let key = rustid_core::grants::hashed_key("web-consent|1-1", USER_CONSENT);
    assert!(f.stores.grants.get(&key).await.unwrap().is_none());
    let (interaction, _) = decide(&f, query("web-consent", "openid", ""), None).await;
    assert_eq!(interaction, Interaction::Consent);
}

#[tokio::test]
async fn consent_responses_are_kept_for_ten_minutes_and_taken_once() {
    let f = Fixture::new();
    let grants = f.stores.grants.as_ref();
    let response = granted(&["openid"], false);
    consent::store_response(grants, "ID", Some("1"), "web-consent", &response, now())
        .await
        .unwrap();
    assert_eq!(
        consent::read_response(grants, "ID", now()).await.unwrap(),
        Some(response.clone())
    );
    assert_eq!(
        consent::read_response(grants, "ID", now() + Duration::seconds(601))
            .await
            .unwrap(),
        None,
        "expired"
    );
    consent::delete_response(grants, "ID").await.unwrap();
    assert_eq!(
        consent::read_response(grants, "ID", now()).await.unwrap(),
        None
    );
}
