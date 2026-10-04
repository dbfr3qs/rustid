//! Pushed authorization requests (RFC 9126): pushing, using the
//! `request_uri` at the authorize endpoint, and every way that fails.

mod support;

use chrono::{DateTime, Duration, Utc};
use rustid_core::authorize::{AuthorizeFailure, AuthorizeRequestType, return_url_query, validate};
use rustid_core::params::Params;
use rustid_core::pushed_authorization::{self, PushError};
use support::Fixture;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn now() -> DateTime<Utc> {
    Utc::now()
}

fn pushed_params(client: &str) -> Params {
    Params::parse_query(&format!(
        "client_id={client}&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code\
         &scope=openid%20api1&state=pushed_state&code_challenge={CHALLENGE}&code_challenge_method=S256"
    ))
}

async fn push(
    f: &Fixture,
    client: &str,
    params: Params,
    at: DateTime<Utc>,
) -> Result<(String, i64), PushError> {
    let client = f
        .clients
        .clients
        .iter()
        .find(|c| c.client_id == client)
        .unwrap()
        .clone();
    pushed_authorization::push(&f.authorize_ctx(at), &client, params, None).await
}

async fn authorize(
    f: &Fixture,
    query: &str,
    at: DateTime<Utc>,
) -> Result<rustid_core::authorize::ValidatedAuthorizeRequest, (String, Option<String>)> {
    match validate(&f.authorize_ctx(at), Params::parse_query(query), None).await {
        Ok(r) => Ok(r),
        Err(AuthorizeFailure::Invalid(e)) => Err((e.error.to_owned(), e.description)),
        Err(AuthorizeFailure::Server(m)) => panic!("{m}"),
    }
}

fn uri_query(uri: &str, client: &str) -> String {
    format!(
        "client_id={client}&request_uri={}",
        rustid_core::params::url_encode(uri)
    )
}

fn invalid_uri(description: &str) -> (String, Option<String>) {
    (
        "invalid_request_uri".to_owned(),
        Some(description.to_owned()),
    )
}

#[tokio::test]
async fn a_pushed_request_is_used_by_reference() {
    let f = Fixture::new();
    let (uri, expires_in) = push(&f, "web", pushed_params("web"), now()).await.unwrap();
    assert!(
        uri.starts_with("urn:ietf:params:oauth:request_uri:"),
        "{uri}"
    );
    assert_eq!(expires_in, 600);
    let r = authorize(
        &f,
        &format!("{}&state=query_state", uri_query(&uri, "web")),
        now(),
    )
    .await
    .unwrap();
    assert_eq!(
        r.request_type,
        AuthorizeRequestType::AuthorizeWithPushedParameters
    );
    assert_eq!(
        r.raw.get("state").as_deref(),
        Some("pushed_state"),
        "the pushed parameters"
    );
    assert_eq!(
        r.redirect_uri.as_deref(),
        Some("https://client.test/callback")
    );
    // The return URL names the pushed request, not its parameters.
    let reference = uri.rsplit(':').next().unwrap();
    assert_eq!(
        return_url_query(&r),
        format!(
            "request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A{reference}&client_id=web"
        )
    );
}

#[tokio::test]
async fn consumed_expired_foreign_and_disabled_pushed_requests_fail() {
    let mut f = Fixture::new();
    let (uri, _) = push(&f, "web", pushed_params("web"), now()).await.unwrap();
    assert_eq!(
        authorize(&f, &uri_query(&uri, "code-confidential"), now())
            .await
            .unwrap_err(),
        invalid_uri("invalid client for pushed authorization request")
    );
    assert_eq!(
        authorize(&f, &uri_query(&uri, "web"), now() + Duration::seconds(601))
            .await
            .unwrap_err(),
        invalid_uri("expired pushed authorization request")
    );
    let reference = uri.rsplit(':').next().unwrap();
    pushed_authorization::consume(f.stores.grants.as_ref(), reference)
        .await
        .unwrap();
    assert_eq!(
        authorize(&f, &uri_query(&uri, "web"), now())
            .await
            .unwrap_err(),
        invalid_uri("invalid or reused PAR request uri")
    );
    let (uri, _) = push(&f, "web", pushed_params("web"), now()).await.unwrap();
    f.options.endpoints.enable_pushed_authorization_endpoint = false;
    assert_eq!(
        authorize(&f, &uri_query(&uri, "web"), now())
            .await
            .unwrap_err(),
        invalid_uri("Pushed authorization is disabled.")
    );
}

#[tokio::test]
async fn pushing_validates_like_the_authorize_endpoint() {
    let f = Fixture::new();
    let mut with_uri = pushed_params("web");
    with_uri.add("request_uri", "https://client.test/r");
    assert_eq!(
        push(&f, "web", with_uri, now()).await.unwrap_err(),
        PushError {
            error: "invalid_request".into(),
            description: Some("Pushed authorization cannot use request_uri".into()),
            dpop_nonce: None,
        }
    );
    let mut bad = pushed_params("web");
    bad.set("redirect_uri", "https://evil.test/cb");
    let error = push(&f, "web", bad, now()).await.unwrap_err();
    assert_eq!(error.error, "invalid_request");
    assert_eq!(error.description.as_deref(), Some("Invalid redirect_uri"));
}

#[tokio::test]
async fn required_pushed_authorization_refuses_plain_requests() {
    let plain = "client_id=web&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid";
    let required = (
        "invalid_request".to_owned(),
        Some("Pushed authorization is required.".to_owned()),
    );
    let mut f = Fixture::new();
    f.options.pushed_authorization.required = true;
    assert_eq!(authorize(&f, plain, now()).await.unwrap_err(), required);
    let (uri, _) = push(&f, "web", pushed_params("web"), now()).await.unwrap();
    assert!(
        authorize(&f, &uri_query(&uri, "web"), now()).await.is_ok(),
        "pushing is allowed"
    );

    let mut f = Fixture::new();
    f.edit_clients(|clients| {
        clients
            .iter_mut()
            .find(|c| c.client_id == "web")
            .unwrap()
            .require_pushed_authorization = true;
    });
    assert_eq!(authorize(&f, plain, now()).await.unwrap_err(), required);
}

#[tokio::test]
async fn a_client_lifetime_overrides_the_default() {
    let mut f = Fixture::new();
    f.edit_clients(|clients| {
        clients
            .iter_mut()
            .find(|c| c.client_id == "web")
            .unwrap()
            .pushed_authorization_lifetime = Some(30);
    });
    let (_, expires_in) = push(&f, "web", pushed_params("web"), now()).await.unwrap();
    assert_eq!(expires_in, 30);
}

#[tokio::test]
async fn client_credentials_are_not_stored_with_the_pushed_request() {
    let f = Fixture::new();
    let mut params = pushed_params("code-confidential");
    params.add("client_secret", "secret");
    params.add("client_assertion", "a.b.c");
    params.add(
        "client_assertion_type",
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    );
    let (uri, _) = push(&f, "code-confidential", params, now()).await.unwrap();
    let reference = uri.rsplit(':').next().unwrap();
    let pushed = pushed_authorization::get(f.stores.grants.as_ref(), reference)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !pushed.parameters.contains("client_secret"),
        "{}",
        pushed.parameters
    );
    assert!(
        !pushed.parameters.contains("client_assertion"),
        "{}",
        pushed.parameters
    );
    assert!(pushed.parameters.contains("client_id=code-confidential"));
}

const PAR_URL: &str = "http://h/connect/par";

async fn push_with_proof(
    f: &Fixture,
    client: &str,
    params: Params,
    proof: &str,
) -> Result<(String, i64), PushError> {
    let client = f
        .clients
        .clients
        .iter()
        .find(|c| c.client_id == client)
        .unwrap()
        .clone();
    let dpop = pushed_authorization::PushProof {
        proof,
        url: PAR_URL,
        replay: &f.replay,
        protector: &f.protector,
    };
    pushed_authorization::push(&f.authorize_ctx(now()), &client, params, Some(&dpop)).await
}

fn dpop_error(error: &str, description: &str) -> PushError {
    PushError {
        error: error.into(),
        description: Some(description.into()),
        dpop_nonce: None,
    }
}

#[tokio::test]
async fn a_proof_at_par_binds_the_code_to_its_key() {
    let f = Fixture::new();
    let key = support::key("client-jwt-key.pem", "p", "RS256");
    let jkt = support::dpop_thumbprint(&key);
    let (uri, _) = push_with_proof(
        &f,
        "web",
        pushed_params("web"),
        &support::dpop_proof(&key, PAR_URL, None),
    )
    .await
    .unwrap();
    let request = authorize(&f, &uri_query(&uri, "web"), now()).await.unwrap();
    assert_eq!(request.dpop_key_thumbprint.as_deref(), Some(jkt.as_str()));

    // A matching dpop_jkt is fine; a different one isn't.
    let mut params = pushed_params("web");
    params.add("dpop_jkt", &jkt);
    assert!(
        push_with_proof(&f, "web", params, &support::dpop_proof(&key, PAR_URL, None))
            .await
            .is_ok()
    );
    let mut params = pushed_params("web");
    params.add("dpop_jkt", "other");
    assert_eq!(
        push_with_proof(&f, "web", params, &support::dpop_proof(&key, PAR_URL, None)).await,
        Err(dpop_error(
            "invalid_request",
            "Mismatch between thumbprint of JWK in DPoP HTTP header and dpop_jkt parameter"
        ))
    );
}

#[tokio::test]
async fn invalid_proofs_at_par() {
    let mut f = Fixture::new();
    assert_eq!(
        push_with_proof(&f, "web", pushed_params("web"), "malformed").await,
        Err(dpop_error("invalid_dpop_proof", "Malformed DPoP token."))
    );
    assert_eq!(
        push_with_proof(&f, "web", pushed_params("web"), &"x".repeat(4001)).await,
        Err(dpop_error(
            "invalid_dpop_proof",
            "DPoP proof token is too long"
        ))
    );
    // A proof for the token endpoint isn't one for PAR.
    let key = support::key("client-jwt-key.pem", "p", "RS256");
    assert_eq!(
        push_with_proof(
            &f,
            "web",
            pushed_params("web"),
            &support::dpop_proof(&key, "http://h/connect/token", None)
        )
        .await,
        Err(dpop_error("invalid_dpop_proof", "Invalid 'htu' value."))
    );
    // Nonce mode: use_dpop_nonce with an empty description and a nonce.
    f.edit_clients(|clients| {
        let web = clients.iter_mut().find(|c| c.client_id == "web").unwrap();
        web.dpop_validation_mode = rustid_core::dpop::DPoPValidationMode::Nonce;
    });
    let e = push_with_proof(
        &f,
        "web",
        pushed_params("web"),
        &support::dpop_proof(&key, PAR_URL, None),
    )
    .await
    .unwrap_err();
    assert_eq!(
        (e.error.as_str(), e.description.as_deref()),
        ("use_dpop_nonce", Some(""))
    );
    let nonce = e.dpop_nonce.expect("a server nonce");
    assert!(
        push_with_proof(
            &f,
            "web",
            pushed_params("web"),
            &support::dpop_proof(&key, PAR_URL, Some(&nonce))
        )
        .await
        .is_ok()
    );
}

/// A request object for the `jar` client, signed with its RSA key.
fn jar_object(extra: serde_json::Value) -> String {
    let key = rustid_core::keys::LoadedKey::load(&rustid_core::keys::KeyConfig {
        kid: "k".into(),
        alg: "RS256".into(),
        key_file: support::fixture("client-jwt-key.pem"),
        cert_file: None,
    })
    .unwrap();
    let now = Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": "jar",
        "aud": support::ISSUER,
        "exp": now + 60,
        "client_id": "jar",
        "response_type": "id_token",
        "scope": "openid profile",
        "redirect_uri": "https://client.test/callback",
        "nonce": "n",
    });
    let mut claims = claims;
    for (k, v) in extra.as_object().unwrap() {
        claims[k] = v.clone();
    }
    rustid_core::jwt::encode(&key, &[], claims.as_object().unwrap()).unwrap()
}

/// RFC 9126 §3: a push whose parameters are all in the request object is
/// the authenticated client's, with no client_id in the form.
#[tokio::test]
async fn a_request_object_push_without_client_id_is_the_authenticated_clients() {
    let f = Fixture::new();
    let params = Params::parse_query(&format!("request={}", jar_object(serde_json::json!({}))));
    assert!(push(&f, "jar", params, now()).await.is_ok());
}

#[tokio::test]
async fn a_push_without_client_id_or_request_object_is_refused() {
    let f = Fixture::new();
    let params = Params::parse_query(
        "redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=id_token&scope=openid&nonce=n",
    );
    let e = push(&f, "jar", params, now()).await.unwrap_err();
    assert_eq!(
        (e.error.as_str(), e.description.as_deref()),
        ("invalid_request", Some("Invalid client_id"))
    );
}

/// A DPoP-bound push whose request object names the proof's key in
/// `dpop_jkt` (FAPI 2 Message Signing): not a duplicate of the form.
#[tokio::test]
async fn dpop_jkt_in_the_request_object_is_checked_against_the_proof() {
    let f = Fixture::new();
    let key = support::key("client-jwt-key.pem", "p", "RS256");
    let jkt = support::dpop_thumbprint(&key);
    let object = |jkt: Option<&str>| {
        let extra = jkt.map_or(
            serde_json::json!({}),
            |j| serde_json::json!({ "dpop_jkt": j }),
        );
        Params::parse_query(&format!("client_id=jar&request={}", jar_object(extra)))
    };
    let proof = || support::dpop_proof(&key, PAR_URL, None);

    let (uri, _) = push_with_proof(&f, "jar", object(Some(&jkt)), &proof())
        .await
        .unwrap();
    let request = authorize(&f, &uri_query(&uri, "jar"), now()).await.unwrap();
    assert_eq!(request.dpop_key_thumbprint.as_deref(), Some(jkt.as_str()));

    let (uri, _) = push_with_proof(&f, "jar", object(None), &proof())
        .await
        .unwrap();
    let request = authorize(&f, &uri_query(&uri, "jar"), now()).await.unwrap();
    assert_eq!(
        request.dpop_key_thumbprint.as_deref(),
        Some(jkt.as_str()),
        "bound anyway"
    );

    assert_eq!(
        push_with_proof(&f, "jar", object(Some("other")), &proof()).await,
        Err(dpop_error(
            "invalid_request",
            "Mismatch between thumbprint of JWK in DPoP HTTP header and dpop_jkt parameter"
        ))
    );
}
