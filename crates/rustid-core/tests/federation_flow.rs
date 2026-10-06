//! The upstream leg of federation: discovery checks and caching, the id
//! token checks (OIDC Core §3.1.3.7), the token request, the correlation
//! cookie and the authorization URL, against a fake upstream.

use std::sync::{Arc, Mutex};

use rustid_core::data_protection::DataProtector;
use rustid_core::federation::challenge::{Correlation, authorization_url};
use rustid_core::federation::flow::{Failure, Federation};
use rustid_core::federation::id_token::{Expectations, IdTokenCheck, ValidatedIdToken, validate};
use rustid_core::federation::provider::{Credential, IdentityProvider, Provider, Providers};
use rustid_core::federation::session::{sign_in, subject_for};
use rustid_core::federation::upstream::{
    FormPost, Metadata, UpstreamClient, UpstreamError, token_request,
};
use rustid_core::jwt::{b64url, b64url_decode};
use rustid_core::keys::{KeyOrigin, LoadedKey, generate_pkcs8};
use serde_json::{Value, json};

const AUTHORITY: &str = "https://up.example";
const DISCOVERY: &str = "https://up.example/.well-known/openid-configuration";
const JWKS: &str = "https://up.example/jwks";
const NOW: i64 = 1_800_000_000;

fn key(kid: &str, alg: &str) -> LoadedKey {
    let der = generate_pkcs8(alg, 2048).unwrap();
    LoadedKey::from_der(kid, alg, &der, None, &KeyOrigin::default()).unwrap()
}

fn jwk(key: &LoadedKey) -> Value {
    serde_json::to_value(&key.jwk).unwrap()
}

fn discovery() -> Value {
    json!({
        "issuer": AUTHORITY,
        "authorization_endpoint": "https://up.example/authorize",
        "token_endpoint": "https://up.example/token",
        "jwks_uri": JWKS,
        "id_token_signing_alg_values_supported": ["RS256"],
    })
}

struct FakeState {
    discovery: Value,
    jwks: Vec<Value>,
    token_status: u16,
    token_body: Value,
    gets: Vec<String>,
    posts: Vec<FormPost>,
    userinfo: Value,
    bearer: Vec<String>,
}

struct Fake(Mutex<FakeState>);

impl Fake {
    fn new(keys: &[&LoadedKey]) -> Arc<Fake> {
        Arc::new(Fake(Mutex::new(FakeState {
            discovery: discovery(),
            jwks: keys.iter().map(|k| jwk(k)).collect(),
            token_status: 200,
            token_body: json!({}),
            gets: Vec::new(),
            posts: Vec::new(),
            userinfo: json!({ "sub": "upstream-user", "email": "ada@userinfo.example", "iss": "ignored" }),
            bearer: Vec::new(),
        })))
    }
    fn gets(&self, url: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .gets
            .iter()
            .filter(|g| *g == url)
            .count()
    }
}

#[async_trait::async_trait]
impl UpstreamClient for Fake {
    async fn get_json(&self, url: &str) -> Result<Value, UpstreamError> {
        let mut s = self.0.lock().unwrap();
        s.gets.push(url.to_owned());
        match url {
            u if u.ends_with("/.well-known/openid-configuration") => Ok(s.discovery.clone()),
            JWKS => Ok(json!({ "keys": s.jwks })),
            _ => Err(UpstreamError(format!("unexpected GET {url}"))),
        }
    }
    async fn post_form(&self, post: &FormPost) -> Result<(u16, Value), UpstreamError> {
        let mut s = self.0.lock().unwrap();
        s.posts.push(post.clone());
        Ok((s.token_status, s.token_body.clone()))
    }
    async fn get_userinfo(&self, url: &str, access_token: &str) -> Result<Value, UpstreamError> {
        let mut s = self.0.lock().unwrap();
        assert_eq!(url, "https://up.example/userinfo");
        s.bearer.push(access_token.to_owned());
        Ok(s.userinfo.clone())
    }
}

fn config() -> IdentityProvider {
    serde_json::from_value(json!({
        "scheme": "up", "displayName": "Upstream", "authority": AUTHORITY,
        "clientId": "abc", "clientAuthentication": { "secret": "s" },
    }))
    .unwrap()
}

fn provider(credential: Credential) -> Provider {
    Provider {
        config: config(),
        credential,
    }
}

fn metadata() -> Metadata {
    serde_json::from_value(discovery()).unwrap()
}

fn baseline(nonce: &str) -> Value {
    json!({ "iss": AUTHORITY, "aud": "abc", "exp": NOW + 300, "iat": NOW,
            "nonce": nonce, "sub": "upstream-user" })
}

fn token(key: &LoadedKey, payload: &Value) -> String {
    rustid_core::jwt::encode(key, &[], payload.as_object().unwrap()).unwrap()
}

/// A token with exactly this header, signed by `key` (or with `signature`).
fn raw_token(key: Option<&LoadedKey>, header: &Value, payload: &Value) -> String {
    let input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(payload.to_string().as_bytes())
    );
    let sig = key
        .map(|k| k.sign(input.as_bytes()).unwrap())
        .unwrap_or_default();
    format!("{input}.{}", b64url(&sig))
}

fn expect<'a>(algorithms: &'a [String], nonce: &'a str) -> Expectations<'a> {
    Expectations {
        issuer: AUTHORITY,
        client_id: "abc",
        nonce,
        algorithms,
        now: NOW,
        skew: 300,
    }
}

#[tokio::test]
async fn metadata_is_checked_and_cached() {
    let k = key("k1", "RS256");
    let fake = Fake::new(&[&k]);
    fake.0.lock().unwrap().discovery["issuer"] = "https://other.example".into();
    let fed = Federation::new(
        Providers::new(vec![provider(Credential::Basic("s".into()))]).unwrap(),
        fake.clone(),
        false,
    );
    let p = fed.find("up").await.unwrap().unwrap();
    let p = &*p;
    match fed.metadata(p, NOW).await.unwrap_err() {
        Failure::MetadataUnavailable(detail) => assert!(detail.contains("issuer"), "{detail}"),
        other => panic!("{other:?}"),
    }
    fake.0.lock().unwrap().discovery = discovery();
    // The failure is kept for a minute.
    fed.metadata(p, NOW + 61).await.unwrap();
    fed.metadata(p, NOW + 62).await.unwrap();
    assert_eq!(fake.gets(DISCOVERY), 2, "one failed, one cached");
    fed.metadata(p, NOW + 61 + 86_401).await.unwrap();
    assert_eq!(fake.gets(DISCOVERY), 3);
}

#[tokio::test]
async fn a_failed_discovery_is_kept_for_a_minute() {
    let k = key("k1", "RS256");
    let fake = Fake::new(&[&k]);
    fake.0.lock().unwrap().discovery = json!(null);
    let fed = federation(fake.clone());
    let p = fed.find("up").await.unwrap().unwrap();
    assert!(fed.metadata(&p, NOW).await.is_err());
    // Recovered upstream, but within the minute: the failure answers,
    // without a request.
    fake.0.lock().unwrap().discovery = discovery();
    assert!(matches!(
        fed.metadata(&p, NOW + 59).await,
        Err(Failure::MetadataUnavailable(_))
    ));
    assert_eq!(fake.gets(DISCOVERY), 1);
    // After it, the provider is asked again, and the success replaces it.
    fed.metadata(&p, NOW + 60).await.unwrap();
    fed.metadata(&p, NOW + 61).await.unwrap();
    assert_eq!(fake.gets(DISCOVERY), 2);
}

#[tokio::test]
async fn metadata_endpoints_must_be_https() {
    let k = key("k1", "RS256");
    let fake = Fake::new(&[&k]);
    fake.0.lock().unwrap().discovery["token_endpoint"] = "http://up.example/token".into();
    let fed = Federation::new(
        Providers::new(vec![provider(Credential::Basic("s".into()))]).unwrap(),
        fake,
        false,
    );
    let p = fed.find("up").await.unwrap().unwrap();
    let p = &*p;
    assert!(matches!(
        fed.metadata(p, NOW).await,
        Err(Failure::MetadataUnavailable(_))
    ));
}

#[test]
fn metadata_algorithms_default_to_rs256_and_drop_symmetric_ones() {
    let mut m = metadata();
    m.id_token_signing_alg_values_supported = vec![];
    assert_eq!(m.id_token_algorithms(), ["RS256"]);
    m.id_token_signing_alg_values_supported = vec!["HS256".into(), "none".into(), "ES256".into()];
    assert_eq!(m.id_token_algorithms(), ["ES256"]);
}

#[test]
fn id_token_checks() {
    let k = key("k1", "RS256");
    let keys = vec![k.public_jwk()];
    let rs256 = vec!["RS256".to_owned()];
    let check = |t: &str| validate(t, &keys, &expect(&rs256, "n1"));
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut p = baseline("n1");
        edit(&mut p);
        token(&k, &p)
    };

    let ok = check(&token(&k, &baseline("n1"))).unwrap();
    assert_eq!(ok.issuer, AUTHORITY);
    assert_eq!(ok.subject, "upstream-user");

    let none = raw_token(None, &json!({ "alg": "none" }), &baseline("n1"));
    assert_eq!(check(&none), Err(IdTokenCheck::Algorithm));
    let hs = raw_token(
        None,
        &json!({ "alg": "HS256", "kid": "k1" }),
        &baseline("n1"),
    );
    assert_eq!(check(&hs), Err(IdTokenCheck::Algorithm));
    let es = key("k1", "ES256");
    assert_eq!(
        check(&token(&es, &baseline("n1"))),
        Err(IdTokenCheck::Algorithm)
    );
    let other = key("k2", "RS256");
    assert_eq!(
        check(&token(&other, &baseline("n1"))),
        Err(IdTokenCheck::UnknownKey)
    );
    let good = token(&k, &baseline("n1"));
    let (input, sig) = good.rsplit_once('.').unwrap();
    let mut sig = b64url_decode(sig).unwrap();
    sig[0] ^= 1;
    assert_eq!(
        check(&format!("{input}.{}", b64url(&sig))),
        Err(IdTokenCheck::Signature)
    );

    assert_eq!(
        check(&with(&|p| p["iss"] = "https://evil".into())),
        Err(IdTokenCheck::Issuer)
    );
    assert_eq!(
        check(&with(&|p| p["aud"] = json!(["other"]))),
        Err(IdTokenCheck::Audience)
    );
    assert_eq!(
        check(&with(&|p| p["aud"] = json!(["abc", "other"]))),
        Err(IdTokenCheck::AuthorizedParty)
    );
    check(&with(&|p| {
        p["aud"] = json!(["abc", "other"]);
        p["azp"] = "abc".into();
    }))
    .unwrap();
    assert_eq!(
        check(&with(&|p| p["azp"] = "other".into())),
        Err(IdTokenCheck::AuthorizedParty)
    );
    assert_eq!(
        check(&with(&|p| p["exp"] = (NOW - 301).into())),
        Err(IdTokenCheck::Expired)
    );
    check(&with(&|p| p["exp"] = (NOW - 299).into())).unwrap();
    assert_eq!(
        check(&with(&|p| {
            p.as_object_mut().unwrap().remove("exp");
        })),
        Err(IdTokenCheck::Expired)
    );
    assert_eq!(
        check(&with(&|p| p["iat"] = (NOW + 301).into())),
        Err(IdTokenCheck::IssuedInFuture)
    );
    // iat is required (OIDC Core 2).
    assert_eq!(
        check(&with(&|p| {
            p.as_object_mut().unwrap().remove("iat");
        })),
        Err(IdTokenCheck::IssuedInFuture)
    );
    assert_eq!(
        check(&with(&|p| p["nonce"] = "x".into())),
        Err(IdTokenCheck::Nonce)
    );
    assert_eq!(
        check(&with(&|p| p["sub"] = "".into())),
        Err(IdTokenCheck::Subject)
    );
    assert_eq!(check("not.a.jwt"), Err(IdTokenCheck::Malformed));
}

#[test]
fn a_named_key_must_be_a_signing_key_for_the_algorithm() {
    let k = key("k1", "RS256");
    let rs256 = vec!["RS256".to_owned()];
    let t = token(&k, &baseline("n1"));
    let parse = |v: Value| serde_json::from_value::<rustid_core::jwt::PublicJwk>(v).unwrap();
    let mut encryption = jwk(&k);
    encryption["use"] = "enc".into();
    assert_eq!(
        validate(&t, &[parse(encryption)], &expect(&rs256, "n1")),
        Err(IdTokenCheck::Signature)
    );
    let mut other_alg = jwk(&k);
    other_alg["alg"] = "PS256".into();
    assert_eq!(
        validate(&t, &[parse(other_alg)], &expect(&rs256, "n1")),
        Err(IdTokenCheck::Signature)
    );
}

#[test]
fn no_kid_uses_the_only_suitable_key() {
    let k = key("k1", "RS256");
    let rs256 = vec!["RS256".to_owned()];
    let t = raw_token(Some(&k), &json!({ "alg": "RS256" }), &baseline("n1"));
    validate(&t, &[k.public_jwk()], &expect(&rs256, "n1")).unwrap();
    // Keys that can't apply are ignored (RFC 7517 section 5): another
    // algorithm, an encryption key.
    let parse = |v: Value| serde_json::from_value::<rustid_core::jwt::PublicJwk>(v).unwrap();
    let mut other_alg = jwk(&key("x1", "RS256"));
    other_alg.as_object_mut().unwrap().remove("kid");
    other_alg["alg"] = "RS9999".into();
    let mut encryption = jwk(&key("x2", "RS256"));
    encryption.as_object_mut().unwrap().remove("kid");
    encryption["use"] = "enc".into();
    let ignored = [k.public_jwk(), parse(other_alg), parse(encryption)];
    validate(&t, &ignored, &expect(&rs256, "n1")).unwrap();
    let two = [k.public_jwk(), key("k2", "RS256").public_jwk()];
    assert_eq!(
        validate(&t, &two, &expect(&rs256, "n1")),
        Err(IdTokenCheck::Signature)
    );
}

#[test]
fn token_request_forms() {
    let m = metadata();
    let form = |post: &FormPost| -> Vec<(String, String)> { post.form.clone() };
    let pairs = |v: &[(&str, &str)]| -> Vec<(String, String)> {
        v.iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    };
    let basic = token_request(
        &provider(Credential::Basic("s p".into())),
        &m,
        "c",
        "https://rp/cb",
        "ver",
        NOW,
    )
    .unwrap();
    assert_eq!(basic.url, "https://up.example/token");
    assert_eq!(
        form(&basic),
        pairs(&[
            ("grant_type", "authorization_code"),
            ("code", "c"),
            ("redirect_uri", "https://rp/cb"),
            ("code_verifier", "ver")
        ])
    );
    assert_eq!(basic.basic, Some(("abc".to_owned(), "s p".to_owned())));

    let post = token_request(
        &provider(Credential::Post("s".into())),
        &m,
        "c",
        "https://rp/cb",
        "ver",
        NOW,
    )
    .unwrap();
    assert_eq!(post.basic, None);
    assert!(post.form.contains(&("client_id".into(), "abc".into())));
    assert!(post.form.contains(&("client_secret".into(), "s".into())));

    let pkcs8 = generate_pkcs8("RS256", 2048).unwrap();
    let cert = rustid_core::keys::self_signed_certificate(
        "RS256",
        &pkcs8,
        "rustid",
        chrono::Utc::now() - chrono::Duration::days(1),
        chrono::Utc::now() + chrono::Duration::days(1),
    )
    .unwrap();
    let pk =
        LoadedKey::from_der("pk1", "RS256", &pkcs8, Some(&cert), &KeyOrigin::default()).unwrap();
    let jwt = token_request(
        &provider(Credential::PrivateKeyJwt(Arc::new(pk.clone()))),
        &m,
        "c",
        "https://rp/cb",
        "ver",
        NOW,
    )
    .unwrap();
    assert_eq!(jwt.basic, None);
    assert!(jwt.form.contains(&(
        "client_assertion_type".into(),
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into()
    )));
    let assertion = &jwt
        .form
        .iter()
        .find(|(k, _)| k == "client_assertion")
        .unwrap()
        .1;
    let jws = rustid_core::jwt::Jws::decode(assertion).unwrap();
    assert_eq!(jws.header_str("alg"), Some("RS256"));
    assert_eq!(jws.header_str("kid"), Some("pk1"));
    let thumbprint = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, &cert);
    assert_eq!(
        jws.header_str("x5t"),
        Some(b64url(thumbprint.as_ref()).as_str())
    );
    assert_eq!(jws.claim_str("iss"), Some("abc"));
    assert_eq!(jws.claim_str("sub"), Some("abc"));
    assert_eq!(jws.claim_str("aud"), Some("https://up.example/token"));
    assert_eq!(jws.claim_i64("exp"), Some(NOW + 60));
    assert!(jws.claim_str("jti").unwrap().len() >= 32);
    assert!(jws.verify(&pk.public_jwk()));
}

fn federation(fake: Arc<Fake>) -> Federation {
    Federation::new(
        Providers::new(vec![provider(Credential::Basic("s".into()))]).unwrap(),
        fake,
        false,
    )
}

#[tokio::test]
async fn redeem_happy_path() {
    let k = key("k1", "RS256");
    let fake = Fake::new(&[&k]);
    let fed = federation(fake.clone());
    let p = fed.find("up").await.unwrap().unwrap();
    let p = &*p;
    let c = Correlation::new("up", "/return", NOW);
    fake.0.lock().unwrap().token_body = json!({ "id_token": token(&k, &baseline(&c.nonce)) });
    let t = fed
        .redeem(p, "code", "https://rp/cb", &c, 300, NOW)
        .await
        .unwrap();
    assert_eq!(t.subject, "upstream-user");
    let s = fake.0.lock().unwrap();
    assert!(
        s.posts[0]
            .form
            .contains(&("code_verifier".into(), c.code_verifier.clone()))
    );
}

#[tokio::test]
async fn redeem_failures() {
    let k = key("k1", "RS256");
    let fake = Fake::new(&[&k]);
    let fed = federation(fake.clone());
    let p = fed.find("up").await.unwrap().unwrap();
    let p = &*p;
    let c = Correlation::new("up", "/return", NOW);
    fake.0.lock().unwrap().token_status = 400;
    fake.0.lock().unwrap().token_body = json!({ "error": "invalid_grant" });
    assert!(matches!(
        fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW).await,
        Err(Failure::TokenRequestFailed(_))
    ));
    fake.0.lock().unwrap().token_status = 200;
    fake.0.lock().unwrap().token_body = json!({ "access_token": "a" });
    assert!(matches!(
        fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW).await,
        Err(Failure::TokenRequestFailed(_))
    ));
    fake.0.lock().unwrap().token_body = json!({ "id_token": token(&k, &baseline("wrong")) });
    let failure = fed
        .redeem(p, "code", "https://rp/cb", &c, 300, NOW)
        .await
        .unwrap_err();
    assert_eq!(failure, Failure::IdTokenInvalid(IdTokenCheck::Nonce));
    assert_eq!(failure.reason(), "id_token_invalid");
    assert!(failure.detail().contains("nonce"));
}

#[tokio::test]
async fn unknown_keys_refetch_the_key_set_once_per_sign_in_up_to_a_limit() {
    let k1 = key("k1", "RS256");
    let fake = Fake::new(&[&k1]);
    let fed = federation(fake.clone());
    let p = fed.find("up").await.unwrap().unwrap();
    let p = &*p;
    let c = Correlation::new("up", "/return", NOW);
    let set = |t: String| fake.0.lock().unwrap().token_body = json!({ "id_token": t });

    set(token(&k1, &baseline(&c.nonce)));
    fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW)
        .await
        .unwrap();
    assert_eq!(fake.gets(JWKS), 1);

    // The provider rotates its key, seconds later: one refetch picks it up.
    let k2 = key("k2", "RS256");
    fake.0.lock().unwrap().jwks = vec![jwk(&k2)];
    set(token(&k2, &baseline(&c.nonce)));
    fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW + 5)
        .await
        .unwrap();
    assert_eq!(fake.gets(JWKS), 2);

    // A token without kid whose signature fails on the cached keys: the
    // provider may have rotated again, so one refetch.
    let k3 = key("k3", "RS256");
    fake.0.lock().unwrap().jwks = vec![jwk(&k3)];
    set(raw_token(
        Some(&k3),
        &json!({ "alg": "RS256" }),
        &baseline(&c.nonce),
    ));
    fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW + 6)
        .await
        .unwrap();
    assert_eq!(fake.gets(JWKS), 3);

    // A key the provider never publishes: one refetch per redemption, and
    // no more than JWKS_REFETCH_LIMIT in a minute.
    let limit = rustid_core::federation::flow::JWKS_REFETCH_LIMIT as i64;
    let unknown = key("k9", "RS256");
    set(token(&unknown, &baseline(&c.nonce)));
    for _ in 0..limit {
        assert_eq!(
            fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW + 10)
                .await
                .unwrap_err(),
            Failure::IdTokenInvalid(IdTokenCheck::UnknownKey)
        );
    }
    // The limit is reached (k2, the no-kid token, then limit - 2 more).
    assert_eq!(fake.gets(JWKS), 1 + limit as usize);
    // A minute after the first refetch, refetching resumes.
    assert!(
        fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW + 66)
            .await
            .is_err()
    );
    assert_eq!(fake.gets(JWKS), 2 + limit as usize);
}

#[test]
fn sign_in_session() {
    let mut payload = baseline("n");
    payload["name"] = "Ada".into();
    payload["email"] = "ada@example.com".into();
    payload["groups"] = json!(["x"]);
    let token = |p: &Value| ValidatedIdToken {
        raw: String::new(),
        issuer: AUTHORITY.into(),
        subject: "upstream-user".into(),
        payload: p.as_object().unwrap().clone(),
    };
    let s = sign_in(&config(), &token(&payload), NOW);
    assert_eq!(s.subject_id, subject_for(AUTHORITY, "upstream-user"));
    assert_eq!(s.idp.as_deref(), Some("up"));
    assert_eq!(s.amr, ["external"]);
    assert_eq!(s.auth_time, Some(NOW));
    let types: Vec<&str> = s.claims.iter().map(|c| c.claim_type.as_str()).collect();
    assert_eq!(types, ["name", "email"]);

    payload["amr"] = json!(["mfa", "pwd"]);
    payload["auth_time"] = (NOW - 50).into();
    let s = sign_in(&config(), &token(&payload), NOW);
    assert_eq!(s.amr, ["mfa", "pwd"]);
    assert_eq!(s.auth_time, Some(NOW - 50));
    payload["amr"] = json!([]);
    assert_eq!(sign_in(&config(), &token(&payload), NOW).amr, ["external"]);
}

#[test]
fn correlation_round_trip_and_authorization_url() {
    let protector = DataProtector::new([("k", [7u8; 32].as_slice())]).unwrap();
    let c = Correlation::new("up", "/connect/authorize/callback?x=1", NOW);
    assert!(c.state.len() >= 43 && c.nonce.len() >= 43 && c.code_verifier.len() >= 43);
    let sealed = c.seal(&protector);
    assert_eq!(
        Correlation::open(&protector, &sealed, NOW + 600),
        Some(c.clone())
    );
    assert_eq!(Correlation::open(&protector, &sealed, NOW + 601), None);
    assert_eq!(Correlation::open(&protector, "garbage", NOW), None);
    let expected =
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, c.code_verifier.as_bytes());
    assert_eq!(c.code_challenge(), b64url(expected.as_ref()));

    let url = authorization_url(
        &config(),
        &metadata(),
        "https://idsrv.test/federation/up/callback",
        &c,
        &[
            ("login_hint", "ada@x".into()),
            ("prompt", "login".into()),
            ("max_age", "60".into()),
        ],
    );
    assert!(url.starts_with("https://up.example/authorize?"), "{url}");
    for part in [
        "response_type=code".to_owned(),
        "client_id=abc".to_owned(),
        "redirect_uri=https%3A%2F%2Fidsrv.test%2Ffederation%2Fup%2Fcallback".to_owned(),
        "scope=openid%20profile%20email".to_owned(),
        format!("state={}", c.state),
        format!("nonce={}", c.nonce),
        format!("code_challenge={}", c.code_challenge()),
        "code_challenge_method=S256".to_owned(),
        "login_hint=ada@x".to_owned(),
        "prompt=login".to_owned(),
        "max_age=60".to_owned(),
    ] {
        assert!(url.contains(&part), "{url} lacks {part}");
    }
}

fn userinfo_federation(fake: Arc<Fake>) -> Federation {
    let mut p = provider(Credential::Basic("s".into()));
    p.config.userinfo = true;
    Federation::new(Providers::new(vec![p]).unwrap(), fake, false)
}

#[tokio::test]
async fn userinfo_is_called_only_when_enabled_and_its_sub_must_match() {
    let k = key("k1", "RS256");
    let fake = Fake::new(&[&k]);
    fake.0.lock().unwrap().discovery["userinfo_endpoint"] = "https://up.example/userinfo".into();
    let c = Correlation::new("up", "/return", NOW);
    fake.0.lock().unwrap().token_body =
        json!({ "id_token": token(&k, &baseline(&c.nonce)), "access_token": "at1" });

    // Off by default: no userinfo call.
    let fed = federation(fake.clone());
    let p = fed.find("up").await.unwrap().unwrap();
    let p = &*p;
    let t = fed
        .redeem(p, "code", "https://rp/cb", &c, 300, NOW)
        .await
        .unwrap();
    assert!(fake.0.lock().unwrap().bearer.is_empty());
    assert!(t.payload.get("email").is_none());

    // On: called with the access token; its claims join the token's, and
    // its protocol claims never replace the token's.
    let fed = userinfo_federation(fake.clone());
    let p = fed.find("up").await.unwrap().unwrap();
    let p = &*p;
    let t = fed
        .redeem(p, "code", "https://rp/cb", &c, 300, NOW)
        .await
        .unwrap();
    assert_eq!(fake.0.lock().unwrap().bearer, ["at1"]);
    assert_eq!(t.payload["email"], "ada@userinfo.example");
    assert_eq!(t.payload["iss"], AUTHORITY);

    // A different sub is refused (OIDC Core 5.3.4).
    fake.0.lock().unwrap().userinfo["sub"] = "someone-else".into();
    let failure = fed
        .redeem(p, "code", "https://rp/cb", &c, 300, NOW)
        .await
        .unwrap_err();
    assert_eq!(failure.reason(), "userinfo_failed");
    assert!(failure.detail().contains("sub"), "{}", failure.detail());

    // No access token, or no userinfo endpoint: refused.
    fake.0.lock().unwrap().userinfo["sub"] = "upstream-user".into();
    fake.0.lock().unwrap().token_body = json!({ "id_token": token(&k, &baseline(&c.nonce)) });
    assert_eq!(
        fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW)
            .await
            .unwrap_err()
            .reason(),
        "userinfo_failed"
    );
}

#[test]
fn metadata_userinfo_endpoint_must_be_https() {
    let mut m = metadata();
    m.userinfo_endpoint = Some("http://up.example/userinfo".into());
    assert!(m.check(AUTHORITY, false, false).is_err());
    m.userinfo_endpoint = Some("https://up.example/userinfo".into());
    m.check(AUTHORITY, false, false).unwrap();
}

#[test]
fn sign_out_flag_signout_correlation_and_end_session_url() {
    use rustid_core::federation::challenge::{SignoutCorrelation, end_session_url};
    assert!(!config().sign_out);
    let mut cfg = config();
    cfg.sign_out = true;
    let protector = DataProtector::new([("k", [7u8; 32].as_slice())]).unwrap();
    let c = SignoutCorrelation::new("up", "handle-1", NOW);
    assert!(c.state.len() >= 43);
    assert_eq!(c.handle, "handle-1");
    let sealed = c.seal(&protector);
    assert_eq!(
        SignoutCorrelation::open(&protector, &sealed, NOW + 600),
        Some(c.clone())
    );
    assert_eq!(
        SignoutCorrelation::open(&protector, &sealed, NOW + 601),
        None
    );
    assert_eq!(SignoutCorrelation::open(&protector, "garbage", NOW), None);
    // A correlation sealed for sign-in doesn't open as a sign-out one.
    let sign_in = Correlation::new("up", "/r", NOW).seal(&protector);
    assert_eq!(SignoutCorrelation::open(&protector, &sign_in, NOW), None);

    let mut m = metadata();
    assert_eq!(
        end_session_url(&cfg, &m, Some("t.o.k"), "https://rp/so", "st"),
        None
    );
    m.end_session_endpoint = Some("https://up.example/endsession?x=1".into());
    let url = end_session_url(&cfg, &m, Some("t.o.k"), "https://rp/so", "st").unwrap();
    assert_eq!(
        url,
        "https://up.example/endsession?x=1&id_token_hint=t.o.k&client_id=abc&post_logout_redirect_uri=https%3A%2F%2Frp%2Fso&state=st"
    );
    let url = end_session_url(&cfg, &m, None, "https://rp/so", "st").unwrap();
    assert!(!url.contains("id_token_hint"), "{url}");
}

#[tokio::test]
async fn redeemed_tokens_keep_their_compact_form() {
    let k = key("k1", "RS256");
    let fake = Fake::new(&[&k]);
    let fed = federation(fake.clone());
    let p = fed.find("up").await.unwrap().unwrap();
    let p = &*p;
    let c = Correlation::new("up", "/return", NOW);
    let t = token(&k, &baseline(&c.nonce));
    fake.0.lock().unwrap().token_body = json!({ "id_token": t });
    assert_eq!(
        fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW)
            .await
            .unwrap()
            .raw,
        t
    );
}

#[test]
fn sessions_carry_the_upstream_id_token_only_when_set() {
    use rustid_core::session::{SignIn, UserSession};
    let protector = DataProtector::new([("k", [7u8; 32].as_slice())]).unwrap();
    let now = chrono::Utc::now();
    let with = UserSession::sign_in(
        SignIn {
            subject_id: "s".into(),
            upstream_id_token: Some("a.b.c".into()),
            ..Default::default()
        },
        None,
        now,
        3600,
    );
    assert_eq!(with.upstream_id_token.as_deref(), Some("a.b.c"));
    let opened = UserSession::open(&protector, &with.seal(&protector), now).unwrap();
    assert_eq!(opened.upstream_id_token.as_deref(), Some("a.b.c"));
    let without = UserSession::sign_in(
        SignIn {
            subject_id: "s".into(),
            ..Default::default()
        },
        None,
        now,
        3600,
    );
    let json = serde_json::to_value(&without).unwrap();
    assert!(json.get("upstream_id_token").is_none(), "{json}");
}

#[tokio::test]
async fn signout_return_urls_are_kept_server_side_and_taken_once() {
    use rustid_core::federation::challenge::{store_signout_return, take_signout_return};
    let stores = rustid_store_memory::stores(Default::default(), Default::default());
    let grants = stores.grants.as_ref();
    let now = chrono::Utc::now();
    let long = format!("/signed-out?logoutId={}", "x".repeat(6000));
    let handle = store_signout_return(grants, &long, now).await.unwrap();
    assert!(handle.len() < 100, "a short handle");
    assert_eq!(
        take_signout_return(grants, &handle, now)
            .await
            .unwrap()
            .as_deref(),
        Some(long.as_str())
    );
    assert_eq!(
        take_signout_return(grants, &handle, now).await.unwrap(),
        None,
        "once"
    );
    let handle = store_signout_return(grants, "/x", now).await.unwrap();
    let later = now + chrono::Duration::seconds(601);
    assert_eq!(
        take_signout_return(grants, &handle, later).await.unwrap(),
        None,
        "expired"
    );
}

#[test]
fn metadata_end_session_endpoint_must_be_https() {
    let mut m = metadata();
    m.end_session_endpoint = Some("http://up.example/endsession".into());
    assert!(m.check(AUTHORITY, false, false).is_err());
}

const TENANT_A: &str = "11111111-1111-1111-1111-111111111111";
const TENANT_B: &str = "22222222-2222-2222-2222-222222222222";

fn multi_tenant_federation(fake: Arc<Fake>, tenants: &[&str]) -> Federation {
    let mut config: IdentityProvider = serde_json::from_value(json!({
        "scheme": "entra", "displayName": "Entra", "authority": "https://up.example/organizations/v2.0",
        "clientId": "abc", "clientAuthentication": { "secret": "s" },
        "multiTenant": { "tenants": tenants },
    }))
    .unwrap();
    config.validate(false).unwrap();
    config.scheme = "up".into();
    fake.0.lock().unwrap().discovery["issuer"] = "https://up.example/{tenantid}/v2.0".into();
    Federation::new(
        Providers::new(vec![Provider {
            config,
            credential: Credential::Basic("s".into()),
        }])
        .unwrap(),
        fake,
        false,
    )
}

fn tenant_token(k: &LoadedKey, nonce: &str, tid: Option<&str>, iss_tenant: &str) -> String {
    let mut p = baseline(nonce);
    p["iss"] = format!("https://up.example/{iss_tenant}/v2.0").into();
    if let Some(tid) = tid {
        p["tid"] = tid.into();
    }
    token(k, &p)
}

#[tokio::test]
async fn multi_tenant_providers_check_the_tenant_and_its_issuer() {
    let k = key("k1", "RS256");
    let fake = Fake::new(&[&k]);
    let fed = multi_tenant_federation(fake.clone(), &[TENANT_A]);
    let p = fed.find("up").await.unwrap().unwrap();
    let p = &*p;
    let c = Correlation::new("up", "/return", NOW);
    let set = |t: String| fake.0.lock().unwrap().token_body = json!({ "id_token": t });

    set(tenant_token(&k, &c.nonce, Some(TENANT_A), TENANT_A));
    let t = fed
        .redeem(p, "code", "https://rp/cb", &c, 300, NOW)
        .await
        .unwrap();
    assert_eq!(t.issuer, format!("https://up.example/{TENANT_A}/v2.0"));
    assert_eq!(
        sign_in(&p.config, &t, NOW).subject_id,
        subject_for(
            &format!("https://up.example/{TENANT_A}/v2.0"),
            "upstream-user"
        )
    );

    set(tenant_token(&k, &c.nonce, Some(TENANT_B), TENANT_B));
    let failure = fed
        .redeem(p, "code", "https://rp/cb", &c, 300, NOW)
        .await
        .unwrap_err();
    assert_eq!(failure.reason(), "tenant_not_allowed");
    assert!(failure.detail().contains(TENANT_B), "{}", failure.detail());

    set(tenant_token(&k, &c.nonce, None, TENANT_A));
    assert_eq!(
        fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW)
            .await
            .unwrap_err()
            .reason(),
        "tenant_not_allowed"
    );

    // The tid is allowed, but the issuer names another tenant.
    set(tenant_token(&k, &c.nonce, Some(TENANT_A), TENANT_B));
    assert_eq!(
        fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW)
            .await
            .unwrap_err(),
        Failure::IdTokenInvalid(IdTokenCheck::Issuer)
    );
}

#[tokio::test]
async fn tenant_ids_compare_without_case() {
    let k = key("k1", "RS256");
    let fake = Fake::new(&[&k]);
    let upper = "AAAAAAAA-1111-1111-1111-111111111111";
    let lower = upper.to_lowercase();
    let fed = multi_tenant_federation(fake.clone(), &[upper]);
    let p = fed.find("up").await.unwrap().unwrap();
    let p = &*p;
    let c = Correlation::new("up", "/return", NOW);
    fake.0.lock().unwrap().token_body =
        json!({ "id_token": tenant_token(&k, &c.nonce, Some(&lower), &lower) });
    fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW)
        .await
        .unwrap();
}

#[test]
fn the_tenant_template_is_accepted_only_for_multi_tenant_providers() {
    let mut m = metadata();
    m.issuer = "https://up.example/{tenantid}/v2.0".into();
    let authority = "https://up.example/organizations/v2.0";
    m.check(authority, false, true).unwrap();
    assert!(
        m.check(authority, false, false).is_err(),
        "single tenant: exact match"
    );
    // More than one segment differs.
    m.issuer = "https://up.example/{tenantid}/v3.0".into();
    assert!(m.check(authority, false, true).is_err());
    // No template at all.
    m.issuer = authority.into();
    assert!(m.check(authority, false, true).is_err());
    m.issuer = "https://other.example/{tenantid}/v2.0".into();
    assert!(m.check(authority, false, true).is_err());
}

fn logout_claims() -> Value {
    json!({
        "iss": AUTHORITY, "aud": "abc", "iat": NOW, "jti": "jti-1",
        "sub": "upstream-user", "sid": "upstream-sid",
        "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
    })
}

#[tokio::test]
async fn logout_tokens_are_checked_as_back_channel_logout_requires() {
    use rustid_core::federation::logout::LogoutTokenCheck;
    use rustid_core::replay::InMemoryReplayCache;
    let k = key("k1", "RS256");
    let fake = Fake::new(&[&k]);
    let fed = federation(fake.clone());
    let p = fed.find("up").await.unwrap().unwrap();
    let replay = InMemoryReplayCache::default();
    let ok = verify(&fed, &p, token(&k, &logout_claims()), &replay)
        .await
        .unwrap();
    assert_eq!(ok.sub.as_deref(), Some("upstream-user"));
    assert_eq!(ok.sid.as_deref(), Some("upstream-sid"));
    assert_eq!(ok.issuer, AUTHORITY);
    // The same jti again: a replay.
    assert_eq!(
        verify(&fed, &p, token(&k, &logout_claims()), &replay)
            .await
            .unwrap_err()
            .check(),
        Some(LogoutTokenCheck::Replayed)
    );
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut c = logout_claims();
        c["jti"] = format!("jti-{}", rand_suffix()).into();
        edit(&mut c);
        token(&k, &c)
    };
    for (edit, expected) in [
        (
            Box::new(|c: &mut Value| c["iss"] = "https://evil".into()) as Box<dyn Fn(&mut Value)>,
            LogoutTokenCheck::Issuer,
        ),
        (
            Box::new(|c: &mut Value| c["aud"] = "other".into()),
            LogoutTokenCheck::Audience,
        ),
        (
            Box::new(|c: &mut Value| {
                c.as_object_mut().unwrap().remove("iat");
            }),
            LogoutTokenCheck::IssuedAt,
        ),
        (
            Box::new(|c: &mut Value| c["iat"] = (NOW + 301).into()),
            LogoutTokenCheck::IssuedAt,
        ),
        (
            Box::new(|c: &mut Value| c["exp"] = (NOW - 301).into()),
            LogoutTokenCheck::Expired,
        ),
        (
            Box::new(|c: &mut Value| {
                c.as_object_mut().unwrap().remove("jti");
            }),
            LogoutTokenCheck::Jti,
        ),
        (
            Box::new(|c: &mut Value| {
                c.as_object_mut().unwrap().remove("events");
            }),
            LogoutTokenCheck::Events,
        ),
        (
            Box::new(|c: &mut Value| {
                c["events"] = json!({ "http://schemas.openid.net/event/backchannel-logout": "x" })
            }),
            LogoutTokenCheck::Events,
        ),
        (
            Box::new(|c: &mut Value| {
                let o = c.as_object_mut().unwrap();
                o.remove("sub");
                o.remove("sid");
            }),
            LogoutTokenCheck::SubjectOrSession,
        ),
        (
            Box::new(|c: &mut Value| c["nonce"] = "n".into()),
            LogoutTokenCheck::Nonce,
        ),
    ] {
        assert_eq!(
            verify(&fed, &p, with(&*edit), &replay)
                .await
                .unwrap_err()
                .check(),
            Some(expected)
        );
    }
    // sid alone, or sub alone, is enough.
    verify(
        &fed,
        &p,
        with(&|c| {
            c.as_object_mut().unwrap().remove("sub");
        }),
        &replay,
    )
    .await
    .unwrap();
    verify(
        &fed,
        &p,
        with(&|c| {
            c.as_object_mut().unwrap().remove("sid");
        }),
        &replay,
    )
    .await
    .unwrap();
    // alg none and a symmetric algorithm are refused.
    let none = raw_token(None, &json!({ "alg": "none" }), &logout_claims());
    assert_eq!(
        verify(&fed, &p, none, &replay).await.unwrap_err().check(),
        Some(LogoutTokenCheck::Algorithm)
    );
    // A key rotated in since: refetched once.
    let k2 = key("k2", "RS256");
    fake.0.lock().unwrap().jwks.push(jwk(&k2));
    let before = fake.gets(JWKS);
    let mut c = logout_claims();
    c["jti"] = "jti-rotated".into();
    verify(&fed, &p, token(&k2, &c), &replay).await.unwrap();
    assert_eq!(fake.gets(JWKS), before + 1);
    // Known now: no further fetch.
    c["jti"] = "jti-rotated-2".into();
    verify(&fed, &p, token(&k2, &c), &replay).await.unwrap();
    assert_eq!(fake.gets(JWKS), before + 1);
}

async fn verify(
    fed: &Federation,
    p: &Provider,
    token: String,
    replay: &dyn rustid_core::replay::ReplayCache,
) -> Result<
    rustid_core::federation::logout::LogoutToken,
    rustid_core::federation::flow::LogoutFailure,
> {
    fed.verify_logout_token(p, &token, replay, 300, NOW).await
}

fn rand_suffix() -> String {
    rustid_core::federation::challenge::random_value()
}

#[test]
fn sign_in_keeps_the_upstream_session_id() {
    let mut payload = baseline("n");
    payload["sid"] = "upstream-sid".into();
    let token = ValidatedIdToken {
        raw: String::new(),
        issuer: AUTHORITY.into(),
        subject: "upstream-user".into(),
        payload: payload.as_object().unwrap().clone(),
    };
    assert_eq!(
        sign_in(&config(), &token, NOW).upstream_sid.as_deref(),
        Some("upstream-sid")
    );
}

#[tokio::test]
async fn a_registered_id_token_algorithm_is_the_only_one_accepted() {
    use rustid_core::federation::logout::LogoutTokenCheck;
    use rustid_core::replay::InMemoryReplayCache;
    let rs = key("k1", "RS256");
    let es = key("k2", "ES256");
    let fake = Fake::new(&[&rs, &es]);
    fake.0.lock().unwrap().discovery["id_token_signing_alg_values_supported"] =
        json!(["RS256", "ES256"]);
    let replay = InMemoryReplayCache::default();
    let fresh = || {
        let mut c = logout_claims();
        c["jti"] = format!("jti-{}", rand_suffix()).into();
        c
    };

    // Without the setting, anything asymmetric the provider advertises.
    let fed = federation(fake.clone());
    let p = fed.find("up").await.unwrap().unwrap();
    assert!(
        verify(&fed, &p, token(&es, &fresh()), &replay)
            .await
            .is_ok()
    );

    // With it, only the registered algorithm, for logout and id tokens.
    let mut pinned = provider(Credential::Basic("s".into()));
    pinned.config.id_token_signed_response_alg = Some("RS256".into());
    let fed = Federation::new(Providers::new(vec![pinned]).unwrap(), fake.clone(), false);
    let p = fed.find("up").await.unwrap().unwrap();
    assert_eq!(
        verify(&fed, &p, token(&es, &fresh()), &replay)
            .await
            .unwrap_err()
            .check(),
        Some(LogoutTokenCheck::Algorithm)
    );
    assert!(
        verify(&fed, &p, token(&rs, &fresh()), &replay)
            .await
            .is_ok()
    );
    let c = Correlation::new("up", "/return", NOW);
    fake.0.lock().unwrap().token_body = json!({ "id_token": token(&es, &baseline(&c.nonce)) });
    assert_eq!(
        fed.redeem(&p, "code", "https://rp/cb", &c, 300, NOW)
            .await
            .unwrap_err(),
        Failure::IdTokenInvalid(IdTokenCheck::Algorithm)
    );
}

#[test]
fn a_registered_id_token_algorithm_must_be_asymmetric() {
    let mut c = config();
    c.id_token_signed_response_alg = Some("HS256".into());
    assert!(c.validate(false).is_err());
    c.id_token_signed_response_alg = Some("ES256".into());
    assert!(c.validate(false).is_ok());
}

#[tokio::test]
async fn logout_tokens_older_than_the_replay_window_are_refused() {
    use rustid_core::federation::logout::LogoutTokenCheck;
    use rustid_core::replay::InMemoryReplayCache;
    let k = key("k1", "RS256");
    let fed = federation(Fake::new(&[&k]));
    let p = fed.find("up").await.unwrap().unwrap();
    let replay = InMemoryReplayCache::default();
    // The skew is 300: a token issued 601 seconds ago is past the 300
    // second window and the skew, with or without a far `exp`.
    for exp in [None, Some(NOW + 86_400)] {
        let mut c = logout_claims();
        c["jti"] = format!("jti-{}", rand_suffix()).into();
        c["iat"] = (NOW - 601).into();
        if let Some(exp) = exp {
            c["exp"] = exp.into();
        }
        assert_eq!(
            verify(&fed, &p, token(&k, &c), &replay)
                .await
                .unwrap_err()
                .check(),
            Some(LogoutTokenCheck::IssuedAt)
        );
    }
    let mut c = logout_claims();
    c["jti"] = format!("jti-{}", rand_suffix()).into();
    c["iat"] = (NOW - 599).into();
    assert!(verify(&fed, &p, token(&k, &c), &replay).await.is_ok());
}

struct DownReplay;

#[async_trait::async_trait]
impl rustid_core::replay::ReplayCache for DownReplay {
    async fn add_if_absent(
        &self,
        _: &str,
        _: &str,
        _: i64,
        _: i64,
    ) -> Result<bool, rustid_core::stores::StoreError> {
        Err(rustid_core::stores::StoreError::Backend("down".into()))
    }
    async fn remove_expired(
        &self,
        _: i64,
        _: usize,
    ) -> Result<u64, rustid_core::stores::StoreError> {
        Err(rustid_core::stores::StoreError::Backend("down".into()))
    }
    async fn remove(&self, _: &str, _: &str) -> Result<(), rustid_core::stores::StoreError> {
        Err(rustid_core::stores::StoreError::Backend("down".into()))
    }
}

#[tokio::test]
async fn a_failing_replay_cache_is_its_own_failure() {
    use rustid_core::federation::flow::LogoutFailure;
    let k = key("k1", "RS256");
    let fed = federation(Fake::new(&[&k]));
    let p = fed.find("up").await.unwrap().unwrap();
    let failure = verify(&fed, &p, token(&k, &logout_claims()), &DownReplay)
        .await
        .unwrap_err();
    assert!(
        matches!(failure, LogoutFailure::ReplayUnavailable(_)),
        "{failure:?}"
    );
    assert_eq!(failure.reason(), "replay_unavailable");
    assert_eq!(failure.check(), None);
}
