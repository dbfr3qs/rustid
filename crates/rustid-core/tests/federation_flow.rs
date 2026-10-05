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
            DISCOVERY => Ok(s.discovery.clone()),
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
    let p = fed.providers.find("up").unwrap();
    match fed.metadata(p, NOW).await.unwrap_err() {
        Failure::MetadataUnavailable(detail) => assert!(detail.contains("issuer"), "{detail}"),
        other => panic!("{other:?}"),
    }
    fake.0.lock().unwrap().discovery = discovery();
    fed.metadata(p, NOW + 1).await.unwrap();
    fed.metadata(p, NOW + 2).await.unwrap();
    assert_eq!(fake.gets(DISCOVERY), 2, "one failed, one cached");
    fed.metadata(p, NOW + 1 + 86_401).await.unwrap();
    assert_eq!(fake.gets(DISCOVERY), 3);
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
    let p = fed.providers.find("up").unwrap();
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
fn no_kid_uses_the_only_suitable_key() {
    let k = key("k1", "RS256");
    let rs256 = vec!["RS256".to_owned()];
    let t = raw_token(Some(&k), &json!({ "alg": "RS256" }), &baseline("n1"));
    validate(&t, &[k.public_jwk()], &expect(&rs256, "n1")).unwrap();
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
    let p = fed.providers.find("up").unwrap();
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
    let p = fed.providers.find("up").unwrap();
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
async fn unknown_kid_refetches_once_per_minute() {
    let k1 = key("k1", "RS256");
    let k2 = key("k2", "RS256");
    let k3 = key("k3", "RS256");
    let fake = Fake::new(&[&k1]);
    let fed = federation(fake.clone());
    let p = fed.providers.find("up").unwrap();
    let c = Correlation::new("up", "/return", NOW);
    let set = |k: &LoadedKey| {
        fake.0.lock().unwrap().token_body = json!({ "id_token": token(k, &baseline(&c.nonce)) })
    };

    set(&k1);
    fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW)
        .await
        .unwrap();
    assert_eq!(fake.gets(JWKS), 1);

    // The upstream rotates to k2: one refetch picks it up.
    fake.0.lock().unwrap().jwks.push(jwk(&k2));
    set(&k2);
    fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW + 120)
        .await
        .unwrap();
    assert_eq!(fake.gets(JWKS), 2);

    // An unknown key within a minute of that refetch: no new GET.
    set(&k3);
    assert_eq!(
        fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW + 150)
            .await
            .unwrap_err(),
        Failure::IdTokenInvalid(IdTokenCheck::UnknownKey)
    );
    assert_eq!(fake.gets(JWKS), 2);
    // A minute later it refetches (and still doesn't know the key).
    assert!(
        fed.redeem(p, "code", "https://rp/cb", &c, 300, NOW + 181)
            .await
            .is_err()
    );
    assert_eq!(fake.gets(JWKS), 3);
}

#[test]
fn sign_in_session() {
    let mut payload = baseline("n");
    payload["name"] = "Ada".into();
    payload["email"] = "ada@example.com".into();
    payload["groups"] = json!(["x"]);
    let token = |p: &Value| ValidatedIdToken {
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
    let p = fed.providers.find("up").unwrap();
    let t = fed
        .redeem(p, "code", "https://rp/cb", &c, 300, NOW)
        .await
        .unwrap();
    assert!(fake.0.lock().unwrap().bearer.is_empty());
    assert!(t.payload.get("email").is_none());

    // On: called with the access token; its claims join the token's, and
    // its protocol claims never replace the token's.
    let fed = userinfo_federation(fake.clone());
    let p = fed.providers.find("up").unwrap();
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
    assert!(m.check(AUTHORITY, false).is_err());
    m.userinfo_endpoint = Some("https://up.example/userinfo".into());
    m.check(AUTHORITY, false).unwrap();
}
