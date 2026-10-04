//! The password and extension grants at the token endpoint
//! (validate resource owner credential request,
//! validate extension grant request) with a scripted validator in the
//! validate extension grant request) with a scripted validator.

mod support;

use std::sync::{Arc, Mutex};

use chrono::Utc;
use rustid_core::clients::{AccessTokenType, Client};
use rustid_core::form::Form;
use rustid_core::grant_validation::{
    ExtensionRequest, GrantAnswer, GrantResult, GrantSubject, GrantValidator, PasswordRequest,
    RequestChanges,
};
use rustid_core::jwt::Jws;
use rustid_core::profile::ProfileError;
use rustid_core::token::{TokenFailure, TokenResponse, process};
use rustid_core::tokens::Claim;
use serde_json::{Map, Value, json};
use support::Fixture;

/// What the validator was asked, for checking what it may see.
#[derive(Default)]
struct Scripted {
    seen: Mutex<Vec<Vec<(String, String)>>>,
}

fn answer(result: GrantResult) -> GrantAnswer {
    GrantAnswer {
        result,
        custom: Map::new(),
        changes: RequestChanges::default(),
    }
}

fn subject(sub: &str, amr: &str, claims: Vec<Claim>) -> GrantResult {
    GrantResult::Subject(GrantSubject {
        subject_id: sub.into(),
        authentication_method: amr.into(),
        idp: None,
        claims,
    })
}

fn get<'a>(parameters: &'a [(String, String)], name: &str) -> Option<&'a str> {
    parameters
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[async_trait::async_trait]
impl GrantValidator for Scripted {
    fn supports_password(&self) -> bool {
        true
    }

    fn extension_grant_types(&self) -> Vec<String> {
        vec!["custom".into(), "custom.nosubject".into(), "dynamic".into()]
    }

    /// The test user resource owner password validator over bob/bob and an
    /// inactive user, plus the custom-response validator's shape.
    async fn validate_password(
        &self,
        r: &PasswordRequest<'_>,
    ) -> Result<GrantAnswer, ProfileError> {
        self.seen.lock().unwrap().push(r.parameters.to_vec());
        Ok(match (r.username, r.password) {
            ("bob", "bob") | ("inactive", "inactive") => answer(subject(
                r.username,
                "pwd",
                vec![Claim::string("name", "Bob Smith")],
            )),
            ("custom", _) => GrantAnswer {
                result: GrantResult::Error {
                    error: None,
                    description: None,
                },
                custom: [("int_value".to_owned(), json!(42))].into_iter().collect(),
                changes: RequestChanges::default(),
            },
            _ => answer(GrantResult::Error {
                error: Some("invalid_grant".into()),
                description: Some("invalid_credential".into()),
            }),
        })
    }

    async fn validate_extension(
        &self,
        r: &ExtensionRequest<'_>,
    ) -> Result<GrantAnswer, ProfileError> {
        self.seen.lock().unwrap().push(r.parameters.to_vec());
        let p = r.parameters;
        Ok(match r.grant_type {
            // A validator that throws.
            "dynamic" if get(p, "lifetime").is_some_and(|l| l.parse::<i64>().is_err()) => {
                return Err(ProfileError("lifetime is not a number".into()));
            }
            "custom" if get(p, "custom_credential").is_some() => {
                let claims = get(p, "extra_claim")
                    .map(|c| vec![Claim::string("extra_claim", c)])
                    .unwrap_or_default();
                answer(subject("818727", "custom", claims))
            }
            "custom.nosubject" if get(p, "custom_credential").is_some() => {
                answer(GrantResult::NoSubject)
            }
            "dynamic" => GrantAnswer {
                result: match get(p, "sub") {
                    Some(sub) => subject(sub, "delegation", Vec::new()),
                    None => GrantResult::NoSubject,
                },
                custom: Map::new(),
                changes: RequestChanges {
                    client_id: get(p, "impersonated_client").map(str::to_owned),
                    access_token_lifetime: get(p, "lifetime").and_then(|l| l.parse().ok()),
                    access_token_type: match get(p, "type") {
                        Some("reference") => Some(AccessTokenType::Reference),
                        Some("jwt") => Some(AccessTokenType::Jwt),
                        _ => None,
                    },
                    client_claims: get(p, "claim")
                        .map(|c| vec![Claim::string("extra", c)])
                        .unwrap_or_default(),
                },
            },
            _ => answer(GrantResult::Error {
                error: Some("invalid_grant".into()),
                description: Some("invalid custom credential".into()),
            }),
        })
    }
}

/// Refuses the subject `inactive`.
struct InactiveProfile;

#[async_trait::async_trait]
impl rustid_core::profile::ProfileService for InactiveProfile {
    async fn profile_claims(
        &self,
        r: &rustid_core::profile::ProfileRequest<'_>,
    ) -> Result<Vec<Claim>, ProfileError> {
        rustid_core::profile::DefaultProfileService
            .profile_claims(r)
            .await
    }

    async fn is_active(
        &self,
        r: &rustid_core::profile::ActiveRequest<'_>,
    ) -> Result<bool, ProfileError> {
        Ok(r.subject_id != "inactive")
    }
}

fn client(value: Value) -> Client {
    serde_json::from_value(value).unwrap()
}

const SECRET: &str = "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=";

fn setup() -> (Fixture, Arc<Scripted>) {
    let mut f = Fixture::new();
    f.edit_clients(|clients| {
        clients.push(client(json!({
            "clientId": "roclient",
            "clientSecrets": [{ "value": SECRET }],
            "allowedGrantTypes": ["password"],
            "allowOfflineAccess": true,
            "allowedScopes": ["openid", "profile", "api1", "api2"],
        })));
        clients.push(client(json!({
            "clientId": "client.custom",
            "clientSecrets": [{ "value": SECRET }],
            "allowedGrantTypes": ["custom", "custom.nosubject"],
            "allowedScopes": ["api1", "api2"],
            "allowOfflineAccess": true,
        })));
        clients.push(client(json!({
            "clientId": "client.dynamic",
            "clientSecrets": [{ "value": SECRET }],
            "allowedGrantTypes": ["dynamic"],
            "allowedScopes": ["api1", "api2"],
            "alwaysSendClientClaims": true,
        })));
    });
    let scripted = Arc::new(Scripted::default());
    f.stores.grant_validation = scripted.clone();
    f.stores.profile = Arc::new(InactiveProfile);
    (f, scripted)
}

async fn token(f: &Fixture, pairs: &[(&str, &str)]) -> Result<TokenResponse, TokenFailure> {
    process(&f.ctx(Utc::now()), None, &Form::from_pairs(pairs)).await
}

fn claims(response: &TokenResponse) -> Map<String, Value> {
    Jws::decode(&response.access_token).unwrap().payload
}

fn failure(
    result: Result<TokenResponse, TokenFailure>,
) -> (String, Option<String>, Map<String, Value>) {
    match result {
        Err(TokenFailure::Protocol(e)) => (e.error.into_owned(), e.description, e.custom),
        other => panic!("expected an error, got {other:?}"),
    }
}

fn ro<'a>(username: &'a str, password: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("grant_type", "password"),
        ("client_id", "roclient"),
        ("client_secret", "secret"),
        ("username", username),
        ("password", password),
    ]
}

#[tokio::test]
async fn the_password_grant_issues_a_user_token_without_an_id_token() {
    let (f, scripted) = setup();
    let r = token(&f, &ro("bob", "bob")).await.unwrap();
    assert!(r.id_token.is_none());
    assert!(
        r.refresh_token.is_some(),
        "offline_access is among the defaults"
    );
    assert_eq!(
        r.scope, "api1 api2 offline_access openid profile",
        "sorted, as ParseScopesString"
    );
    let c = claims(&r);
    assert_eq!(c["sub"], "1".replace('1', "bob"));
    assert_eq!(c["amr"], json!(["pwd"]));
    assert_eq!(c["idp"], "local");
    assert!(c["auth_time"].is_i64());
    assert!(c.get("sid").is_none());
    // The password never reaches the validator's parameters.
    let seen = scripted.seen.lock().unwrap().clone();
    assert!(
        seen[0]
            .iter()
            .all(|(k, _)| k != "password" && k != "client_secret")
    );

    // Its refresh token refreshes.
    let rt = r.refresh_token.unwrap();
    let refreshed = token(
        &f,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", "roclient"),
            ("client_secret", "secret"),
            ("refresh_token", &rt),
        ],
    )
    .await
    .unwrap();
    assert_eq!(claims(&refreshed)["sub"], "bob");
}

#[tokio::test]
async fn password_grant_failures() {
    let (f, _) = setup();
    assert_eq!(
        failure(token(&f, &ro("bob", "wrong")).await).0,
        "invalid_grant"
    );
    let (error, description, _) = failure(token(&f, &ro("bob", "wrong")).await);
    assert_eq!(
        (error.as_str(), description.as_deref()),
        ("invalid_grant", Some("invalid_credential"))
    );
    // No error from the validator: invalid_grant with the default description
    // and its custom response.
    let (error, description, custom) = failure(token(&f, &ro("custom", "x")).await);
    assert_eq!(
        (
            error.as_str(),
            description.as_deref(),
            custom.get("int_value")
        ),
        (
            "invalid_grant",
            Some("invalid_username_or_password"),
            Some(&json!(42))
        )
    );
    // An inactive user.
    assert_eq!(
        failure(token(&f, &ro("inactive", "inactive")).await).0,
        "invalid_grant"
    );
    // No username.
    let mut no_user = ro("", "x");
    no_user.retain(|(k, _)| *k != "username");
    assert_eq!(failure(token(&f, &no_user).await).0, "invalid_grant");
    // A client without the grant.
    let mut other = ro("bob", "bob");
    other[1] = ("client_id", "client.custom");
    assert_eq!(failure(token(&f, &other).await).0, "unauthorized_client");
}

fn ext<'a>(
    client: &'a str,
    grant: &'a str,
    extra: &[(&'a str, &'a str)],
) -> Vec<(&'a str, &'a str)> {
    let mut v = vec![
        ("grant_type", grant),
        ("client_id", client),
        ("client_secret", "secret"),
    ];
    v.extend_from_slice(extra);
    v
}

#[tokio::test]
async fn extension_grants_with_and_without_a_subject() {
    let (f, _) = setup();
    let r = token(
        &f,
        &ext(
            "client.custom",
            "custom",
            &[
                ("custom_credential", "x"),
                ("extra_claim", "e"),
                ("scope", "api1"),
            ],
        ),
    )
    .await
    .unwrap();
    let c = claims(&r);
    assert_eq!(
        (c["sub"].as_str(), c["amr"].clone()),
        (Some("818727"), json!(["custom"]))
    );
    assert!(r.refresh_token.is_none(), "offline_access not requested");
    // Default scopes include offline_access: a refresh token.
    let r = token(
        &f,
        &ext("client.custom", "custom", &[("custom_credential", "x")]),
    )
    .await
    .unwrap();
    assert_eq!(r.scope, "api1 api2 offline_access");
    assert!(r.refresh_token.is_some());

    let r = token(
        &f,
        &ext(
            "client.custom",
            "custom.nosubject",
            &[("custom_credential", "x"), ("scope", "api1")],
        ),
    )
    .await
    .unwrap();
    assert!(claims(&r).get("sub").is_none());
    assert_eq!(claims(&r)["client_id"], "client.custom");

    // Offline_access without a subject: a refresh token,
    // whose access token has no offline_access scope; redeeming it is
    // refused (an unhandled failure).
    let r = token(
        &f,
        &ext(
            "client.custom",
            "custom.nosubject",
            &[("custom_credential", "x"), ("scope", "api1 offline_access")],
        ),
    )
    .await
    .unwrap();
    assert_eq!(r.scope, "api1 offline_access");
    assert_eq!(claims(&r)["scope"], json!(["api1"]));
    let handle = r.refresh_token.expect("a refresh token");
    let refresh = [
        ("grant_type", "refresh_token"),
        ("client_id", "client.custom"),
        ("client_secret", "secret"),
        ("refresh_token", handle.as_str()),
    ];
    assert_eq!(failure(token(&f, &refresh).await).0, "invalid_grant");

    let (error, description, _) = failure(token(&f, &ext("client.custom", "custom", &[])).await);
    assert_eq!(
        (error.as_str(), description.as_deref()),
        ("invalid_grant", Some("invalid custom credential"))
    );
    assert_eq!(
        failure(token(&f, &ext("client.custom", "unknown", &[])).await).0,
        "unsupported_grant_type"
    );
    assert_eq!(
        failure(token(&f, &ext("client.custom", "dynamic", &[])).await).0,
        "unsupported_grant_type",
        "a grant type the client isn't allowed"
    );
}

#[tokio::test]
async fn extension_grants_may_change_the_request() {
    let (f, _) = setup();
    let r = token(
        &f,
        &ext(
            "client.dynamic",
            "dynamic",
            &[("lifetime", "5000"), ("sub", "88421113"), ("claim", "x")],
        ),
    )
    .await
    .unwrap();
    assert_eq!(r.expires_in, 5000);
    let c = claims(&r);
    assert_eq!(
        c["exp"].as_i64().unwrap() - c["iat"].as_i64().unwrap(),
        5000
    );
    assert_eq!(c["sub"], "88421113");
    assert_eq!(
        c["client_extra"], "x",
        "client claims carry the client prefix"
    );

    let r = token(
        &f,
        &ext(
            "client.dynamic",
            "dynamic",
            &[("impersonated_client", "impersonated")],
        ),
    )
    .await
    .unwrap();
    assert_eq!(claims(&r)["client_id"], "impersonated");

    let r = token(
        &f,
        &ext("client.dynamic", "dynamic", &[("type", "reference")]),
    )
    .await
    .unwrap();
    assert!(!r.access_token.contains('.'), "a reference token");
}

#[tokio::test]
async fn an_impersonated_token_belongs_to_the_requesting_client() {
    let (f, _) = setup();
    for sub in [Some("88421113"), None] {
        let mut extra = vec![
            ("type", "reference"),
            ("impersonated_client", "impersonated"),
        ];
        extra.extend(sub.map(|s| ("sub", s)));
        let r = token(&f, &ext("client.dynamic", "dynamic", &extra))
            .await
            .unwrap();
        let stored = rustid_core::reference_tokens::get(f.stores.grants.as_ref(), &r.access_token)
            .await
            .unwrap()
            .expect("a stored reference token");
        assert_eq!(stored.client_id, "client.dynamic", "{sub:?}");
        assert!(
            stored
                .claims
                .iter()
                .any(|c| c.claim_type == "client_id" && c.value == "impersonated"),
            "{sub:?}"
        );
    }
}

#[tokio::test]
async fn a_failing_extension_validator_is_invalid_grant() {
    let (f, _) = setup();
    let (error, description, _) = failure(
        token(
            &f,
            &ext("client.dynamic", "dynamic", &[("lifetime", "abc")]),
        )
        .await,
    );
    assert_eq!((error.as_str(), description), ("invalid_grant", None));
}
