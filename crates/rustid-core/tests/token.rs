mod support;

use rustid_core::form::Form;
use rustid_core::jwt::{Jws, PublicJwk};
use rustid_core::token::{TokenError, TokenFailure, process};

struct Fixture(support::Fixture);

impl Fixture {
    fn new() -> Self {
        Fixture(support::Fixture::new())
    }

    async fn run(
        &self,
        form: &[(&str, &str)],
    ) -> Result<rustid_core::token::TokenResponse, TokenFailure> {
        process(
            &self.0.ctx(chrono::Utc::now()),
            None,
            &Form::from_pairs(form),
        )
        .await
    }
}

fn error(code: &'static str) -> Result<rustid_core::token::TokenResponse, TokenFailure> {
    Err(TokenFailure::Protocol(TokenError::new(code)))
}

#[tokio::test]
async fn client_credentials_issues_a_verifiable_access_token() {
    let f = Fixture::new();
    let response = f
        .run(&[
            ("grant_type", "client_credentials"),
            ("client_id", "client"),
            ("client_secret", "secret"),
            ("scope", "api1"),
        ])
        .await
        .unwrap();
    assert_eq!(
        (
            response.expires_in,
            response.token_type,
            response.scope.as_str()
        ),
        (3600, "Bearer", "api1")
    );
    let jws = Jws::decode(&response.access_token).unwrap();
    assert_eq!(jws.header_str("typ"), Some("at+jwt"));
    assert_eq!(jws.claim_str("client_id"), Some("client"));
    let public =
        PublicJwk::parse(&serde_json::to_string(&f.0.material.signing[0].jwk).unwrap()).unwrap();
    assert!(jws.verify(&public));
}

#[tokio::test]
async fn authentication_and_grant_errors() {
    let f = Fixture::new();
    let cc = |id: &'static str, secret: &'static str| {
        vec![
            ("grant_type", "client_credentials"),
            ("client_id", id),
            ("client_secret", secret),
        ]
    };
    assert_eq!(
        f.run(&[("grant_type", "client_credentials")]).await,
        error("invalid_request")
    );
    assert_eq!(
        f.run(&cc("nobody", "secret")).await,
        error("invalid_client")
    );
    assert_eq!(f.run(&cc("client", "wrong")).await, error("invalid_client"));
    assert_eq!(
        f.run(&[
            ("grant_type", "client_credentials"),
            ("client_id", "client.no_secret")
        ])
        .await,
        error("invalid_client")
    );
    assert_eq!(
        f.run(&[
            ("grant_type", "client_credentials"),
            ("client_id", "implicit")
        ])
        .await,
        error("unauthorized_client")
    );
    assert_eq!(
        f.run(&[("client_id", "client"), ("client_secret", "secret")])
            .await,
        error("unsupported_grant_type")
    );
    assert_eq!(
        f.run(&[
            ("grant_type", "authorization_code"),
            ("client_id", "client"),
            ("client_secret", "secret")
        ])
        .await,
        error("unauthorized_client")
    );
    assert_eq!(
        f.run(&[
            ("grant_type", "custom"),
            ("client_id", "client"),
            ("client_secret", "secret")
        ])
        .await,
        error("unsupported_grant_type")
    );
}

#[tokio::test]
async fn scope_errors() {
    let f = Fixture::new();
    let with_scope = |id: &'static str, scope: &'static str| {
        vec![
            ("grant_type", "client_credentials"),
            ("client_id", id),
            ("client_secret", "secret"),
            ("scope", scope),
        ]
    };
    assert_eq!(
        f.run(&with_scope("client.identityscopes", "openid")).await,
        error("invalid_scope")
    );
    assert_eq!(
        f.run(&with_scope("client", "offline_access")).await,
        error("invalid_scope")
    );
    assert_eq!(
        f.run(&with_scope("client", "nope")).await,
        error("invalid_scope")
    );
    assert_eq!(
        f.run(&[
            ("grant_type", "client_credentials"),
            ("client_id", "client.no_default_scopes"),
            ("client_secret", "secret")
        ])
        .await,
        error("invalid_scope")
    );
    assert_eq!(
        f.run(&[
            ("grant_type", "client_credentials"),
            ("client_id", "client"),
            ("client_secret", "secret"),
            ("resource", "https://x")
        ])
        .await,
        error("invalid_target")
    );
}

#[tokio::test]
async fn reference_clients_get_a_handle_to_a_stored_token() {
    let f = Fixture::new();
    let response = f
        .run(&[
            ("grant_type", "client_credentials"),
            ("client_id", "client.reference"),
            ("client_secret", "secret"),
            ("scope", "api1 api2"),
        ])
        .await
        .unwrap();
    let handle = &response.access_token;
    assert_eq!(handle.len(), 66, "{handle}");
    assert!(handle.ends_with("-1"));
    assert!(
        handle[..64]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
    );
    let stored = rustid_core::reference_tokens::get(f.0.stores.grants.as_ref(), handle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.client_id, "client.reference");
    assert_eq!(stored.lifetime, 3600);
    assert_eq!(stored.audiences, ["api1-resource", "api"]);
    let types: Vec<&str> = stored
        .claims
        .iter()
        .map(|c| c.claim_type.as_str())
        .collect();
    assert_eq!(
        types,
        [
            "client_id",
            "client_role",
            "client_count",
            "scope",
            "scope",
            "jti"
        ]
    );
}
