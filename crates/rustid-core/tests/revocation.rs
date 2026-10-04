mod support;

use chrono::Utc;
use rustid_core::form::Form;
use rustid_core::reference_tokens;
use rustid_core::revocation::process;
use support::Fixture;

async fn revoke(f: &Fixture, form: &[(&str, &str)]) -> Result<(), &'static str> {
    process(&f.ctx(Utc::now()), None, &Form::from_pairs(form))
        .await
        .unwrap()
}

fn as_client<'a>(id: &'a str, extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut form = vec![("client_id", id), ("client_secret", "secret")];
    form.extend_from_slice(extra);
    form
}

#[tokio::test]
async fn the_owner_revokes_its_reference_token() {
    let f = Fixture::new();
    let handle = f.issue("client.reference", "api1", Utc::now()).await;
    assert_eq!(
        revoke(&f, &as_client("client", &[("token", &handle)])).await,
        Ok(())
    );
    assert!(
        reference_tokens::get(f.stores.grants.as_ref(), &handle)
            .await
            .unwrap()
            .is_some(),
        "not the owner"
    );
    assert_eq!(
        revoke(
            &f,
            &as_client(
                "client.reference",
                &[("token", &handle), ("token_type_hint", "access_token")]
            )
        )
        .await,
        Ok(())
    );
    assert!(
        reference_tokens::get(f.stores.grants.as_ref(), &handle)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn unknown_tokens_and_jwts_succeed_without_effect() {
    let f = Fixture::new();
    let jwt = f.issue("client", "api1", Utc::now()).await;
    assert_eq!(
        revoke(&f, &as_client("client", &[("token", &jwt)])).await,
        Ok(())
    );
    assert_eq!(
        revoke(
            &f,
            &as_client(
                "client",
                &[("token", "unknown"), ("token_type_hint", "refresh_token")]
            )
        )
        .await,
        Ok(())
    );
}

#[tokio::test]
async fn request_errors() {
    let f = Fixture::new();
    assert_eq!(revoke(&f, &[("token", "x")]).await, Err("invalid_request"));
    assert_eq!(
        revoke(
            &f,
            &[
                ("client_id", "client"),
                ("client_secret", "bad"),
                ("token", "x")
            ]
        )
        .await,
        Err("invalid_client")
    );
    assert_eq!(
        revoke(&f, &as_client("client", &[])).await,
        Err("invalid_request")
    );
    assert_eq!(
        revoke(
            &f,
            &as_client("client", &[("token", "x"), ("token_type_hint", "id_token")])
        )
        .await,
        Err("unsupported_token_type")
    );
}

#[tokio::test]
async fn a_refresh_token_hint_does_not_fall_back_to_access_tokens() {
    let f = Fixture::new();
    let handle = f.issue("client.reference", "api1", Utc::now()).await;
    let hinted = as_client(
        "client.reference",
        &[("token", &handle), ("token_type_hint", "refresh_token")],
    );
    assert_eq!(revoke(&f, &hinted).await, Ok(()));
    assert!(
        reference_tokens::get(f.stores.grants.as_ref(), &handle)
            .await
            .unwrap()
            .is_some()
    );
}
