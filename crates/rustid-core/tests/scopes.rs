use rustid_core::clients::Client;
use rustid_core::resources::Resources;
use rustid_core::scopes::{
    ResourceValidationError, parse_scopes_string, validate_requested_resources,
};

fn resources() -> Resources {
    serde_json::from_value(serde_json::json!({
        "identityResources": [{ "name": "openid", "userClaims": ["sub"] }],
        "apiScopes": [{ "name": "a" }, { "name": "b" }, { "name": "hidden" }],
        "apiResources": [
            { "name": "api1", "scopes": ["a"] },
            { "name": "api2", "scopes": ["a", "b"], "allowedAccessTokenSigningAlgorithms": ["ES256", "RS256"] },
            { "name": "api3", "scopes": ["b"], "allowedAccessTokenSigningAlgorithms": ["ES256"] },
            { "name": "isolated", "scopes": ["a"], "requireResourceIndicator": true }
        ]
    }))
    .unwrap()
}

fn client(scopes: &[&str], offline: bool) -> Client {
    Client {
        allowed_scopes: scopes.iter().map(|s| s.to_string()).collect(),
        allow_offline_access: offline,
        ..Default::default()
    }
}

fn scopes(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn parse_trims_splits_dedups_and_sorts() {
    assert_eq!(parse_scopes_string("  b a  b "), Some(scopes(&["a", "b"])));
    assert_eq!(parse_scopes_string("   "), None);
}

#[test]
fn audiences_follow_scope_order_then_store_order_without_isolated_apis() {
    let r = validate_requested_resources(
        &client(&["a", "b"], false),
        &resources(),
        &scopes(&["a", "b"]),
        &[],
    )
    .unwrap();
    assert_eq!(r.audiences(), ["api1", "api2", "api3"]);
    assert_eq!(r.scopes, ["a", "b"]);
    assert_eq!(
        r.allowed_signing_algorithms(),
        Ok(vec!["ES256".to_string()])
    );
}

#[test]
fn signing_algorithms_unconstrained_or_conflicting() {
    let r =
        validate_requested_resources(&client(&["a"], false), &resources(), &scopes(&["a"]), &[])
            .unwrap();
    assert_eq!(
        r.allowed_signing_algorithms(),
        Ok(vec!["ES256".to_string(), "RS256".to_string()])
    );
    let mut res = resources();
    res.api_resources[0].allowed_access_token_signing_algorithms = vec!["PS256".into()];
    let r =
        validate_requested_resources(&client(&["a"], false), &res, &scopes(&["a"]), &[]).unwrap();
    assert_eq!(
        r.allowed_signing_algorithms(),
        Err(rustid_core::scopes::NoCommonSigningAlgorithm)
    );
}

#[test]
fn identity_and_offline_access_are_recognised() {
    let r = validate_requested_resources(
        &client(&["openid"], true),
        &resources(),
        &scopes(&["offline_access", "openid"]),
        &[],
    )
    .unwrap();
    assert!(r.offline_access);
    assert_eq!(r.identity_resources.len(), 1);
    assert_eq!(r.scopes, ["offline_access", "openid"]);
}

#[test]
fn every_invalid_scope_is_reported() {
    let err = validate_requested_resources(
        &client(&["a"], false),
        &resources(),
        &scopes(&["a", "b", "nope", "offline_access"]),
        &[],
    )
    .unwrap_err();
    assert_eq!(
        err,
        ResourceValidationError::InvalidScope(scopes(&["b", "nope", "offline_access"]))
    );
}

#[test]
fn resource_indicators_admit_isolated_apis_and_reject_unmatched_names() {
    let r = validate_requested_resources(
        &client(&["a"], false),
        &resources(),
        &scopes(&["a"]),
        &scopes(&["isolated"]),
    )
    .unwrap();
    assert_eq!(r.audiences(), ["api1", "api2", "isolated"]);
    let err = validate_requested_resources(
        &client(&["a"], false),
        &resources(),
        &scopes(&["a"]),
        &scopes(&["api3", "unknown"]),
    )
    .unwrap_err();
    assert_eq!(
        err,
        ResourceValidationError::InvalidResourceIndicator(scopes(&["api3", "unknown"]))
    );
}
