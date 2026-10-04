//! the checks before the user is consulted:
//! in its order, with its messages.

use rustid_saml::idp_initiated::{Refusal, check};
use rustid_saml::model::{Binding, IndexedEndpoint, ServiceProvider, load_service_providers};
use rustid_saml::options::SamlOptions;

fn sp() -> ServiceProvider {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/saml-service-providers.json");
    load_service_providers(&path)
        .unwrap()
        .into_iter()
        .find(|sp| sp.entity_id == "https://idp-initiated.example")
        .unwrap()
}

fn refused(sp: Option<&ServiceProvider>, entity_id: &str, relay: Option<&str>) -> String {
    match check(sp, entity_id, relay, &SamlOptions::default()) {
        Err(Refusal(message)) => message,
        Ok(_) => panic!("accepted"),
    }
}

fn acs(location: &str, binding: Binding, index: i32, is_default: bool) -> IndexedEndpoint {
    IndexedEndpoint {
        location: location.to_owned(),
        binding,
        index,
        is_default,
    }
}

#[test]
fn the_checks_in_order() {
    let sp = sp();
    assert_eq!(
        refused(None, "  ", None),
        "Missing required 'spEntityId' parameter"
    );
    assert_eq!(
        refused(None, "https://nobody", None),
        "Service provider not found"
    );
    let mut disabled = sp.clone();
    disabled.enabled = false;
    disabled.allow_idp_initiated = false;
    assert_eq!(
        refused(Some(&disabled), &sp.entity_id, None),
        "Service provider is disabled"
    );
    let mut not_allowed = sp.clone();
    not_allowed.allow_idp_initiated = false;
    assert_eq!(
        refused(Some(&not_allowed), &sp.entity_id, None),
        "Service provider does not allow IdP-initiated SSO"
    );
    let mut no_acs = sp.clone();
    no_acs.assertion_consumer_service_urls.clear();
    assert_eq!(
        refused(Some(&no_acs), &sp.entity_id, Some(&"x".repeat(81))),
        "RelayState exceeds maximum length of 80 bytes",
        "relay state comes before the ACS"
    );
    assert_eq!(
        refused(Some(&no_acs), &sp.entity_id, None),
        "Service provider has no assertion consumer service URLs configured"
    );
    let mut relative = sp.clone();
    relative.assertion_consumer_service_urls = vec![acs("/acs", Binding::HttpPost, 0, true)];
    assert_eq!(
        refused(Some(&relative), &sp.entity_id, None),
        "Service provider has an invalid assertion consumer service URL configured"
    );
}

#[test]
fn relay_state_is_counted_in_bytes_and_empty_is_none() {
    let sp = sp();
    let options = SamlOptions::default();
    // 40 two-byte characters are 80 bytes: allowed; one more byte isn't.
    let at_limit = "é".repeat(40);
    let target = check(Some(&sp), &sp.entity_id, Some(&at_limit), &options).unwrap();
    assert_eq!(target.relay_state.as_deref(), Some(at_limit.as_str()));
    assert!(
        check(
            Some(&sp),
            &sp.entity_id,
            Some(&format!("{at_limit}x")),
            &options
        )
        .is_err()
    );
    let target = check(Some(&sp), &sp.entity_id, Some(""), &options).unwrap();
    assert_eq!(target.relay_state, None);
}

#[test]
fn the_default_acs_else_the_first_whatever_its_binding() {
    let mut sp = sp();
    let options = SamlOptions::default();
    sp.assertion_consumer_service_urls = vec![
        acs("https://sp/first", Binding::HttpPost, 0, false),
        acs("https://sp/default", Binding::HttpRedirect, 1, true),
    ];
    let target = check(Some(&sp), &sp.entity_id, None, &options).unwrap();
    assert_eq!(target.acs.location, "https://sp/default");
    sp.assertion_consumer_service_urls[1].is_default = false;
    let target = check(Some(&sp), &sp.entity_id, None, &options).unwrap();
    assert_eq!(target.acs.location, "https://sp/first");
}
