use rustid_core::options::{
    DEFAULT_PROMPT_VALUES, DEFAULT_SIGNING_ALGORITHMS, ProtocolOptions, TimeSpan,
};

#[test]
fn defaults_hold() {
    let o = ProtocolOptions::default();
    assert_eq!(o.issuer_uri, None);
    assert!(o.lower_case_issuer_uri);
    assert!(o.emit_issuer_identification_response_parameter);
    assert!(o.endpoints.enable_authorize_endpoint);
    assert!(!o.endpoints.enable_jwt_request_uri);
    assert!(o.endpoints.enable_oauth2_metadata_endpoint);
    assert!(o.discovery.show_key_set);
    assert!(o.discovery.expand_relative_paths_in_custom_entries);
    assert_eq!(o.discovery.response_cache_interval, None);
    assert_eq!(
        o.user_interaction.prompt_values_supported,
        DEFAULT_PROMPT_VALUES
    );
    assert_eq!(
        o.supported_client_assertion_signing_algorithms,
        DEFAULT_SIGNING_ALGORITHMS
    );
    assert_eq!(
        o.supported_request_object_signing_algorithms,
        DEFAULT_SIGNING_ALGORITHMS
    );
    assert_eq!(
        o.dpop.supported_dpop_signing_algorithms,
        DEFAULT_SIGNING_ALGORITHMS
    );
}

#[test]
fn partial_json_keeps_defaults_for_missing_fields() {
    let o: ProtocolOptions = serde_json::from_str(
        r#"{ "endpoints": { "enable_introspection_endpoint": false }, "discovery": { "show_claims": false } }"#,
    )
    .unwrap();
    assert!(!o.endpoints.enable_introspection_endpoint);
    assert!(o.endpoints.enable_token_endpoint);
    assert!(!o.discovery.show_claims);
    assert!(o.discovery.show_key_set);
}

#[test]
fn lists_replace_rather_than_append() {
    let o: ProtocolOptions =
        serde_json::from_str(r#"{ "supported_client_assertion_signing_algorithms": ["RS256"] }"#)
            .unwrap();
    assert_eq!(o.supported_client_assertion_signing_algorithms, ["RS256"]);
}

#[test]
fn unknown_option_is_rejected_with_its_name() {
    let err = serde_json::from_str::<ProtocolOptions>(
        r#"{ "endpoints": { "enable_tokn_endpoint": false } }"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("enable_tokn_endpoint"), "{err}");
}

#[test]
fn create_account_url_adds_create_prompt_once() {
    let o: ProtocolOptions = serde_json::from_str(
        r#"{ "user_interaction": { "create_account_url": "/account/create" } }"#,
    )
    .unwrap();
    let o = o.finalize().finalize();
    assert_eq!(
        o.user_interaction.prompt_values_supported,
        ["none", "login", "consent", "select_account", "create"]
    );
}

#[test]
fn custom_entries_keep_their_order() {
    let o: ProtocolOptions = serde_json::from_str(
        r#"{ "discovery": { "custom_entries": { "z": 1, "a": "x", "m": { "n": true } } } }"#,
    )
    .unwrap();
    let keys: Vec<&String> = o.discovery.custom_entries.keys().collect();
    assert_eq!(keys, ["z", "a", "m"]);
}

#[test]
fn token_option_defaults_hold() {
    let o = ProtocolOptions::default();
    assert_eq!(o.access_token_jwt_type, "at+jwt");
    assert!(!o.emit_static_audience_claim && !o.emit_scopes_as_space_delimited_string_in_jwt);
    assert!(!o.strict_client_assertion_audience_validation);
    assert_eq!(o.jwt_validation_clock_skew, TimeSpan(300));
    let limits = &o.input_length_restrictions;
    assert_eq!(
        (
            limits.client_id,
            limits.client_secret,
            limits.scope,
            limits.grant_type,
            limits.jwt
        ),
        (100, 100, 300, 100, 51200)
    );
    assert!(
        !o.pushed_authorization
            .allow_unregistered_pushed_redirect_uris
    );
}

#[test]
fn timespans_read_text_or_seconds() {
    for (json, seconds) in [
        (r#""00:05:00""#, 300),
        (r#""1.02:03:04""#, 93784),
        ("42", 42),
    ] {
        let o: ProtocolOptions =
            serde_json::from_str(&format!(r#"{{ "jwt_validation_clock_skew": {json} }}"#)).unwrap();
        assert_eq!(o.jwt_validation_clock_skew, TimeSpan(seconds), "{json}");
    }
    let err = serde_json::from_str::<ProtocolOptions>(
        r#"{ "jwt_validation_clock_skew": "five minutes" }"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("TimeSpan"), "{err}");
}

#[test]
fn caching_defaults_are_fifteen_minutes_and_read_timespans() {
    let defaults = ProtocolOptions::default().caching;
    assert_eq!(defaults.client_store_expiration, TimeSpan(900));
    assert_eq!(defaults.resource_store_expiration, TimeSpan(900));
    assert_eq!(defaults.cors_expiration, TimeSpan(900));
    let options: ProtocolOptions =
        serde_json::from_str(r#"{"caching": {"client_store_expiration": "00:00:30"}}"#).unwrap();
    assert_eq!(options.caching.client_store_expiration, TimeSpan(30));
    assert_eq!(options.caching.cors_expiration, TimeSpan(900));
}

#[test]
fn authorize_option_defaults_hold() {
    let o = ProtocolOptions::default();
    let ui = &o.user_interaction;
    assert_eq!(
        (
            ui.login_url.as_str(),
            ui.login_return_url_parameter.as_str()
        ),
        ("/Account/Login", "ReturnUrl")
    );
    assert_eq!(
        (ui.logout_url.as_str(), ui.logout_id_parameter.as_str()),
        ("/Account/Logout", "logoutId")
    );
    assert_eq!(
        (
            ui.consent_url.as_str(),
            ui.consent_return_url_parameter.as_str()
        ),
        ("/consent", "returnUrl")
    );
    assert_eq!(
        (ui.error_url.as_str(), ui.error_id_parameter.as_str()),
        ("/home/error", "errorId")
    );
    assert_eq!(ui.create_account_url, None);
    assert_eq!(ui.create_account_return_url_parameter, "returnUrl");
    assert_eq!(ui.custom_redirect_return_url_parameter, "returnUrl");
    let limits = &o.input_length_restrictions;
    assert_eq!(
        (
            limits.redirect_uri,
            limits.nonce,
            limits.ui_locale,
            limits.login_hint,
            limits.acr_values,
            limits.dpop_key_thumbprint
        ),
        (400, 300, 100, 100, 300, 100)
    );
    assert_eq!(o.csp.level, rustid_core::options::CspLevel::Two);
    assert!(o.csp.add_deprecated_header);
    assert!(!o.validate_tenant_on_authorization);
}

#[test]
fn csp_level_reads_names_or_numbers() {
    for (json, level) in [
        (r#""One""#, "One"),
        (r#""two""#, "Two"),
        ("0", "One"),
        ("1", "Two"),
    ] {
        let o: ProtocolOptions =
            serde_json::from_str(&format!(r#"{{ "csp": {{ "level": {json} }} }}"#)).unwrap();
        assert_eq!(format!("{:?}", o.csp.level), level, "{json}");
    }
    assert!(serde_json::from_str::<ProtocolOptions>(r#"{ "csp": { "level": "Three" } }"#).is_err());
}

#[test]
fn authentication_defaults_hold() {
    let o = ProtocolOptions::default();
    assert_eq!(o.authentication.cookie_lifetime, TimeSpan(36_000));
    assert_eq!(o.authentication.check_session_cookie_name, "idsrv.session");
    let o: ProtocolOptions = serde_json::from_str(
        r#"{ "authentication": { "cookie_lifetime": "01:00:00", "check_session_cookie_name": "sid" } }"#,
    )
    .unwrap();
    assert_eq!(o.authentication.cookie_lifetime, TimeSpan(3600));
    assert_eq!(o.authentication.check_session_cookie_name, "sid");
}

#[test]
fn code_redemption_option_defaults_hold() {
    let o = ProtocolOptions::default();
    assert!(!o.emit_state_hash);
    assert_eq!(o.input_length_restrictions.authorization_code, 100);
    assert_eq!(
        rustid_core::options::InputLengthRestrictions::CODE_VERIFIER_MIN_LENGTH,
        43
    );
    assert_eq!(
        rustid_core::options::InputLengthRestrictions::CODE_VERIFIER_MAX_LENGTH,
        128
    );
}

/// `StoragePurgeOptions`: the defaults; set from config.
#[test]
fn storage_purge_options() {
    let defaults = ProtocolOptions::default().storage_purge;
    assert!(defaults.enable_purge);
    assert_eq!(defaults.purge_interval.0, 3600);
    assert_eq!(defaults.batch_size, 100);
    assert!(defaults.fuzz_startup);
    let o: ProtocolOptions = serde_json::from_str(
        r#"{ "storage_purge": { "enable_purge": false, "purge_interval": 60 } }"#,
    )
    .unwrap();
    assert!(!o.storage_purge.enable_purge);
    assert_eq!(o.storage_purge.purge_interval.0, 60);
    assert_eq!(o.storage_purge.batch_size, 100);
}
