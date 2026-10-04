use std::collections::BTreeMap;

use rustid_testkit::normalize::{BASE_PLACEHOLDER, MASK, Normalizer, REFERENCE_HANDLE};
use rustid_testkit::recorded::{Body, Recorded};
use serde_json::json;

fn recorded(status: u16, headers: &[(&str, &str)], body: Body) -> Recorded {
    Recorded {
        status,
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>(),
        set_cookies: Vec::new(),
        body,
    }
}

#[test]
fn replaces_base_url_inside_json_strings() {
    let n = Normalizer::new("http://127.0.0.1:5001/");
    let r = recorded(
        200,
        &[],
        Body::Json(json!({
            "token_endpoint": "http://127.0.0.1:5001/connect/token",
            "nested": { "list": ["http://127.0.0.1:5001/a", "https://other.test/b"] }
        })),
    );
    let out = n.normalize(&r);
    assert_eq!(
        out.body,
        Body::Json(json!({
            "token_endpoint": format!("{BASE_PLACEHOLDER}/connect/token"),
            "nested": { "list": [format!("{BASE_PLACEHOLDER}/a"), "https://other.test/b"] }
        }))
    );
}

#[test]
fn masks_default_and_custom_fields_at_any_depth() {
    let n = Normalizer::new("http://127.0.0.1:5001").mask_fields(&["custom"]);
    let r = recorded(
        200,
        &[],
        Body::Json(json!({
            "jti": "abc", "keep": 1, "inner": { "iat": 12345, "custom": "x", "keep": "y" }
        })),
    );
    let out = n.normalize(&r);
    assert_eq!(
        out.body,
        Body::Json(json!({
            "jti": MASK, "keep": 1, "inner": { "iat": MASK, "custom": MASK, "keep": "y" }
        }))
    );
}

#[test]
fn normalizes_location_header_base_query_order_and_masked_params() {
    let n = Normalizer::new("http://127.0.0.1:5001");
    let r = recorded(
        302,
        &[(
            "location",
            "http://127.0.0.1:5001/account/login?returnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fx%3D1&b=2&a=1",
        )],
        Body::Empty,
    );
    let out = n.normalize(&r);
    assert_eq!(
        out.headers.get("location").map(String::as_str),
        Some("{base}/account/login?a=1&b=2&returnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fx%3D1")
    );

    let r = recorded(
        302,
        &[(
            "location",
            "https://client.test/cb?state=s&code=abc&session_state=ss",
        )],
        Body::Empty,
    );
    let out = n.normalize(&r);
    assert_eq!(
        out.headers.get("location").map(String::as_str),
        Some("https://client.test/cb?code=%3Cmasked%3E&session_state=%3Cmasked%3E&state=s")
    );
}

#[test]
fn leaves_relative_location_without_query_untouched() {
    let n = Normalizer::new("http://127.0.0.1:5001");
    let r = recorded(302, &[("location", "/home/error")], Body::Empty);
    assert_eq!(
        n.normalize(&r).headers.get("location").map(String::as_str),
        Some("/home/error")
    );
}

#[test]
fn replaces_base_url_in_text_bodies_and_keeps_status() {
    let n = Normalizer::new("http://127.0.0.1:5001");
    let r = recorded(
        400,
        &[],
        Body::Text("see http://127.0.0.1:5001/docs".to_owned()),
    );
    let out = n.normalize(&r);
    assert_eq!(out.status, 400);
    assert_eq!(out.body, Body::Text(format!("see {BASE_PLACEHOLDER}/docs")));
}

#[test]
fn jwt_strings_are_decoded_with_relative_lifetimes_and_masked_ids() {
    use base64::Engine;
    let b64 = |v: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    };
    let token = format!(
        "{}.{}.sig",
        b64(json!({ "alg": "RS256", "kid": "k" })),
        b64(
            json!({ "iss": "http://127.0.0.1:5001", "iat": 100, "nbf": 100, "exp": 3700, "jti": "abc", "client_id": "c" })
        )
    );
    let n = Normalizer::new("http://127.0.0.1:5001");
    let out = n.normalize(&recorded(
        200,
        &[],
        Body::Json(json!({ "access_token": token, "not_jwt": "a.b.c" })),
    ));
    assert_eq!(
        out.body,
        Body::Json(json!({
            "access_token": {
                "jwt_header": { "alg": "RS256", "kid": "k" },
                "jwt_payload": { "iss": BASE_PLACEHOLDER, "iat": MASK, "nbf": "iat+0", "exp": "iat+3600", "jti": MASK, "client_id": "c" }
            },
            "not_jwt": "a.b.c"
        }))
    );
}

#[test]
fn reference_token_handles_are_replaced() {
    let handle = format!("{}-1", "0123456789ABCDEF".repeat(4));
    let lower = format!("{}-1", "0123456789abcdef".repeat(4));
    let n = Normalizer::new("http://h");
    let out = n.normalize(&recorded(
        200,
        &[],
        Body::Json(json!({ "access_token": handle, "lower": lower, "short": "AB-1" })),
    ));
    assert_eq!(
        out.body,
        Body::Json(json!({ "access_token": REFERENCE_HANDLE, "lower": lower, "short": "AB-1" }))
    );
}

#[test]
fn jwt_text_bodies_are_decoded() {
    use base64::Engine;
    let b64 = |v: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    };
    let token = format!(
        "{}.{}.sig",
        b64(json!({ "alg": "RS256", "typ": "token-introspection+jwt" })),
        b64(
            json!({ "iss": "http://h", "iat": 5, "token_introspection": { "active": true, "exp": 9 } })
        )
    );
    let out = Normalizer::new("http://h").normalize(&recorded(200, &[], Body::Text(token)));
    assert_eq!(
        out.body,
        Body::Json(json!({
            "jwt_header": { "alg": "RS256", "typ": "token-introspection+jwt" },
            "jwt_payload": { "iss": BASE_PLACEHOLDER, "iat": MASK,
                             "token_introspection": { "active": true, "exp": MASK } }
        }))
    );
}

#[test]
fn cookies_are_kept_masked_or_dropped_by_name() {
    let mut r = recorded(303, &[], Body::Empty);
    r.set_cookies = vec![
        ".AspNetCore.Culture=c%3Den-US%7Cuic%3Den-US; path=/".into(),
        "idsrv=abc; path=/; secure; samesite=none; httponly".into(),
        "idsrv.interaction=xyz; path=/".into(),
    ];
    let out = Normalizer::new("http://h").normalize(&r);
    assert_eq!(
        out.set_cookies,
        [
            ".AspNetCore.Culture=c%3Den-US%7Cuic%3Den-US; path=/".to_owned(),
            format!("idsrv={MASK}; path=/; secure; samesite=none; httponly"),
        ]
    );
}

#[test]
fn form_post_inputs_with_masked_names_are_masked() {
    let html = "<input type='hidden' name='state' value='s1' />\n<input type='hidden' name='session_state' value='abc.123' />";
    let out = Normalizer::new("http://h").normalize(&recorded(200, &[], Body::Text(html.into())));
    assert_eq!(
        out.body,
        Body::Text(format!(
            "<input type='hidden' name='state' value='s1' />\n<input type='hidden' name='session_state' value='{MASK}' />"
        ))
    );
}

#[test]
fn fragment_parameters_are_sorted_and_masked() {
    let r = recorded(
        303,
        &[(
            "location",
            "https://c.test/cb#state=s1&error=login_required&session_state=abc.1",
        )],
        Body::Empty,
    );
    let out = Normalizer::new("http://h").normalize(&r);
    assert_eq!(
        out.headers["location"],
        format!(
            "https://c.test/cb#error=login_required&session_state={}&state=s1",
            MASK.replace('<', "%3C").replace('>', "%3E")
        )
    );
    let r = recorded(
        303,
        &[("location", "https://c.test/cb?error=x&session_state=a#_")],
        Body::Empty,
    );
    let out = Normalizer::new("http://h").normalize(&r);
    assert_eq!(
        out.headers["location"],
        format!(
            "https://c.test/cb?error=x&session_state={}#_",
            MASK.replace('<', "%3C").replace('>', "%3E")
        )
    );
}

#[test]
fn deleting_masked_cookies_mask_their_expiry() {
    let mut r = recorded(200, &[], Body::Empty);
    r.set_cookies = vec![
        "idsrv.session=.; expires=Sun, 21 Sep 2025 14:13:20 GMT; path=/; samesite=none".into(),
    ];
    let out = Normalizer::new("http://h").normalize(&r);
    assert_eq!(
        out.set_cookies,
        [format!(
            "idsrv.session={MASK}; expires={MASK}; path=/; samesite=none"
        )]
    );
}

#[test]
fn masked_fields_are_masked_inside_jwt_payloads() {
    use base64::Engine;
    let b64 = |v: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    };
    let jwt = format!(
        "{}.{}.sig",
        b64(json!({ "alg": "RS256", "typ": "JWT" })),
        b64(
            json!({ "iat": 100, "exp": 400, "sub": "1", "sid": "S", "at_hash": "h", "auth_time": 90, "nonce": "n", "s_hash": "kept" })
        )
    );
    let out = Normalizer::new("http://h").normalize(&recorded(
        200,
        &[],
        Body::Json(json!({ "id_token": jwt })),
    ));
    assert_eq!(
        out.body,
        Body::Json(json!({ "id_token": {
            "jwt_header": { "alg": "RS256", "typ": "JWT" },
            "jwt_payload": {
                "iat": MASK, "exp": "iat+300", "sub": "1", "sid": MASK, "at_hash": MASK,
                "auth_time": MASK, "nonce": "n", "s_hash": "kept"
            }
        }}))
    );
}

#[test]
fn jwts_in_redirect_parameters_and_form_inputs_are_compared_by_content() {
    use base64::Engine;
    let b64 = |v: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    };
    let jwt = |sig: &str| {
        format!(
            "{}.{}.{sig}",
            b64(json!({ "alg": "RS256" })),
            b64(json!({ "iat": 100, "exp": 400, "sub": "1" }))
        )
    };
    let normalized = r#"{"jwt_header":{"alg":"RS256"},"jwt_payload":{"iat":"<masked>","exp":"iat+300","sub":"1"}}"#;
    let n = Normalizer::new("http://h");
    let a = n.normalize(&recorded(
        303,
        &[(
            "location",
            &format!("https://c.test/cb#id_token={}&state=s", jwt("a")),
        )],
        Body::Empty,
    ));
    let b = n.normalize(&recorded(
        303,
        &[(
            "location",
            &format!("https://c.test/cb#id_token={}&state=s", jwt("b")),
        )],
        Body::Empty,
    ));
    assert_eq!(
        a.headers["location"], b.headers["location"],
        "signatures differ, contents don't"
    );
    let fragment = a.headers["location"].split_once('#').unwrap().1;
    let decoded: Vec<(String, String)> = url::form_urlencoded::parse(fragment.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(decoded[0], ("id_token".to_owned(), normalized.to_owned()));

    let html = format!(
        "<input type='hidden' name='id_token' value='{}' />",
        jwt("c")
    );
    let out = n.normalize(&recorded(200, &[], Body::Text(html)));
    assert_eq!(
        out.body,
        Body::Text(format!(
            "<input type='hidden' name='id_token' value='{normalized}' />"
        ))
    );
}

#[test]
fn pushed_request_references_are_masked_however_encoded() {
    use rustid_testkit::normalize::Normalizer;
    use rustid_testkit::recorded::{Body, Recorded};
    let n = Normalizer::new("http://t");
    let recorded = Recorded {
        status: 303,
        headers: [(
            "location".to_owned(),
            "http://t/Account/Login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Frequest_uri%3Durn%253Aietf%253Aparams%253Aoauth%253Arequest_uri%253AAB12-1%26client_id%3Dweb".to_owned(),
        )]
        .into(),
        set_cookies: Vec::new(),
        body: Body::Json(serde_json::json!({
            "request_uri": "urn:ietf:params:oauth:request_uri:0F3C-1",
            "expires_in": 600,
        })),
    };
    let normalized = n.normalize(&recorded);
    assert_eq!(
        normalized.headers["location"],
        "{base}/Account/Login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Frequest_uri%3Durn%253Aietf%253Aparams%253Aoauth%253Arequest_uri%253A%3Cmasked%3E%26client_id%3Dweb"
    );
    let Body::Json(body) = normalized.body else {
        panic!()
    };
    assert_eq!(
        body["request_uri"],
        "urn:ietf:params:oauth:request_uri:<masked>"
    );
}
