//! The HTTP harness: the whole server in process, fuzzed per request.

#[test]
fn the_harness_answers_a_token_request() {
    // Selector 0 = POST /connect/token with the rest as the form body.
    let mut input = vec![0u8];
    input.extend_from_slice(b"grant_type=client_credentials&client_id=m2m&client_secret=secret");
    assert_eq!(rustid_fuzz::http::request(&input), Some(200));
}

#[test]
fn the_harness_reaches_saml_and_admin() {
    // Selector 6 = GET /Saml2/SSO?<rest>: no message redirects to the error page.
    assert_eq!(rustid_fuzz::http::request(&[6]), Some(302));
    // Selector 8 = POST /admin/clients: an empty body is a 400, not a 401.
    assert_eq!(rustid_fuzz::http::request(b"\x08{}"), Some(400));
}

#[test]
fn the_harness_makes_no_outbound_calls() {
    // Selector 1 = GET /connect/authorize?<rest>; a request_uri to a
    // listener that records connections must not be contacted.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut input = vec![1u8];
    input.extend_from_slice(
        format!(
            "client_id=client&request_uri=http://127.0.0.1:{port}/x&response_type=code&scope=openid&redirect_uri=https://client/cb"
        )
        .as_bytes(),
    );
    let _ = rustid_fuzz::http::request(&input);
    assert!(
        listener.accept().is_err(),
        "the harness fetched a request_uri"
    );
}

#[test]
#[should_panic(expected = "handler panic")]
fn a_handler_panic_reaches_the_caller() {
    rustid_fuzz::http::request_with_handler(|| panic!("handler panic"));
}

#[test]
fn a_reset_harness_forgets_earlier_inputs() {
    // Admin writes persist across inputs until the harness is rebuilt,
    // which happens every `REBUILD_EVERY` inputs (and on `reset`).
    let body = br#"{"clientId":"reset-probe","allowedGrantTypes":["client_credentials"],"allowedScopes":["api1"],"clientSecrets":[{"plaintextValue":"s"}]}"#;
    let input = [&[8u8][..], body].concat();
    rustid_fuzz::http::reset();
    assert_eq!(rustid_fuzz::http::request(&input), Some(201));
    assert_eq!(rustid_fuzz::http::request(&input), Some(409));
    rustid_fuzz::http::reset();
    assert_eq!(rustid_fuzz::http::request(&input), Some(201));
}

// Rebuilt often enough that memory stays bounded within a campaign.
const _: () = assert!(rustid_fuzz::http::REBUILD_EVERY <= 10_000);

#[test]
fn a_token_request_line_before_the_form_is_a_dpop_header() {
    // Selector 0: "<DPoP header>\n<form>". A malformed proof reaches DPoP
    // validation and is refused as one.
    let input =
        b"\x00not-a-proof\ngrant_type=client_credentials&client_id=m2m&client_secret=secret";
    assert_eq!(rustid_fuzz::http::request(input), Some(400));
    let body = rustid_fuzz::http::request_body(input).unwrap();
    assert!(body.contains("invalid_dpop_proof"), "{body}");
}
