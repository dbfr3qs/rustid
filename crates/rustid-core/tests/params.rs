use rustid_core::form::Form;
use rustid_core::params::{
    Params, add_hash_fragment, add_query_param, add_query_string, is_local_url, url_encode,
    utf16_len,
};

#[test]
fn keys_group_case_insensitively_in_first_seen_order() {
    let p = Params::parse_query("b=1&A=2&a=3&B=4&c=%20&d");
    assert_eq!(p.get("a").as_deref(), Some("2,3"));
    assert_eq!(p.values("B"), ["1", "4"]);
    assert!(!p.contains("c"), "blank values are dropped");
    assert!(!p.contains("d"));
    assert_eq!(p.to_query_string(), "B=1&B=4&a=2&a=3");
}

#[test]
fn repeated_query_keys_take_the_second_casing() {
    let p = Params::parse_query("state=a&STATE=b&x=1&State=c");
    assert_eq!(p.to_query_string(), "STATE=a&STATE=b&STATE=c&x=1");
    let p = Params::parse_query("state=&STATE=b");
    assert_eq!(p.to_query_string(), "STATE=b");
}

#[test]
fn form_keys_keep_the_first_casing() {
    let form = Form::parse(b"state=a&x=1&STATE=b").unwrap();
    assert_eq!(
        Params::from_form(&form).to_query_string(),
        "state=a&state=b&x=1"
    );
}

#[test]
fn set_replaces_in_place_and_remove_drops_the_key() {
    let mut p = Params::from_pairs([("x", "1"), ("acr_values", "idp:a b"), ("y", "2")]);
    p.set("ACR_VALUES", "b");
    assert_eq!(p.to_query_string(), "x=1&acr_values=b&y=2");
    p.remove("acr_values");
    p.add("suppressed_prompt", "login");
    assert_eq!(p.to_query_string(), "x=1&y=2&suppressed_prompt=login");
}

#[test]
fn plus_and_escapes_decode() {
    let p = Params::parse_query("state=a+b%2Bc%zz");
    assert_eq!(p.get("state").as_deref(), Some("a b+c%zz"));
}

#[test]
fn url_encode_matches_the_default_encoder() {
    let ascii: String = (32u8..127).map(char::from).collect();
    assert_eq!(
        url_encode(&ascii),
        "%20!%22%23$%25%26%27()*%2B,-.%2F0123456789%3A;%3C%3D%3E%3F@ABCDEFGHIJKLMNOPQRSTUVWXYZ%5B%5C%5D%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~"
    );
    assert_eq!(url_encode("é€😀"), "%C3%A9%E2%82%AC%F0%9F%98%80");
}

#[test]
fn empty_value_is_written_as_bare_key() {
    let mut p = Params::default();
    p.add("suppressed_prompt", "");
    p.add("a", "1");
    assert_eq!(p.to_query_string(), "suppressed_prompt&a=1");
}

#[test]
fn query_and_fragment_appending() {
    assert_eq!(add_query_string("https://c/cb", "a=1"), "https://c/cb?a=1");
    assert_eq!(
        add_query_string("https://c/cb?x=1", "a=1"),
        "https://c/cb?x=1&a=1"
    );
    assert_eq!(
        add_query_string("https://c/cb?x=1&", "a=1"),
        "https://c/cb?x=1&a=1"
    );
    assert_eq!(
        add_query_param("/home/error", "errorId", "a b"),
        "/home/error?errorId=a%20b"
    );
    assert_eq!(add_hash_fragment("https://c/cb", "a=1"), "https://c/cb#a=1");
    assert_eq!(
        add_hash_fragment("https://c/cb#x", "a=1"),
        "https://c/cb#xa=1"
    );
}

#[test]
fn local_urls() {
    for local in ["/", "/account/login", "~/", "~/x"] {
        assert!(is_local_url(local), "{local}");
    }
    for other in [
        "",
        "//evil",
        "/\\evil",
        "~//x",
        "https://x/",
        "account",
        "/a\u{7}b",
    ] {
        assert!(!is_local_url(other), "{other}");
    }
}

#[test]
fn lengths_count_utf16_units() {
    assert_eq!(utf16_len("a😀"), 3);
}

#[test]
fn parsing_many_distinct_keys_takes_linear_time() {
    let query: String = (0..50_000).map(|i| format!("k{i:06}=v&")).collect();
    let started = std::time::Instant::now();
    let p = Params::parse_query(&query);
    assert_eq!(p.iter().count(), 50_000);
    assert_eq!(p.get("K049999").as_deref(), Some("v"));
    // Quadratic parsing of 50,000 keys takes minutes; linear takes about a
    // second in a debug build, more on a loaded machine.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
}
