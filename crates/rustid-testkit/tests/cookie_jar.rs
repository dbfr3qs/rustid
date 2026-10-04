use reqwest::cookie::CookieStore;
use reqwest::header::HeaderValue;
use rustid_testkit::cookie_jar::CookieJar;

fn set(jar: &CookieJar, url: &str, headers: &[&str]) {
    let values: Vec<HeaderValue> = headers
        .iter()
        .map(|h| HeaderValue::from_str(h).unwrap())
        .collect();
    jar.set_cookies(&mut values.iter(), &url::Url::parse(url).unwrap());
}

fn sent(jar: &CookieJar, url: &str) -> Option<String> {
    jar.cookies(&url::Url::parse(url).unwrap())
        .map(|v| v.to_str().unwrap().to_owned())
}

#[test]
fn cookies_follow_host_and_path_and_can_be_removed() {
    let jar = CookieJar::default();
    set(
        &jar,
        "http://a.test/x",
        &[
            "idsrv=1; path=/; samesite=none; httponly",
            "idsrv.session=S; path=/identity",
        ],
    );
    assert_eq!(sent(&jar, "http://a.test/"), Some("idsrv=1".into()));
    assert_eq!(
        sent(&jar, "http://a.test/identity/connect"),
        Some("idsrv=1; idsrv.session=S".into())
    );
    assert_eq!(
        sent(&jar, "http://a.test/identityx"),
        Some("idsrv=1".into())
    );
    assert_eq!(sent(&jar, "http://b.test/"), None);
    set(&jar, "http://a.test/", &["idsrv=2; path=/"]);
    assert_eq!(
        jar.get(&url::Url::parse("http://a.test/").unwrap(), "idsrv"),
        Some("2".into())
    );
    jar.remove("idsrv");
    assert_eq!(sent(&jar, "http://a.test/"), None);
}

#[test]
fn expired_cookies_are_deleted() {
    let jar = CookieJar::default();
    set(&jar, "http://a.test/", &["c=1; path=/", "d=1; path=/"]);
    set(
        &jar,
        "http://a.test/",
        &[
            "c=.; expires=Fri, 31 Dec 1999 11:00:00 GMT; path=/; httponly",
            "d=; max-age=0; path=/",
        ],
    );
    assert_eq!(sent(&jar, "http://a.test/"), None);
}
