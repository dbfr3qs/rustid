//! Request cookies and the `Set-Cookie` values written.

use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::Response;
use chrono::{DateTime, Utc};

/// The first value of a request cookie.
pub(crate) fn get<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// Where the server's cookies apply: the path base, or `/`.
pub(crate) fn cookie_path(base_path: &str) -> &str {
    if base_path.is_empty() { "/" } else { base_path }
}

/// A session cookie: `path`, `secure` over HTTPS,
/// `samesite=none`, then `httponly` when set.
pub(crate) fn cookie(name: &str, value: &str, path: &str, secure: bool, http_only: bool) -> String {
    let mut out = format!("{name}={value}; path={path}");
    if secure {
        out.push_str("; secure");
    }
    out.push_str("; samesite=none");
    if http_only {
        out.push_str("; httponly");
    }
    out
}

/// The session cookie: as [`cookie`], with `expires` when persistent.
pub(crate) fn session_cookie(
    name: &str,
    value: &str,
    path: &str,
    secure: bool,
    expires: Option<DateTime<Utc>>,
) -> String {
    let mut out = format!("{name}={value}");
    if let Some(expires) = expires {
        out.push_str(&format!(
            "; expires={}",
            expires.format("%a, %d %b %Y %H:%M:%S GMT")
        ));
    }
    out.push_str(&format!("; path={path}"));
    if secure {
        out.push_str("; secure");
    }
    out.push_str("; samesite=none; httponly");
    out
}

/// A deleting cookie: value `.` and an expiry a year back, as
/// remove session id cookie writes it.
pub(crate) fn expired(name: &str, path: &str, secure: bool, now: DateTime<Utc>) -> String {
    let when = (now - chrono::Duration::days(365))
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    let mut out = format!("{name}=.; expires={when}; path={path}");
    if secure {
        out.push_str("; secure");
    }
    out.push_str("; samesite=none");
    out
}

/// The authentication cookie as sign-out deletes it: empty, expired at the epoch, `httponly`.
pub(crate) fn deleted(name: &str, path: &str, secure: bool) -> String {
    let mut out = format!("{name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path={path}");
    if secure {
        out.push_str("; secure");
    }
    out.push_str("; samesite=none; httponly");
    out
}

pub(crate) fn append(response: &mut Response, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().append(SET_COOKIE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_are_read_from_every_cookie_header() {
        let mut h = HeaderMap::new();
        h.append(COOKIE, HeaderValue::from_static("a=1; idsrv=xyz"));
        h.append(COOKIE, HeaderValue::from_static("b=2"));
        assert_eq!(get(&h, "idsrv"), Some("xyz"));
        assert_eq!(get(&h, "b"), Some("2"));
        assert_eq!(get(&h, "c"), None);
    }

    #[test]
    fn set_cookie_values_are_written_exactly() {
        assert_eq!(
            cookie("idsrv", "v", "/", false, true),
            "idsrv=v; path=/; samesite=none; httponly"
        );
        assert_eq!(
            cookie("idsrv.session", "S", "/identity", true, false),
            "idsrv.session=S; path=/identity; secure; samesite=none"
        );
        let now = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
        assert_eq!(
            expired("idsrv.session", "/", false, now),
            "idsrv.session=.; expires=Sun, 21 Sep 2025 14:13:20 GMT; path=/; samesite=none"
        );
    }
}
