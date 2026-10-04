//! A browser-like cookie jar for the harness client, which, unlike
//! reqwest's, lets a scenario drop a cookie (to test cookie reissue).

use std::sync::Mutex;

use chrono::{NaiveDateTime, Utc};
use reqwest::header::HeaderValue;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stored {
    host: String,
    path: String,
    name: String,
    value: String,
}

/// Cookies by host, path and name. Expiry in the past (or `max-age=0`)
/// deletes; otherwise every cookie lives for the jar's lifetime, as
/// session cookies do.
#[derive(Debug, Default)]
pub struct CookieJar {
    cookies: Mutex<Vec<Stored>>,
}

impl CookieJar {
    /// Drops every cookie with this name.
    pub fn remove(&self, name: &str) {
        self.lock().retain(|c| c.name != name);
    }

    /// The value of a cookie sent to this URL.
    pub fn get(&self, url: &url::Url, name: &str) -> Option<String> {
        self.lock()
            .iter()
            .find(|c| c.name == name && applies(c, url))
            .map(|c| c.value.clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Stored>> {
        self.cookies.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set(&self, header: &str, url: &url::Url) {
        let mut parts = header.split(';');
        let Some((name, value)) = parts.next().and_then(|p| p.trim().split_once('=')) else {
            return;
        };
        let mut path = "/".to_owned();
        let mut expired = false;
        for attribute in parts {
            let (key, val) = attribute
                .trim()
                .split_once('=')
                .unwrap_or((attribute.trim(), ""));
            match key.to_ascii_lowercase().as_str() {
                "path" if val.starts_with('/') => path = val.to_owned(),
                "max-age" => expired |= val.trim().parse::<i64>().is_ok_and(|s| s <= 0),
                "expires" => {
                    expired |=
                        NaiveDateTime::parse_from_str(val.trim(), "%a, %d %b %Y %H:%M:%S GMT")
                            .is_ok_and(|t| t.and_utc() <= Utc::now());
                }
                _ => {}
            }
        }
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        let mut cookies = self.lock();
        cookies.retain(|c| !(c.host == host && c.path == path && c.name == name));
        if !expired {
            cookies.push(Stored {
                host,
                path,
                name: name.to_owned(),
                value: value.to_owned(),
            });
        }
    }
}

fn applies(cookie: &Stored, url: &url::Url) -> bool {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let path = url.path();
    cookie.host == host
        && (cookie.path == "/"
            || path == cookie.path
            || path.starts_with(&format!("{}/", cookie.path.trim_end_matches('/'))))
}

impl reqwest::cookie::CookieStore for CookieJar {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &url::Url) {
        for header in cookie_headers {
            if let Ok(header) = header.to_str() {
                self.set(header, url);
            }
        }
    }

    fn cookies(&self, url: &url::Url) -> Option<HeaderValue> {
        let value = self
            .lock()
            .iter()
            .filter(|c| applies(c, url))
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ");
        (!value.is_empty())
            .then(|| HeaderValue::from_str(&value).ok())
            .flatten()
    }
}
