use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};
use url::form_urlencoded;

use crate::recorded::{Body, Recorded};

pub const BASE_PLACEHOLDER: &str = "{base}";
pub const MASK: &str = "<masked>";
/// Replaces reference token handles: 64 upper-case hex characters and `-1`.
pub const REFERENCE_HANDLE: &str = "<reference-handle>";
pub const DEFAULT_MASKED_FIELDS: &[&str] = &[
    "jti",
    "iat",
    "exp",
    "nbf",
    "auth_time",
    "nonce",
    "session_state",
    "request_id",
    "requestId",
    "sid",
    "at_hash",
    "c_hash",
    "refresh_token",
    "device_code",
    "user_code",
    "auth_req_id",
    "internal_id",
];
pub const DEFAULT_MASKED_QUERY_PARAMS: &[&str] =
    &["code", "session_state", "errorId", "logoutId", "userCode"];
/// Cookies whose values vary per run; their attributes still compare.
pub const DEFAULT_MASKED_COOKIES: &[&str] = &["idsrv", "idsrv.session"];
/// Cookies one target's implementation sets that the other's doesn't: the
/// Rust interaction browser binding, and the cookies the cookie-based
/// consent message store writes and deletes (the Rust server keeps consent
/// responses server side).
pub const IGNORED_COOKIES: &[&str] = &["idsrv.interaction"];
pub const IGNORED_COOKIE_PREFIXES: &[&str] = &["ConsentResponse."];

/// Rewrites a [`Recorded`] so that two targets on different base URLs with
/// different per-request random values compare equal when their behaviour is equal.
pub struct Normalizer {
    base_url: String,
    masked_fields: BTreeSet<String>,
    masked_query_params: BTreeSet<String>,
}

impl Normalizer {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            masked_fields: DEFAULT_MASKED_FIELDS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            masked_query_params: DEFAULT_MASKED_QUERY_PARAMS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        }
    }

    pub fn mask_fields(mut self, fields: &[&str]) -> Self {
        self.masked_fields
            .extend(fields.iter().map(|s| (*s).to_owned()));
        self
    }

    pub fn mask_query_params(mut self, params: &[&str]) -> Self {
        self.masked_query_params
            .extend(params.iter().map(|s| (*s).to_owned()));
        self
    }

    pub fn normalize(&self, recorded: &Recorded) -> Recorded {
        let mut headers = recorded.headers.clone();
        if let Some(location) = headers.get_mut("location") {
            *location = mask_pushed_references(&self.normalize_url(location));
        }
        if let Some(nonce) = headers.get_mut("dpop-nonce") {
            *nonce = MASK.to_owned();
        }
        let set_cookies = recorded
            .set_cookies
            .iter()
            .filter_map(|cookie| normalize_cookie(cookie))
            .collect();
        let body = match &recorded.body {
            Body::Json(value) => Body::Json(self.normalize_json(value)),
            // JWT response bodies (e.g. RFC 9701 introspection) compare by
            // content, like JWT strings inside JSON.
            Body::Text(text) => match decode_jwt(text.trim()) {
                Some((header, payload)) => Body::Json(self.normalize_jwt(header, payload)),
                None if crate::saml::is_saml_xml(text) => {
                    Body::Text(crate::saml::mask_saml_xml(&self.replace_base(text)))
                }
                None => Body::Text(
                    self.mask_form_inputs(&self.decode_saml_inputs(&self.replace_base(text))),
                ),
            },
            Body::Empty => Body::Empty,
        };
        Recorded {
            status: recorded.status,
            headers,
            set_cookies,
            body,
        }
    }

    /// In an HTML form (`form_post`), masks the value of hidden inputs
    /// whose name is a masked field or query parameter.
    /// A JWT (an implicit or hybrid response's token) as its normalised
    /// header and payload in JSON, so it compares by content.
    fn jwt_as_json(&self, value: &str) -> Option<String> {
        let (header, payload) = decode_jwt(value)?;
        Some(self.normalize_jwt(header, payload).to_string())
    }

    fn mask_form_inputs(&self, html: &str) -> String {
        // Tokens posted to the client compare by content.
        let mut out = String::with_capacity(html.len());
        let mut rest = html;
        while let Some(i) = rest.find("value='") {
            let start = i + "value='".len();
            let Some(len) = rest[start..].find('\'') else {
                break;
            };
            out.push_str(&rest[..start]);
            let value = &rest[start..start + len];
            out.push_str(&self.jwt_as_json(value).unwrap_or_else(|| value.to_owned()));
            rest = &rest[start + len..];
        }
        out.push_str(rest);
        for name in self.masked_fields.iter().chain(&self.masked_query_params) {
            let marker = format!("name='{name}' value='");
            let mut from = 0;
            while let Some(i) = out[from..].find(&marker) {
                let start = from + i + marker.len();
                let Some(len) = out[start..].find('\'') else {
                    break;
                };
                out.replace_range(start..start + len, MASK);
                from = start + MASK.len();
            }
        }
        out
    }

    /// In an auto-post form, the SAML message's value as its masked XML
    /// (HTML-escaped), so it compares by content.
    fn decode_saml_inputs(&self, html: &str) -> String {
        use base64::engine::general_purpose::STANDARD;
        let mut out = html.to_owned();
        for name in ["SAMLResponse", "SAMLRequest"] {
            let Some((start, end)) = crate::saml::input_value_span(&out, name) else {
                continue;
            };
            let Some(xml) = STANDARD
                .decode(out[start..end].trim())
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
            else {
                continue;
            };
            let masked = crate::saml::mask_saml_xml(&self.replace_base(&xml));
            out.replace_range(start..end, &crate::saml::html_escape(&masked));
        }
        out
    }

    /// A redirect binding's message parameter as its masked XML.
    fn decode_saml_param(&self, name: &str, value: &str) -> Option<String> {
        use rustid_saml::bindings::redirect;
        let query = format!("{name}={}", redirect::escape(value));
        let parsed = redirect::parse(&query, 1 << 24, usize::MAX).ok()?;
        Some(crate::saml::mask_saml_xml(&self.replace_base(&parsed.xml)))
    }

    fn replace_base(&self, text: &str) -> String {
        mask_saml_state_ids(&mask_pushed_references(
            &text.replace(&self.base_url, BASE_PLACEHOLDER),
        ))
    }

    fn normalize_json(&self, value: &Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| {
                        let v = if self.masked_fields.contains(k) {
                            Value::String(MASK.to_owned())
                        } else {
                            self.normalize_json(v)
                        };
                        (k.clone(), v)
                    })
                    .collect(),
            ),
            Value::Array(items) => {
                Value::Array(items.iter().map(|v| self.normalize_json(v)).collect())
            }
            Value::String(s) if is_reference_handle(s) => {
                Value::String(REFERENCE_HANDLE.to_owned())
            }
            Value::String(s) => match decode_jwt(s) {
                Some((header, payload)) => self.normalize_jwt(header, payload),
                None => Value::String(self.replace_base(s)),
            },
            other => other.clone(),
        }
    }

    /// A JWT string becomes `{jwt_header, jwt_payload}` so its contents are
    /// compared. `iat` and `jti` are masked; `exp` and `nbf` become
    /// `iat+<seconds>` so lifetimes still compare. The signature is dropped;
    /// each target signs with its own randomness.
    fn normalize_jwt(&self, header: Map<String, Value>, payload: Map<String, Value>) -> Value {
        let iat = payload.get("iat").and_then(Value::as_i64);
        let mut out = Map::new();
        for (key, value) in payload {
            let normalized = match key.as_str() {
                "iat" | "jti" => Value::String(MASK.to_owned()),
                "exp" | "nbf" => match (iat, value.as_i64()) {
                    (Some(iat), Some(t)) => Value::String(format!("iat+{}", t - iat)),
                    _ => Value::String(MASK.to_owned()),
                },
                // The nonce a scenario sends is fixed, so the one mirrored in a
                // token is compared rather than masked.
                "nonce" => self.normalize_json(&value),
                k if self.masked_fields.contains(k) => Value::String(MASK.to_owned()),
                _ => self.normalize_json(&value),
            };
            out.insert(key, normalized);
        }
        serde_json::json!({ "jwt_header": self.normalize_json(&Value::Object(header)), "jwt_payload": Value::Object(out) })
    }

    /// Replaces the base URL, sorts query and fragment parameters by name
    /// and masks the values of masked parameters. A fragment without `=`
    /// (such as `#_`) is left as it is.
    fn normalize_url(&self, url: &str) -> String {
        let url = self.replace_base(url);
        let (url, fragment) = match url.split_once('#') {
            Some((u, f)) if f.contains('=') => {
                (u.to_owned(), Some(format!("#{}", self.normalize_params(f))))
            }
            Some((u, f)) => (u.to_owned(), Some(format!("#{f}"))),
            None => (url, None),
        };
        let url = match url.split_once('?') {
            Some((prefix, query)) => format!("{prefix}?{}", self.normalize_params(query)),
            None => url,
        };
        format!("{url}{}", fragment.unwrap_or_default())
    }

    fn normalize_params(&self, query: &str) -> String {
        let mut pairs: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| {
                let v = if self.masked_query_params.contains(k.as_ref()) || k == "Signature" {
                    MASK.to_owned()
                } else if let Some(xml) = matches!(k.as_ref(), "SAMLRequest" | "SAMLResponse")
                    .then(|| self.decode_saml_param(&k, &v))
                    .flatten()
                {
                    xml
                } else {
                    self.jwt_as_json(&v).unwrap_or_else(|| v.into_owned())
                };
                (k.into_owned(), v)
            })
            .collect();
        pairs.sort();
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (k, v) in &pairs {
            serializer.append_pair(k, v);
        }
        serializer.finish()
    }
}

/// Drops ignored cookies and masks the values of per-run ones.
fn normalize_cookie(cookie: &str) -> Option<String> {
    let (pair, attributes) = cookie.split_once(';').map_or((cookie, ""), |(p, a)| (p, a));
    let name = pair.split_once('=').map_or(pair, |(n, _)| n).trim();
    if IGNORED_COOKIES.contains(&name)
        || IGNORED_COOKIE_PREFIXES.iter().any(|p| name.starts_with(p))
    {
        return None;
    }
    if DEFAULT_MASKED_COOKIES.contains(&name) {
        // A deleting cookie's expiry is a year before now: mask it too.
        let rest: String = attributes
            .split(';')
            .filter(|a| !a.is_empty())
            .map(|a| match a.trim().split_once('=') {
                Some((k, _)) if k.eq_ignore_ascii_case("expires") => format!("; {k}={MASK}"),
                _ => format!(";{a}"),
            })
            .collect();
        return Some(format!("{name}={MASK}{rest}"));
    }
    Some(cookie.to_owned())
}

/// Splits a compact JWS whose header is a JSON object with `alg` into its
/// decoded header and payload. Anything else is not a JWT.
fn decode_jwt(text: &str) -> Option<(Map<String, Value>, Map<String, Value>)> {
    let mut parts = text.split('.');
    let (h, p, _sig) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let object = |segment: &str| match serde_json::from_slice::<Value>(
        &URL_SAFE_NO_PAD.decode(segment).ok()?,
    ) {
        Ok(Value::Object(map)) => Some(map),
        _ => None,
    };
    let header = object(h)?;
    header.contains_key("alg").then_some(())?;
    Some((header, object(p)?))
}

fn is_reference_handle(text: &str) -> bool {
    text.strip_suffix("-1").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'F'))
    })
}

/// Masks the random reference of a pushed authorization request URI
/// (`urn:ietf:params:oauth:request_uri:<reference>`), raw or URL-encoded
/// once or twice, wherever it appears.
fn mask_pushed_references(text: &str) -> String {
    const PREFIXES: &[&str] = &[
        "urn:ietf:params:oauth:request_uri:",
        "urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A",
        "urn%253Aietf%253Aparams%253Aoauth%253Arequest_uri%253A",
    ];
    let mut out = text.to_owned();
    for prefix in PREFIXES {
        let mut from = 0;
        while let Some(i) = out[from..].find(prefix) {
            let start = from + i + prefix.len();
            let len = out[start..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
                .unwrap_or(out.len() - start);
            if len == 0 {
                // Already masked (and re-encoded) inside a nested value.
                from = start;
                continue;
            }
            out.replace_range(start..start + len, MASK);
            from = start + MASK.len();
        }
    }
    out
}

/// Masks the SAML sign-in state id (`samlStateId`, a UUID), raw or
/// URL-encoded once or twice, wherever it appears.
fn mask_saml_state_ids(text: &str) -> String {
    const MARKERS: &[&str] = &["samlStateId=", "samlStateId%3D", "samlStateId%253D"];
    let mut out = text.to_owned();
    for marker in MARKERS {
        let mut from = 0;
        while let Some(i) = out[from..].find(marker) {
            let start = from + i + marker.len();
            let len = out[start..]
                .find(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
                .unwrap_or(out.len() - start);
            if len == 0 {
                from = start;
                continue;
            }
            out.replace_range(start..start + len, MASK);
            from = start + MASK.len();
        }
    }
    out
}
