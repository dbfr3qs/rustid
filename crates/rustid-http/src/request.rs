use axum::http::HeaderMap;
use axum::http::header::HOST;
use rustid_core::issuer::RequestOrigin;

use crate::ProtocolState;

/// A request's origin and its path relative to the path base.
pub(crate) struct Route {
    pub origin: RequestOrigin,
    /// Path after the path base, in the request's own casing.
    pub path: String,
    /// The raw query string without `?`, empty when there is none.
    pub query: String,
    /// The TLS client certificate the request came with.
    pub client_certificate:
        Option<std::sync::Arc<rustid_core::client_certificate::ClientCertificate>>,
}

impl Route {
    /// `None` when the request has no usable Host header.
    pub fn parse(
        state: &ProtocolState,
        headers: &HeaderMap,
        uri: &axum::http::Uri,
        https: bool,
    ) -> Option<Route> {
        let path = uri.path();
        let host = headers.get(HOST)?.to_str().ok()?.to_owned();
        if !is_valid_host(&host) {
            return None;
        }
        let decoded = decode_path(path);
        let path = decoded.as_str();
        let (base_path, rest) = match state
            .path_base
            .as_deref()
            .and_then(|base| strip_segment_prefix(path, base).map(|rest| (base.len(), rest)))
        {
            Some((len, rest)) => (path[..len].to_owned(), rest.to_owned()),
            None => (String::new(), path.to_owned()),
        };
        Some(Route {
            origin: RequestOrigin {
                scheme: if https { "https" } else { "http" }.to_owned(),
                host,
                base_path,
            },
            path: rest,
            query: uri.query().unwrap_or_default().to_owned(),
            client_certificate: None,
        })
    }
}

impl Route {
    /// Whether the request arrived over TLS, which makes cookies `Secure`.
    pub fn is_https(&self) -> bool {
        self.origin.scheme == "https"
    }
}

/// What an endpoint gets besides the body: where the request arrived, its
/// method and headers, who sent it (for events) and the browser's session.
pub(crate) struct Incoming<'a> {
    pub route: &'a Route,
    pub method: &'a axum::http::Method,
    pub headers: &'a HeaderMap,
    pub info: &'a rustid_core::events::RequestInfo,
    pub session: Option<&'a rustid_core::session::UserSession>,
}

/// Case-insensitive segment prefix match: returns the remainder when `path` equals `prefix` or continues with `/`.
pub(crate) fn strip_segment_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let head = path.get(..prefix.len())?;
    if !head.eq_ignore_ascii_case(prefix) {
        return None;
    }
    let rest = &path[prefix.len()..];
    (rest.is_empty() || rest.starts_with('/')).then_some(rest)
}

/// RFC 3986 `host [ ":" port ]` as a Host header must be: an
/// IPv6 literal in brackets or a reg-name, then an optional numeric port.
/// Anything else would end up verbatim in the issuer and every URL.
pub fn is_valid_host(host: &str) -> bool {
    let valid_port = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    if let Some(rest) = host.strip_prefix('[') {
        let Some((literal, after)) = rest.split_once(']') else {
            return false;
        };
        let literal_ok = !literal.is_empty()
            && literal
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
        return literal_ok && (after.is_empty() || after.strip_prefix(':').is_some_and(valid_port));
    }
    let (name, port) = match host.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host, None),
    };
    if name.is_empty() || !port.is_none_or(valid_port) {
        return false;
    }
    let bytes = name.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            let hex = |j: usize| bytes.get(j).is_some_and(u8::is_ascii_hexdigit);
            if !(hex(i + 1) && hex(i + 2)) {
                return false;
            }
            i += 3;
            continue;
        }
        let unreserved_or_sub_delim = b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&b);
        if !unreserved_or_sub_delim {
            return false;
        }
        i += 1;
    }
    true
}

/// Percent-decodes a request path before routing:
/// Every valid escape is decoded except `%2F`, which stays encoded so it can
/// never become a path separator. Invalid escapes are kept literally.
pub(crate) fn decode_path(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let (Some(h), Some(l)) = (
                bytes.get(i + 1).and_then(hex),
                bytes.get(i + 2).and_then(hex),
            )
        {
            let decoded = h * 16 + l;
            if decoded == b'/' {
                out.extend_from_slice(&bytes[i..i + 3]);
            } else {
                out.push(decoded);
            }
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: &u8) -> Option<u8> {
    (*b as char).to_digit(16).map(|d| d as u8)
}
