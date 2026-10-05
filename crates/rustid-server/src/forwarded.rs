//! Forwarded headers from a trusted reverse proxy, one hop: the rightmost
//! `X-Forwarded-Proto`, `X-Forwarded-Host` and `X-Forwarded-For` values
//! become the request's scheme, host and client address, but only when the
//! TCP peer is one of `forwarded_headers.trusted_proxies`. A trusted proxy
//! may also forward the client's TLS certificate in a configured header
//! (`mutual_tls.forwarded_certificate_header`), as a certificate
//! forwarding does.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::HOST;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

/// `forwarded_headers`: nobody is trusted unless listed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ForwardedHeadersConfig {
    /// Proxies whose forwarded headers are believed: IP addresses or CIDR
    /// networks (`10.0.0.0/8`, `::1`).
    pub trusted_proxies: Vec<Network>,
}

/// An IP network: an address and a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    address: IpAddr,
    prefix: u8,
}

impl FromStr for Network {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || format!("`{text}` is not an IP address or CIDR network");
        let (address, prefix) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let address: IpAddr = address.trim().parse().map_err(|_| invalid())?;
        let max = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.trim().parse::<u8>().map_err(|_| invalid())?,
            None => max,
        };
        if prefix > max {
            return Err(invalid());
        }
        Ok(Network { address, prefix })
    }
}

impl<'de> Deserialize<'de> for Network {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl Network {
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        let bits = |a: IpAddr| -> u128 {
            match a {
                IpAddr::V4(v4) => u128::from(u32::from(v4)),
                IpAddr::V6(v6) => u128::from(v6),
            }
        };
        let width = if self.address.is_ipv4() { 32 } else { 128 };
        if ip.is_ipv4() != self.address.is_ipv4() {
            return false;
        }
        if self.prefix == 0 {
            return true;
        }
        let shift = width - u32::from(self.prefix);
        bits(ip) >> shift == bits(self.address) >> shift
    }
}

/// The rightmost value of a comma-separated header, trimmed.
fn rightmost<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let value = headers.get_all(name).iter().next_back()?.to_str().ok()?;
    let last = value.rsplit(',').next()?.trim();
    (!last.is_empty()).then_some(last)
}

/// What a trusted proxy said about the original request.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Forwarded {
    pub https: Option<bool>,
    pub host: Option<String>,
    pub client: Option<SocketAddr>,
}

/// A forwarded host that isn't a valid `host[:port]`.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidForwardedHost;

/// Reads the forwarded headers.
pub fn read(headers: &HeaderMap) -> Result<Forwarded, InvalidForwardedHost> {
    let https = match rightmost(headers, "x-forwarded-proto").map(str::to_ascii_lowercase) {
        Some(p) if p == "https" => Some(true),
        Some(p) if p == "http" => Some(false),
        _ => None,
    };
    let host = match rightmost(headers, "x-forwarded-host") {
        Some(h) if rustid_http::is_valid_host(h) => Some(h.to_owned()),
        Some(_) => return Err(InvalidForwardedHost),
        None => None,
    };
    let client = rightmost(headers, "x-forwarded-for").and_then(|f| {
        f.parse::<SocketAddr>()
            .ok()
            .or_else(|| f.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 0)))
    });
    Ok(Forwarded {
        https,
        host,
        client,
    })
}

/// Who is trusted, and how a forwarded client certificate arrives.
#[derive(Debug)]
pub struct Trusted {
    pub proxies: Vec<Network>,
    pub certificate_header: Option<axum::http::HeaderName>,
    pub client_ca_roots: Option<Arc<rustid_core::client_certificate::ClientCaRoots>>,
}

/// A forwarded certificate: URL-encoded PEM (nginx's
/// `$ssl_client_escaped_cert`), PEM, or base64 DER (the default).
pub fn decode_certificate(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    let text = if value.contains('%') {
        url::form_urlencoded::parse(format!("v={}", value.replace('+', "%2B")).as_bytes())
            .next()
            .map(|(_, v)| v.into_owned())?
    } else {
        value.to_owned()
    };
    if text.contains("-----BEGIN") {
        return pem::parse(text.as_bytes())
            .ok()
            .filter(|p| p.tag() == "CERTIFICATE")
            .map(pem::Pem::into_contents);
    }
    use base64::Engine;
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .ok()
}

/// The middleware: applies a trusted proxy's forwarded headers.
pub async fn apply(
    State(trusted): State<Arc<Trusted>>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    if !peer.is_some_and(|ip| trusted.proxies.iter().any(|n| n.contains(ip))) {
        return next.run(request).await;
    }
    if let Some(header) = &trusted.certificate_header {
        // The proxy's own certificate isn't the client's.
        request
            .extensions_mut()
            .remove::<rustid_http::TlsClientCertificate>();
        let forwarded = request
            .headers()
            .get(header)
            .and_then(|v| v.to_str().ok())
            .and_then(decode_certificate)
            .and_then(|der| {
                rustid_core::client_certificate::ClientCertificate::parse(
                    &der,
                    trusted.client_ca_roots.as_deref(),
                )
            });
        match forwarded {
            Some(cert) => {
                request
                    .extensions_mut()
                    .insert(rustid_http::TlsClientCertificate(Arc::new(cert)));
            }
            None if request.headers().contains_key(header) => {
                tracing::debug!("a forwarded client certificate could not be read");
            }
            None => {}
        }
    }
    let Ok(forwarded) = read(request.headers()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match forwarded.https {
        Some(true) => {
            request.extensions_mut().insert(rustid_http::Https);
        }
        Some(false) => {
            request.extensions_mut().remove::<rustid_http::Https>();
        }
        None => {}
    }
    if let Some(host) = forwarded.host
        && let Ok(value) = HeaderValue::from_str(&host)
    {
        request.headers_mut().insert(HOST, value);
    }
    if let Some(client) = forwarded.client {
        request.extensions_mut().insert(ConnectInfo(client));
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn networks_contain_their_addresses() {
        let n: Network = "10.1.0.0/16".parse().unwrap();
        assert!(n.contains("10.1.255.3".parse().unwrap()));
        assert!(!n.contains("10.2.0.1".parse().unwrap()));
        assert!(
            n.contains("::ffff:10.1.0.9".parse().unwrap()),
            "IPv4-mapped"
        );
        let one: Network = "::1".parse().unwrap();
        assert!(one.contains("::1".parse().unwrap()));
        assert!(!one.contains("127.0.0.1".parse().unwrap()));
        let any: Network = "0.0.0.0/0".parse().unwrap();
        assert!(any.contains("203.0.113.9".parse().unwrap()));
        assert!("1.2.3.4/33".parse::<Network>().is_err());
    }

    #[test]
    fn the_rightmost_values_are_read() {
        let f = read(&headers(&[
            ("x-forwarded-proto", "https, http"),
            ("x-forwarded-host", "a.test, b.test:8443"),
            ("x-forwarded-for", "198.51.100.1, 203.0.113.7"),
        ]))
        .unwrap();
        assert_eq!(
            f,
            Forwarded {
                https: Some(false),
                host: Some("b.test:8443".into()),
                client: Some("203.0.113.7:0".parse().unwrap()),
            }
        );
        let f = read(&headers(&[
            ("x-forwarded-proto", "ftp"),
            ("x-forwarded-for", "[2001:db8::1]:4711"),
        ]))
        .unwrap();
        assert_eq!(f.https, None);
        assert_eq!(f.client, Some("[2001:db8::1]:4711".parse().unwrap()));
        assert!(read(&headers(&[("x-forwarded-host", "a b")])).is_err());
    }
}
