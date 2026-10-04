//! Issuer and base URL derivation, mirroring the issuer name service and
//! `DefaultServerUrls`.

use crate::options::ProtocolOptions;

/// Where a request arrived, as the HTTP layer sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOrigin {
    /// `http` or `https`.
    pub scheme: String,
    /// The Host header exactly as sent (ASCII, Punycode for IDNs, may carry a port).
    pub host: String,
    /// The matched path base in the request's own casing, `""` when none.
    pub base_path: String,
}

impl RequestOrigin {
    /// Origin: scheme and Host in URI (Punycode) form.
    pub fn origin(&self) -> String {
        format!("{}://{}", self.scheme, self.host)
    }

    /// Base url: origin plus path base.
    pub fn base_url(&self) -> String {
        format!("{}{}", self.origin(), self.base_path)
    }

    /// `GetUnicodeOrigin()`: Punycode labels decoded, port preserved.
    pub fn unicode_origin(&self) -> String {
        format!("{}://{}", self.scheme, unicode_host(&self.host))
    }
}

fn unicode_host(host: &str) -> String {
    if host.starts_with('[') {
        return host.to_owned(); // IPv6 literal
    }
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (name, Some(port))
        }
        _ => (host, None),
    };
    let has_punycode = name
        .split('.')
        .any(|label| label.len() > 4 && label.as_bytes()[..4].eq_ignore_ascii_case(b"xn--"));
    let name = if has_punycode {
        let (unicode, result) = idna::domain_to_unicode(name);
        if result.is_ok() {
            unicode
        } else {
            name.to_owned()
        }
    } else {
        name.to_owned()
    };
    match port {
        Some(port) => format!("{name}:{port}"),
        None => name,
    }
}

/// The issuer name service. A configured issuer wins verbatim;
/// otherwise the Unicode origin plus path base, lower-cased unless disabled.
pub fn current_issuer(options: &ProtocolOptions, request: &RequestOrigin) -> String {
    if let Some(issuer) = options
        .issuer_uri
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        return issuer.to_owned();
    }
    let issuer = format!("{}{}", request.unicode_origin(), request.base_path);
    if options.lower_case_issuer_uri {
        issuer.to_lowercase()
    } else {
        issuer
    }
}
