//! HTTP-Redirect (`HttpRedirectBinding`): the message DEFLATE-compressed and
//! base64-encoded in the query, signed over the raw query text.

use std::io::Read;

use super::{BindingError, MessageName, error, from_base64};
use crate::xml::dsig::{XmlSigner, verify_bytes};

/// The binding's query parameters (`ParseQueryString`). `signed_content` is
/// rebuilt from the raw encoded values in the binding's order, only when a
/// signature and algorithm are present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameters {
    pub name: MessageName,
    /// The decoded parameter value (still base64).
    pub message: String,
    pub relay_state: Option<String>,
    pub signature: Option<String>,
    pub sig_alg: Option<String>,
    pub signed_content: Option<String>,
}

/// An unbound redirect message: its XML text and relay state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub name: MessageName,
    pub xml: String,
    pub relay_state: Option<String>,
    pub signature: Option<String>,
    pub sig_alg: Option<String>,
    pub signed_content: Option<String>,
}

/// What a query signature check needs.
pub trait Signed {
    fn signed_content(&self) -> Option<&str>;
    fn signature(&self) -> Option<&str>;
    fn sig_alg(&self) -> Option<&str>;
}

impl Signed for Parameters {
    fn signed_content(&self) -> Option<&str> {
        self.signed_content.as_deref()
    }
    fn signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }
    fn sig_alg(&self) -> Option<&str> {
        self.sig_alg.as_deref()
    }
}

impl Signed for Parsed {
    fn signed_content(&self) -> Option<&str> {
        self.signed_content.as_deref()
    }
    fn signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }
    fn sig_alg(&self) -> Option<&str> {
        self.sig_alg.as_deref()
    }
}

/// `Uri.UnescapeDataString`: valid `%XX` escapes decoded (as UTF-8), the
/// rest left as written.
fn unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            )
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `QueryStringEnumerable.DecodeValue`: '+' is a space, then escapes.
fn decode_value(raw: &str) -> String {
    unescape(&raw.replace('+', " "))
}

/// `Uri.EscapeDataString`: everything but RFC 3986 unreserved characters is
/// percent-encoded, upper case.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn parse_parameters(query: &str) -> Result<Parameters, BindingError> {
    let query = query.strip_prefix('?').unwrap_or(query);
    let mut message: Option<(MessageName, String, String)> = None;
    let mut relay_state: Option<(String, String)> = None;
    let mut sig_alg: Option<(String, String)> = None;
    let mut signature: Option<String> = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        match name {
            "SAMLRequest" | "SAMLResponse" => {
                if let Some((existing, _, _)) = &message {
                    return Err(error(format!(
                        "Duplicate message parameters found: {}, {name}",
                        existing.as_str()
                    )));
                }
                let kind = if name == "SAMLRequest" {
                    MessageName::SamlRequest
                } else {
                    MessageName::SamlResponse
                };
                message = Some((kind, decode_value(value), value.to_owned()));
            }
            "RelayState" => {
                if relay_state.is_some() {
                    return Err(error("Duplicate RelayState parameters found"));
                }
                relay_state = Some((decode_value(value), value.to_owned()));
            }
            "SigAlg" => {
                if sig_alg.is_some() {
                    return Err(error("Duplicate SigAlg parameters found"));
                }
                sig_alg = Some((decode_value(value), value.to_owned()));
            }
            "Signature" => {
                if signature.is_some() {
                    return Err(error("Duplicate Signature parameters found"));
                }
                signature = Some(decode_value(value));
            }
            _ => {}
        }
    }
    let Some((name, message, message_raw)) = message else {
        return Err(error("SAMLResponse or SAMLRequest parameter not found"));
    };
    // Empty values count as absent.
    let signature = signature.filter(|s| !s.is_empty());
    let sig_alg = sig_alg.filter(|(s, _)| !s.is_empty());
    let signed_content = match (&signature, &sig_alg) {
        (Some(_), Some((_, alg_raw))) => {
            let mut content = format!("{}={message_raw}", name.as_str());
            if let Some((_, raw)) = &relay_state {
                content.push_str("&RelayState=");
                content.push_str(raw);
            }
            content.push_str("&SigAlg=");
            content.push_str(alg_raw);
            Some(content)
        }
        _ => None,
    };
    Ok(Parameters {
        name,
        message,
        relay_state: relay_state.map(|(v, _)| v),
        signature,
        sig_alg: sig_alg.map(|(v, _)| v),
        signed_content,
    })
}

/// `Inflate`: the message unescaped (again), base64-decoded
/// and inflated, stopping at `max_size` bytes.
fn inflate(message: &str, max_size: usize) -> Result<String, BindingError> {
    let compressed = from_base64(&unescape(message))?;
    let mut inflated = Vec::new();
    let mut decoder =
        flate2::read::DeflateDecoder::new(compressed.as_slice()).take(max_size as u64 + 1);
    decoder
        .read_to_end(&mut inflated)
        .map_err(|e| error(format!("The SAML message could not be inflated: {e}")))?;
    if inflated.len() > max_size {
        return Err(error("Maximum stream size exceeded."));
    }
    Ok(String::from_utf8_lossy(&inflated).into_owned())
}

/// Un bind up to signature validation: the parameters, the inflated
/// XML, the relay state limit (UTF-8 bytes), and complete signature
/// parameters.
pub fn parse(query: &str, max_size: usize, max_relay_state: usize) -> Result<Parsed, BindingError> {
    let p = parse_parameters(query)?;
    let xml = inflate(&p.message, max_size)?;
    if p.relay_state
        .as_ref()
        .is_some_and(|r| r.len() > max_relay_state)
    {
        return Err(error(format!(
            "RelayState exceeds maximum allowed size of {max_relay_state} bytes."
        )));
    }
    if p.signature.is_some() != p.sig_alg.is_some() {
        return Err(error("Incomplete redirect binding signature parameters"));
    }
    Ok(Parsed {
        name: p.name,
        xml,
        relay_state: p.relay_state,
        signature: p.signature,
        sig_alg: p.sig_alg,
        signed_content: p.signed_content,
    })
}

/// `ValidateSignature`: the algorithm allowed, and the signature verifying
/// with one of the certificates. The key type follows the certificate, so
/// an RSA certificate never checks an ECDSA algorithm or the reverse.
pub fn verify_signature(query: &impl Signed, certificates: &[Vec<u8>], allowed: &[&str]) -> bool {
    let (Some(content), Some(signature), Some(alg)) =
        (query.signed_content(), query.signature(), query.sig_alg())
    else {
        return false;
    };
    if !allowed.contains(&alg) {
        return false;
    }
    let Ok(signature) = from_base64(signature) else {
        return false;
    };
    certificates
        .iter()
        .any(|c| verify_bytes(c, alg, content.as_bytes(), &signature))
}

/// `GetQueryString`: `?{name}={deflated}`, the relay state, and when a
/// credential is given, `SigAlg` and `Signature` over the rest.
pub fn encode(
    name: MessageName,
    xml: &str,
    relay_state: Option<&str>,
    signer: Option<&dyn XmlSigner>,
) -> Result<String, BindingError> {
    use std::io::Write;
    let mut deflater = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    deflater
        .write_all(xml.as_bytes())
        .and_then(|_| deflater.try_finish())
        .map_err(|e| error(e.to_string()))?;
    let compressed = deflater.finish().map_err(|e| error(e.to_string()))?;
    let encoded = {
        use base64::Engine;
        escape(&base64::engine::general_purpose::STANDARD.encode(compressed))
    };
    let mut content = format!("{}={encoded}", name.as_str());
    if let Some(relay_state) = relay_state {
        content.push_str("&RelayState=");
        content.push_str(&escape(relay_state));
    }
    let Some(signer) = signer else {
        return Ok(format!("?{content}"));
    };
    content.push_str("&SigAlg=");
    content.push_str(&escape(signer.signature_method()));
    let signature = signer
        .sign_bytes(content.as_bytes())
        .map_err(|e| error(e.to_string()))?;
    let signature = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(signature)
    };
    Ok(format!("?{content}&Signature={}", escape(&signature)))
}
