//! Client certificates (RFC 8705): what client authentication and bound
//! tokens read from a TLS client certificate,
//! exposes it (`Thumbprint`, `Subject`), and whether its chain is trusted
//! by the configured client CA roots.

use aws_lc_rs::digest;
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use serde_json::json;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::jwt::b64url;

/// Roots a client certificate chain must lead to for its subject name to
/// be believed (`tls_client_auth`).
#[derive(Debug, Clone)]
pub struct ClientCaRoots {
    anchors: Vec<TrustAnchor<'static>>,
}

impl ClientCaRoots {
    /// Every certificate in a PEM bundle.
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, String> {
        let blocks = pem::parse_many(pem_bytes).map_err(|e| e.to_string())?;
        let mut anchors = Vec::new();
        for block in blocks.iter().filter(|b| b.tag() == "CERTIFICATE") {
            let der = CertificateDer::from(block.contents().to_vec());
            let anchor = webpki::anchor_from_trusted_cert(&der)
                .map_err(|e| format!("a client CA certificate: {e}"))?;
            anchors.push(anchor.to_owned());
        }
        if anchors.is_empty() {
            return Err("no certificates in the client CA file".into());
        }
        Ok(ClientCaRoots { anchors })
    }

    /// Whether `der`, with `intermediates`, chains to a root for client
    /// authentication at `now`.
    fn trusts(&self, der: &[u8], intermediates: &[CertificateDer<'_>]) -> bool {
        let der = CertificateDer::from(der);
        let Ok(cert) = webpki::EndEntityCert::try_from(&der) else {
            return false;
        };
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &self.anchors,
            intermediates,
            UnixTime::now(),
            webpki::KeyUsage::client_auth(),
            None,
            None,
        )
        .is_ok()
    }
}

/// A request's client certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificate {
    pub der: Vec<u8>,
    /// SHA-1 of the DER, uppercase hex (`X509Certificate2.Thumbprint`).
    pub thumbprint: String,
    /// SHA-256 of the DER, base64url (`x5t#S256`).
    pub x5t_s256: String,
    /// The subject as `X500DistinguishedName.Name` formats it.
    pub subject: String,
    /// The chain leads to a configured client CA root.
    pub trusted: bool,
    /// The validity period, Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
}

impl ClientCertificate {
    /// Reads a DER certificate; its trust is checked against `roots`.
    pub fn parse(der: &[u8], roots: Option<&ClientCaRoots>) -> Option<Self> {
        Self::parse_chain(der, &[], roots)
    }

    /// As [`ClientCertificate::parse`], with the intermediates the client
    /// sent after its certificate.
    pub fn parse_chain(
        der: &[u8],
        intermediates: &[CertificateDer<'_>],
        roots: Option<&ClientCaRoots>,
    ) -> Option<Self> {
        let (_, cert) = X509Certificate::from_der(der).ok()?;
        let subject = subject_name_text(&cert);
        let validity = cert.validity();
        let sha1 = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, der);
        Some(ClientCertificate {
            der: der.to_vec(),
            thumbprint: sha1.as_ref().iter().map(|b| format!("{b:02X}")).collect(),
            x5t_s256: b64url(digest::digest(&digest::SHA256, der).as_ref()),
            subject,
            trusted: roots.is_some_and(|r| r.trusts(der, intermediates)),
            not_before: validity.not_before.timestamp(),
            not_after: validity.not_after.timestamp(),
        })
    }

    /// Whether `now` is within the certificate's validity period (the
    /// certificate authentication handler's `ValidateValidityPeriod`).
    pub fn valid_at(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        (self.not_before..=self.not_after).contains(&now.timestamp())
    }

    /// `CreateThumbprintCnf`: the `cnf` binding a token to the certificate.
    pub fn cnf(&self) -> String {
        json!({ "x5t#S256": self.x5t_s256 }).to_string()
    }
}

/// The short names for attribute types.
fn short_name(oid: &str) -> String {
    let name = match oid {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "S",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "1.2.840.113549.1.9.1" => "E",
        "2.5.4.9" => "STREET",
        "2.5.4.12" => "T",
        "2.5.4.42" => "G",
        "2.5.4.43" => "I",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "SERIALNUMBER",
        "0.9.2342.19200300.100.1.25" => "DC",
        other => return format!("OID.{other}"),
    };
    name.to_owned()
}

/// A value quoted when it holds a special character or edge whitespace,
/// with inner quotes doubled.
fn quoted(value: &str) -> String {
    let special = value.is_empty()
        || value.starts_with(char::is_whitespace)
        || value.ends_with(char::is_whitespace)
        || value.contains([',', '+', '=', '"', '\n', '<', '>', '#', ';']);
    if special {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

/// `X500DistinguishedName.Name`: RDNs most-specific first, `, `-separated;
/// a multi-valued RDN's attributes joined by ` + `.
fn subject_name_text(cert: &X509Certificate<'_>) -> String {
    let rdns: Vec<String> =
        cert.subject()
            .iter_rdn()
            .map(|rdn| {
                rdn.iter()
                    .map(|attr| {
                        let value = attr.as_str().map(str::to_owned).unwrap_or_else(|_| {
                            String::from_utf8_lossy(attr.as_slice()).into_owned()
                        });
                        format!(
                            "{}={}",
                            short_name(&attr.attr_type().to_id_string()),
                            quoted(&value)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" + ")
            })
            .collect();
    rdns.into_iter().rev().collect::<Vec<_>>().join(", ")
}

/// `endpoint`
/// (`connect/token`) as an mTLS alias of `base_url` (origin and path base):
/// under `connect/mtls/`, on the mTLS domain, or on the mTLS subdomain.
pub fn mtls_endpoint(
    options: &crate::options::MutualTlsOptions,
    base_url: &str,
    endpoint: &str,
) -> String {
    let base = format!("{}/", base_url.trim_end_matches('/'));
    match options.domain_name.as_deref().filter(|d| !d.is_empty()) {
        None => format!("{base}{}", endpoint.replacen("connect", "connect/mtls", 1)),
        Some(domain) if domain.contains('.') => format!("https://{domain}/{endpoint}"),
        Some(label) => {
            let rest = base.split_once("://").map_or(base.as_str(), |(_, r)| r);
            format!("https://{label}.{rest}{endpoint}")
        }
    }
}
