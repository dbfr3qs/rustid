//! IdP metadata: the `EntityDescriptor` the XML writer writes, and the path
//! it is served at.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};

use crate::constants::{NS_METADATA, NS_PROTOCOL, NS_XMLDSIG};
use crate::ids::create_id;
use crate::options::SamlOptions;
use crate::xml::writer::{XmlElement, write};

/// The configured entity id, or the OIDC issuer
/// plus `entity_id_path`.
pub fn saml_issuer(options: &SamlOptions, oidc_issuer: &str) -> String {
    match &options.entity_id {
        Some(entity_id) => entity_id.clone(),
        None => format!("{oidc_issuer}{}", options.entity_id_path),
    }
}

/// The entity id's path when it's an absolute
/// http(s) URL with a path other than `/`; otherwise `entity_id_path`.
pub fn metadata_path(options: &SamlOptions) -> String {
    if let Some(url) = options
        .entity_id
        .as_deref()
        .and_then(|e| url::Url::parse(e).ok())
        && matches!(url.scheme(), "http" | "https")
        && url.path() != "/"
    {
        return url.path().to_owned();
    }
    options.entity_id_path.clone()
}

/// An `xs:duration` for whole seconds.
pub fn xs_duration(seconds: i64) -> String {
    let sign = if seconds < 0 { "-" } else { "" };
    let s = seconds.unsigned_abs();
    let (days, hours, minutes, secs) = (s / 86_400, s / 3_600 % 24, s / 60 % 60, s % 60);
    let mut out = format!("{sign}P");
    if days > 0 {
        out.push_str(&format!("{days}D"));
    }
    if hours > 0 || minutes > 0 || secs > 0 || days == 0 {
        out.push('T');
        if hours > 0 {
            out.push_str(&format!("{hours}H"));
        }
        if minutes > 0 {
            out.push_str(&format!("{minutes}M"));
        }
        if secs > 0 || (days == 0 && hours == 0 && minutes == 0) {
            out.push_str(&format!("{secs}S"));
        }
    }
    out
}

/// The metadata document: the IdP's entity descriptor with a
/// signing key descriptor per certificate (DER), the SLO and SSO services
/// at `base_url` (trailing `/` trimmed), and the supported name-id formats.
pub fn write_metadata(
    options: &SamlOptions,
    issuer: &str,
    certificates: &[Vec<u8>],
    base_url: &str,
    now: DateTime<Utc>,
) -> String {
    let md = |local: &str| XmlElement::new("md", local, NS_METADATA);
    let ds = |local: &str| XmlElement::new("ds", local, NS_XMLDSIG);
    let base = base_url.trim_end_matches('/');
    let services = |name: &str, bindings: &[String], path: &str| {
        bindings
            .iter()
            .map(|binding| {
                md(name)
                    .attr("Binding", binding.as_str())
                    .attr("Location", format!("{base}{path}"))
            })
            .collect::<Vec<_>>()
    };
    let endpoints = &options.endpoints;
    let valid_until = now + chrono::Duration::seconds(options.metadata.expiry_duration.0);
    let mut idp = md("IDPSSODescriptor").attr("protocolSupportEnumeration", NS_PROTOCOL);
    if options.want_authn_requests_signed {
        idp = idp.attr("WantAuthnRequestsSigned", "true");
    }
    let idp = idp
        .children(certificates.iter().map(|cert| {
            md("KeyDescriptor").attr("use", "signing").child(
                ds("KeyInfo")
                    .child(ds("X509Data").child(ds("X509Certificate").text(STANDARD.encode(cert)))),
            )
        }))
        .children(services(
            "SingleLogoutService",
            &endpoints.single_logout_service_bindings,
            &endpoints.single_logout_service_path,
        ))
        .children(
            options
                .supported_name_id_formats
                .iter()
                .map(|format| md("NameIDFormat").text(format.as_str())),
        )
        .children(services(
            "SingleSignOnService",
            &endpoints.single_sign_on_service_bindings,
            &endpoints.single_sign_on_service_path,
        ));
    let entity = md("EntityDescriptor")
        .attr("ID", create_id())
        .attr("entityID", issuer)
        .attr(
            "cacheDuration",
            xs_duration(options.metadata.cache_duration.0),
        )
        .attr(
            "validUntil",
            valid_until.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        )
        .child(idp);
    write(&entity)
}
