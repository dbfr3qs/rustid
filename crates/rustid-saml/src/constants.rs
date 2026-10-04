//! SAML URIs.

pub const BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
pub const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

pub const NAME_ID_EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
pub const NAME_ID_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

pub const AUTHN_CONTEXT_PASSWORD_PROTECTED: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
pub const AUTHN_CONTEXT_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";

pub const NAME_ID_PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
pub const NAME_ID_TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

pub const NS_METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
pub const NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const NS_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const NS_XMLDSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

/// `SamlConstants.ContentTypes.Metadata`.
pub const CONTENT_TYPE_METADATA: &str = "application/samlmetadata+xml";
