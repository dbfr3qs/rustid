//! Enveloped XML signatures as the SAML IdP makes and checks them: one
//! reference to the signature's parent by its `ID`,
//! enveloped and exclusive-canonicalization transforms, RSA or ECDSA keys
//! from X.509 certificates. Verification checks the SignedInfo signature,
//! then the reference digest.

use aws_lc_rs::{digest, rand, signature};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use x509_parser::prelude::FromDer;

use super::c14n::{Options, canonicalize, canonicalize_in};
use super::dom::{self, Document, Element, Limits, XmlError};

pub const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

pub mod algorithms {
    pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
    pub const EXC_C14N_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
    pub const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    pub const C14N_COMMENTS: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    pub const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
    pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
    pub const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    pub const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
    pub const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    pub const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    pub const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    pub const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    pub const ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    pub const ECDSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
}
use algorithms::*;

/// The signature algorithms allowed by default.
pub const DEFAULT_ALLOWED: &[&str] = &[
    SHA256,
    SHA384,
    SHA512,
    RSA_SHA256,
    RSA_SHA384,
    RSA_SHA512,
    ECDSA_SHA256,
    ECDSA_SHA384,
    ECDSA_SHA512,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Curve {
    P256,
    P384,
    P521,
}

enum Key {
    Rsa(signature::RsaKeyPair),
    Ecdsa(signature::EcdsaKeyPair, Curve),
}

/// A signing key with its X.509 certificate.
pub struct Credential {
    key: Key,
    certificate: Vec<u8>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("signature_method", &self.signature_method())
            .finish_non_exhaustive()
    }
}

fn err(message: impl Into<String>) -> XmlError {
    XmlError(message.into())
}

impl Credential {
    /// A certificate PEM and its PKCS#8 private key PEM (RSA, or ECDSA on
    /// P-256, P-384 or P-521).
    pub fn from_pem(certificate_pem: &str, key_pem: &str) -> Result<Self, XmlError> {
        let certificate = pem::parse(certificate_pem)
            .map_err(|e| err(format!("certificate: {e}")))?
            .into_contents();
        let key = pem::parse(key_pem).map_err(|e| err(format!("key: {e}")))?;
        let pkcs8 = key.contents();
        let key = if let Ok(rsa) = signature::RsaKeyPair::from_pkcs8(pkcs8) {
            Key::Rsa(rsa)
        } else {
            [
                (Curve::P256, &signature::ECDSA_P256_SHA256_FIXED_SIGNING),
                (Curve::P384, &signature::ECDSA_P384_SHA384_FIXED_SIGNING),
                (Curve::P521, &signature::ECDSA_P521_SHA512_FIXED_SIGNING),
            ]
            .into_iter()
            .find_map(|(curve, alg)| {
                signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8)
                    .ok()
                    .map(|k| Key::Ecdsa(k, curve))
            })
            .ok_or_else(|| err("the key is not an RSA or P-256/384/521 ECDSA PKCS#8 key"))?
        };
        Ok(Credential { key, certificate })
    }

    /// The certificate, DER.
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// The signature method: RSA-SHA256, or ECDSA with the hash matching the
    /// curve's strength.
    pub fn signature_method(&self) -> &'static str {
        match &self.key {
            Key::Rsa(_) => RSA_SHA256,
            Key::Ecdsa(_, Curve::P256) => ECDSA_SHA256,
            Key::Ecdsa(_, Curve::P384) => ECDSA_SHA384,
            Key::Ecdsa(_, Curve::P521) => ECDSA_SHA512,
        }
    }

    /// The reference digest method matching the signature method.
    pub fn digest_method(&self) -> &'static str {
        match &self.key {
            Key::Ecdsa(_, Curve::P384) => SHA384,
            Key::Ecdsa(_, Curve::P521) => SHA512,
            _ => SHA256,
        }
    }

    /// Signs bytes with the signature method.
    pub fn sign_bytes(&self, data: &[u8]) -> Result<Vec<u8>, XmlError> {
        let rng = rand::SystemRandom::new();
        match &self.key {
            Key::Rsa(key) => {
                let mut out = vec![0; key.public_modulus_len()];
                key.sign(&signature::RSA_PKCS1_SHA256, &rng, data, &mut out)
                    .map_err(|_| err("RSA signing failed"))?;
                Ok(out)
            }
            Key::Ecdsa(key, _) => key
                .sign(&rng, data)
                .map(|s| s.as_ref().to_vec())
                .map_err(|_| err("ECDSA signing failed")),
        }
    }
}

/// A key that signs XML: its certificate (published in `KeyInfo`), its
/// signature and digest methods, and raw signing.
pub trait XmlSigner {
    fn certificate(&self) -> &[u8];
    fn signature_method(&self) -> &'static str;
    fn digest_method(&self) -> &'static str;
    fn sign_bytes(&self, data: &[u8]) -> Result<Vec<u8>, XmlError>;
}

impl XmlSigner for Credential {
    fn certificate(&self) -> &[u8] {
        Credential::certificate(self)
    }
    fn signature_method(&self) -> &'static str {
        Credential::signature_method(self)
    }
    fn digest_method(&self) -> &'static str {
        Credential::digest_method(self)
    }
    fn sign_bytes(&self, data: &[u8]) -> Result<Vec<u8>, XmlError> {
        Credential::sign_bytes(self, data)
    }
}

fn digest_with(method: &str, data: &[u8]) -> Option<Vec<u8>> {
    let algorithm = match method {
        SHA1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        SHA256 => &digest::SHA256,
        SHA384 => &digest::SHA384,
        SHA512 => &digest::SHA512,
        _ => return None,
    };
    Some(digest::digest(algorithm, data).as_ref().to_vec())
}

/// Whether `signature` over `data` verifies with the certificate's key under
/// `method`. Unsupported combinations don't verify.
pub fn verify_bytes(certificate: &[u8], method: &str, data: &[u8], sig: &[u8]) -> bool {
    let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(certificate) else {
        return false;
    };
    let spki = cert.public_key();
    let key = spki.subject_public_key.data.as_ref();
    match spki.algorithm.algorithm.to_id_string().as_str() {
        "1.2.840.113549.1.1.1" => {
            // RSA keys from 1024 bits are accepted; with no legacy SHA-384
            // verifier, SHA-384 needs 2048.
            let algorithm: &dyn signature::VerificationAlgorithm = match method {
                RSA_SHA1 => &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
                RSA_SHA256 => &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                RSA_SHA384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                RSA_SHA512 => &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
                _ => return false,
            };
            signature::UnparsedPublicKey::new(algorithm, key)
                .verify(data, sig)
                .is_ok()
        }
        "1.2.840.10045.2.1" => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|o| o.to_id_string());
            // Any of the curves with any SHA-2 hash; the
            // fixed-size r||s signature is checked in its DER form.
            let (size, algorithm): (usize, &dyn signature::VerificationAlgorithm) =
                match (curve.as_deref(), method) {
                    (Some(P256), ECDSA_SHA256) => (32, &signature::ECDSA_P256_SHA256_ASN1),
                    (Some(P256), ECDSA_SHA384) => (32, &signature::ECDSA_P256_SHA384_ASN1),
                    (Some(P256), ECDSA_SHA512) => (32, &signature::ECDSA_P256_SHA512_ASN1),
                    (Some(P384), ECDSA_SHA256) => (48, &signature::ECDSA_P384_SHA256_ASN1),
                    (Some(P384), ECDSA_SHA384) => (48, &signature::ECDSA_P384_SHA384_ASN1),
                    (Some(P384), ECDSA_SHA512) => (48, &signature::ECDSA_P384_SHA512_ASN1),
                    (Some(P521), ECDSA_SHA256) => (66, &signature::ECDSA_P521_SHA256_ASN1),
                    (Some(P521), ECDSA_SHA384) => (66, &signature::ECDSA_P521_SHA384_ASN1),
                    (Some(P521), ECDSA_SHA512) => (66, &signature::ECDSA_P521_SHA512_ASN1),
                    _ => return false,
                };
            if sig.len() != size * 2 {
                return false;
            }
            let der = fixed_to_der(&sig[..size], &sig[size..]);
            signature::UnparsedPublicKey::new(algorithm, key)
                .verify(data, &der)
                .is_ok()
        }
        _ => false,
    }
}

const P256: &str = "1.2.840.10045.3.1.7";
const P384: &str = "1.3.132.0.34";
const P521: &str = "1.3.132.0.35";

/// An ECDSA signature in DER: SEQUENCE { INTEGER r, INTEGER s }.
fn fixed_to_der(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn length(out: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            out.push(len as u8);
        } else {
            out.push(0x81);
            out.push(len as u8);
        }
    }
    fn integer(bytes: &[u8]) -> Vec<u8> {
        let start = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let trimmed = &bytes[start..];
        let pad = trimmed[0] & 0x80 != 0;
        let mut out = vec![0x02];
        length(&mut out, trimmed.len() + usize::from(pad));
        if pad {
            out.push(0);
        }
        out.extend_from_slice(trimmed);
        out
    }
    let body = [integer(r), integer(s)].concat();
    let mut out = vec![0x30];
    length(&mut out, body.len());
    out.extend(body);
    out
}

/// Exactly one element whose
/// `ID`, `Id` or `id` is `id`, and its attribute must be `ID`.
fn find_by_id<'d>(root: &'d Element, id: &str) -> Result<&'d Element, String> {
    let found: Vec<&Element> = root
        .descendants()
        .into_iter()
        .filter(|e| ["ID", "Id", "id"].iter().any(|n| e.attr(n) == Some(id)))
        .collect();
    match found.as_slice() {
        [one] if one.attr("ID") == Some(id) => Ok(one),
        [_] => Err("Reference target ID attribute must be named ID with uppercase letters".into()),
        _ => Err("Reference target should resolve to exactly one node".into()),
    }
}

/// Signs the element with `id` (its signature goes after its first child
/// element, the `Issuer`) and returns the new document text.
pub fn sign(
    text: &str,
    id: &str,
    credential: &dyn XmlSigner,
    limits: &Limits,
) -> Result<String, XmlError> {
    let doc = dom::parse(text, limits)?;
    let target = find_by_id(&doc.root, id).map_err(err)?;
    if let Some(problem) = not_interoperable(target) {
        return Err(err(problem));
    }
    let issuer = target
        .elements()
        .next()
        .ok_or_else(|| err("the element to sign has no child to follow"))?;
    // A "#id" reference drops comments before its transforms run.
    let canonical = canonicalize_in(
        &doc,
        target,
        &Options {
            comments: false,
            inclusive: &[],
            exclude: None,
            all_namespaces: false,
        },
    );
    let digest_method = credential.digest_method();
    let digest_value = STANDARD
        .encode(digest_with(digest_method, canonical.as_bytes()).expect("a supported digest"));
    let signature_method = credential.signature_method();
    let signed_info = format!(
        "<SignedInfo><CanonicalizationMethod Algorithm=\"{EXC_C14N_COMMENTS}\" /><SignatureMethod Algorithm=\"{signature_method}\" /><Reference URI=\"#{id}\"><Transforms><Transform Algorithm=\"{ENVELOPED}\" /><Transform Algorithm=\"{EXC_C14N_COMMENTS}\" /></Transforms><DigestMethod Algorithm=\"{digest_method}\" /><DigestValue>{digest_value}</DigestValue></Reference></SignedInfo>"
    );
    // SignedInfo canonicalized in its place: under the Signature's default
    // namespace, where exclusive canonicalization renders only that.
    let wrapper = dom::parse(
        &format!("<Signature xmlns=\"{DSIG}\">{signed_info}</Signature>"),
        limits,
    )?;
    let si = wrapper
        .root
        .child(DSIG, "SignedInfo")
        .expect("just written");
    let canonical_si = canonicalize(
        si,
        &Options {
            comments: true,
            inclusive: &[],
            exclude: None,
            all_namespaces: false,
        },
    );
    let value = STANDARD.encode(credential.sign_bytes(canonical_si.as_bytes())?);
    let certificate = STANDARD.encode(credential.certificate());
    let signature = format!(
        "<Signature xmlns=\"{DSIG}\">{signed_info}<SignatureValue>{value}</SignatureValue><KeyInfo><X509Data><X509Certificate>{certificate}</X509Certificate></X509Data></KeyInfo></Signature>"
    );
    Ok(format!(
        "{}{}{}",
        &doc.text[..issuer.end],
        signature,
        &doc.text[issuer.end..]
    ))
}

/// Content some verifiers canonicalize differently from the XML-DSig
/// specification: they re-read the element from its serialization, so a
/// carriage return in text becomes a line feed and a tab in an attribute
/// value a space. Those verifiers and the specification can't both accept
/// the signature, so such content isn't signed.
fn not_interoperable(element: &Element) -> Option<String> {
    for e in element.descendants() {
        if e.attrs.iter().any(|a| a.value.contains('\t')) {
            return Some(format!(
                "the attribute values of {} contain a tab, which some verifiers canonicalize differently",
                e.local
            ));
        }
        if e.children
            .iter()
            .any(|c| matches!(c, dom::Node::Text(t) if t.contains('\r')))
        {
            return Some(format!(
                "the text of {} contains a carriage return, which some verifiers canonicalize differently",
                e.local
            ));
        }
    }
    None
}

fn prefix_list(transform: &Element) -> Vec<String> {
    transform
        .elements()
        .find(|e| e.local == "InclusiveNamespaces")
        .and_then(|e| e.attr("PrefixList"))
        .map(|l| l.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// The canonicalization options an algorithm URI names, with comments as
/// the algorithm says.
fn c14n_options(algorithm: &str, element: &Element) -> Option<(bool, bool, Vec<String>)> {
    match algorithm {
        EXC_C14N => Some((false, false, prefix_list(element))),
        EXC_C14N_COMMENTS => Some((true, false, prefix_list(element))),
        C14N => Some((false, true, Vec::new())),
        C14N_COMMENTS => Some((true, true, Vec::new())),
        _ => None,
    }
}

/// Verification with one key: the SignedInfo signature, then the
/// reference digest. `Err` is an error message, which ends the check.
fn check_with(
    doc: &Document,
    signature: &Element,
    signed_info: &Element,
    reference: &Element,
    value: &[u8],
    certificate: &[u8],
) -> Result<bool, String> {
    let Some(method) = signed_info.child(DSIG, "CanonicalizationMethod") else {
        return Ok(false);
    };
    let Some((comments, all, inclusive)) =
        c14n_options(method.attr("Algorithm").unwrap_or(""), method)
    else {
        return Ok(false);
    };
    let canonical_si = canonicalize_in(
        doc,
        signed_info,
        &Options {
            comments,
            inclusive: &inclusive,
            exclude: None,
            all_namespaces: all,
        },
    );
    let sig_method = signed_info
        .child(DSIG, "SignatureMethod")
        .and_then(|m| m.attr("Algorithm"))
        .unwrap_or("");
    if !verify_bytes(certificate, sig_method, canonical_si.as_bytes(), value) {
        return Ok(false);
    }
    // The reference: "" is the whole document; "#id" resolves strictly.
    // Same-document references drop comments.
    let uri = reference.attr("URI").unwrap_or("");
    let target = match uri.strip_prefix('#') {
        _ if uri.is_empty() => &doc.root,
        Some(id) => find_by_id(&doc.root, id)?,
        None => return Ok(false),
    };
    let mut exclude = None;
    let mut c14n = None;
    for t in reference
        .child(DSIG, "Transforms")
        .map(|ts| ts.elements().collect::<Vec<_>>())
        .unwrap_or_default()
    {
        match t.attr("Algorithm").unwrap_or("") {
            ENVELOPED => {
                if signature.start >= target.start && signature.end <= target.end {
                    exclude = Some(signature.start);
                }
            }
            other => match c14n_options(other, t) {
                Some((_, all, inclusive)) => c14n = Some((all, inclusive)),
                None => return Ok(false),
            },
        }
    }
    // Without a canonicalization transform, Canonical XML applies.
    let (all, inclusive) = c14n.unwrap_or((true, Vec::new()));
    let canonical = canonicalize_in(
        doc,
        target,
        &Options {
            comments: false,
            inclusive: &inclusive,
            exclude,
            all_namespaces: all,
        },
    );
    let digest_method = reference
        .child(DSIG, "DigestMethod")
        .and_then(|m| m.attr("Algorithm"))
        .unwrap_or("");
    let stated = STANDARD
        .decode(text_of(reference.child(DSIG, "DigestValue")))
        .unwrap_or_default();
    Ok(digest_with(digest_method, canonical.as_bytes()).is_some_and(|d| d == stated))
}

fn text_of(element: Option<&Element>) -> String {
    element
        .map(|e| e.text().split_whitespace().collect())
        .unwrap_or_default()
}

/// The `DSIG` child named `local`, refusing two: a second Signature,
/// SignedInfo or SignatureValue could be the one another reader acts on.
fn only_child<'d>(parent: &'d Element, local: &str) -> Result<Option<&'d Element>, String> {
    let mut found = parent
        .elements()
        .filter(|e| e.ns == DSIG && e.local == local);
    let first = found.next();
    if found.next().is_some() {
        return Err(format!("There is more than one {local}."));
    }
    Ok(first)
}

/// Verifies the signature that is a direct child of `signed` against the
/// trusted certificates (DER) and allowed algorithms, as
/// the signed xml helper does. Returns `signed` itself, so a
/// caller acts only on the element the signature covers.
pub fn verify<'d>(
    doc: &'d Document,
    signed: &'d Element,
    trusted: &[Vec<u8>],
    allowed: &[&str],
) -> Result<&'d Element, String> {
    let signature =
        only_child(signed, "Signature")?.ok_or_else(|| "The element is not signed.".to_owned())?;
    let signed_info = only_child(signature, "SignedInfo")?
        .ok_or_else(|| "The Signature has no SignedInfo.".to_owned())?;
    // One value: a second one is never what was checked.
    only_child(signature, "SignatureValue")?;
    let references: Vec<&Element> = signed_info
        .elements()
        .filter(|e| e.ns == DSIG && e.local == "Reference")
        .collect();
    let allowed_list = allowed.join(", ");
    let mut error = String::new();
    if let [reference] = references.as_slice() {
        let value = STANDARD
            .decode(text_of(signature.child(DSIG, "SignatureValue")))
            .unwrap_or_default();
        let mut working = false;
        for certificate in trusted {
            if check_with(doc, signature, signed_info, reference, &value, certificate)? {
                working = true;
                break;
            }
        }
        if !working {
            let embedded = signature
                .child(DSIG, "KeyInfo")
                .and_then(|k| k.child(DSIG, "X509Data"))
                .and_then(|x| x.child(DSIG, "X509Certificate"))
                .and_then(|c| STANDARD.decode(text_of(Some(c))).ok());
            let contained = match embedded {
                Some(certificate) => {
                    check_with(doc, signature, signed_info, reference, &value, &certificate)?
                }
                None => false,
            };
            error += if contained {
                "Signature validated with the contained key, but that is not configured as a trusted key. "
            } else {
                "Signature didn't verify for any of the the specified keys. "
            };
        }
        let uri = reference.attr("URI").unwrap_or("");
        if uri.is_empty() {
            error += "Empty reference URI (implying the whole document is signed) is not allowed in Saml2. ";
        } else {
            let target = find_by_id(&doc.root, uri.strip_prefix('#').unwrap_or(uri))?;
            if target.start != signed.start {
                error += "Incorrect reference on Xml Signature, the reference must be to the parent element of the signature. ";
            }
        }
        for t in reference
            .child(DSIG, "Transforms")
            .map(|ts| ts.elements().collect::<Vec<_>>())
            .unwrap_or_default()
        {
            match t.attr("Algorithm").unwrap_or("") {
                ENVELOPED | EXC_C14N | EXC_C14N_COMMENTS => {}
                other => error += &format!("Transform {other} is not allowed in SAML2. "),
            }
        }
        let digest_method = reference
            .child(DSIG, "DigestMethod")
            .and_then(|m| m.attr("Algorithm"))
            .unwrap_or("");
        if !allowed.contains(&digest_method) {
            error += &format!(
                "Digest algorithm {digest_method} does not match configured [{allowed_list}]. "
            );
        }
    } else {
        error += "The Signature should contain exactly one reference. ";
    }
    let sig_method = signed_info
        .child(DSIG, "SignatureMethod")
        .and_then(|m| m.attr("Algorithm"))
        .unwrap_or("");
    if !allowed.contains(&sig_method) {
        error += &format!(
            "Signature algorithm {sig_method} does not match configured [{allowed_list}]. "
        );
    }
    if error.is_empty() {
        Ok(signed)
    } else {
        Err(error.trim_end().to_owned())
    }
}
