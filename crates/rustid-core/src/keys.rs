//! Signing and validation key material, and its JSON Web Key rendering.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aws_lc_rs::signature::KeyPair;
use aws_lc_rs::{digest, rsa, signature};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

/// One key as configured: a PKCS#8 PEM private key, an optional PEM
/// certificate for the same key, the key id and the JWS algorithm.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    pub kid: String,
    pub alg: String,
    pub key_file: PathBuf,
    #[serde(default)]
    pub cert_file: Option<PathBuf>,
}

/// A JSON Web Key as JWKS documents render it: absent members
/// are omitted.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JsonWebKey {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// A loaded key: its public JWK and the private key used to sign.
#[derive(Debug, Clone)]
pub struct LoadedKey {
    pub kid: String,
    pub alg: String,
    pub jwk: JsonWebKey,
    signer: Signer,
}

impl PartialEq for LoadedKey {
    fn eq(&self, other: &Self) -> bool {
        self.kid == other.kid && self.alg == other.alg && self.jwk == other.jwk
    }
}

#[derive(Clone)]
enum Signer {
    Rsa(Arc<rsa::KeyPair>),
    Ec(Arc<signature::EcdsaKeyPair>),
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Signer::Rsa(_) => "Signer::Rsa(..)",
            Signer::Ec(_) => "Signer::Ec(..)",
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("signing with key {kid} ({alg}) failed")]
pub struct SignError {
    pub kid: String,
    pub alg: String,
}

/// Every key the server knows. Signing keys are also validation keys.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct KeyMaterial {
    pub signing: Vec<LoadedKey>,
    pub validation_only: Vec<LoadedKey>,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("key {kid}: reading {path}: {source}")]
    Read {
        kid: String,
        path: String,
        source: std::io::Error,
    },
    #[error("key {kid}: {path} is not PEM: {message}")]
    Pem {
        kid: String,
        path: String,
        message: String,
    },
    #[error("key {kid}: unsupported algorithm {alg}")]
    UnsupportedAlgorithm { kid: String, alg: String },
    #[error("key {kid}: {path} is not a PKCS#8 key usable with {alg}")]
    WrongKeyType {
        kid: String,
        path: String,
        alg: String,
    },
    #[error("key {kid}: certificate {path} does not match the private key")]
    CertificateMismatch { kid: String, path: String },
    #[error("key id {kid} is configured more than once")]
    DuplicateKid { kid: String },
}

enum Family {
    Rsa,
    Ec {
        crv: &'static str,
        alg: &'static signature::EcdsaSigningAlgorithm,
    },
}

fn family(kid: &str, alg: &str) -> Result<Family, KeyError> {
    match alg {
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => Ok(Family::Rsa),
        "ES256" => Ok(Family::Ec {
            crv: "P-256",
            alg: &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        }),
        "ES384" => Ok(Family::Ec {
            crv: "P-384",
            alg: &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        }),
        "ES512" => Ok(Family::Ec {
            crv: "P-521",
            alg: &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
        }),
        _ => Err(KeyError::UnsupportedAlgorithm {
            kid: kid.to_owned(),
            alg: alg.to_owned(),
        }),
    }
}

fn read_pem(kid: &str, path: &Path) -> Result<Vec<u8>, KeyError> {
    let display = path.display().to_string();
    let bytes = std::fs::read(path).map_err(|source| KeyError::Read {
        kid: kid.to_owned(),
        path: display.clone(),
        source,
    })?;
    let parsed = pem::parse(bytes).map_err(|e| KeyError::Pem {
        kid: kid.to_owned(),
        path: display,
        message: e.to_string(),
    })?;
    Ok(parsed.into_contents())
}

impl LoadedKey {
    pub fn load(config: &KeyConfig) -> Result<Self, KeyError> {
        let kid = config.kid.as_str();
        let der = read_pem(kid, &config.key_file)?;
        let cert = match &config.cert_file {
            Some(path) => Some(read_pem(kid, path)?),
            None => None,
        };
        let origin = KeyOrigin {
            key: config.key_file.display().to_string(),
            cert: config.cert_file.as_ref().map(|p| p.display().to_string()),
        };
        Self::from_der(kid, &config.alg, &der, cert.as_deref(), &origin)
    }

    /// A key from a PKCS#8 private key and an optional X.509 certificate,
    /// both DER. `origin` names where they came from in errors.
    pub fn from_der(
        kid: &str,
        alg: &str,
        der: &[u8],
        cert: Option<&[u8]>,
        origin: &KeyOrigin,
    ) -> Result<Self, KeyError> {
        let wrong = || KeyError::WrongKeyType {
            kid: kid.to_owned(),
            path: origin.key.clone(),
            alg: alg.to_owned(),
        };
        // A certificate is refused whose public key differs from the private
        // key; publishing both would give clients an x5c that can't verify.
        let check_cert = |public_key: &[u8]| -> Result<(), KeyError> {
            match cert {
                Some(der) if certificate_public_key(der) != Some(public_key) => {
                    Err(KeyError::CertificateMismatch {
                        kid: kid.to_owned(),
                        path: origin.cert.clone().unwrap_or_default(),
                    })
                }
                _ => Ok(()),
            }
        };
        let (x5t, x5c) = match cert {
            Some(der) => {
                let thumbprint = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, der);
                (
                    Some(URL_SAFE_NO_PAD.encode(thumbprint)),
                    Some(vec![STANDARD.encode(der)]),
                )
            }
            None => (None, None),
        };
        let (jwk, signer) = match family(kid, alg)? {
            Family::Rsa => {
                let pair = rsa::KeyPair::from_pkcs8(der).map_err(|_| wrong())?;
                check_cert(pair.public_key().as_ref())?;
                let parts = rsa::PublicKeyComponents::<Vec<u8>>::from(pair.public_key());
                let jwk = JsonWebKey {
                    kty: "RSA".into(),
                    use_: "sig".into(),
                    kid: kid.to_owned(),
                    x5t,
                    e: Some(URL_SAFE_NO_PAD.encode(&parts.e)),
                    n: Some(URL_SAFE_NO_PAD.encode(&parts.n)),
                    x5c,
                    alg: alg.to_owned(),
                    crv: None,
                    x: None,
                    y: None,
                };
                (jwk, Signer::Rsa(Arc::new(pair)))
            }
            Family::Ec { crv, alg: ec_alg } => {
                let jws_alg = alg;
                let alg = ec_alg;
                let pair = signature::EcdsaKeyPair::from_pkcs8(alg, der).map_err(|_| wrong())?;
                check_cert(pair.public_key().as_ref())?;
                // Uncompressed SEC1 point: 0x04 || X || Y, coordinates of equal length.
                let point = pair.public_key().as_ref();
                let half = (point.len() - 1) / 2;
                let jwk = JsonWebKey {
                    kty: "EC".into(),
                    use_: "sig".into(),
                    kid: kid.to_owned(),
                    x5t,
                    e: None,
                    n: None,
                    x5c,
                    alg: jws_alg.to_owned(),
                    crv: Some(crv.to_owned()),
                    x: Some(URL_SAFE_NO_PAD.encode(&point[1..=half])),
                    y: Some(URL_SAFE_NO_PAD.encode(&point[1 + half..])),
                };
                (jwk, Signer::Ec(Arc::new(pair)))
            }
        };
        Ok(LoadedKey {
            kid: kid.to_owned(),
            alg: alg.to_owned(),
            jwk,
            signer,
        })
    }

    /// Whether the key carries an X.509 certificate (published as `x5c`).
    pub fn has_certificate(&self) -> bool {
        self.jwk.x5c.is_some()
    }

    /// The key's X.509 certificate (DER), when it has one.
    pub fn certificate(&self) -> Option<Vec<u8>> {
        let first = self.jwk.x5c.as_ref()?.first()?;
        STANDARD.decode(first).ok()
    }

    /// RSA PKCS#1 v1.5 with SHA-256, whatever the key's JWS algorithm (as
    /// XML signatures use RSA keys); `None` for an EC key.
    pub fn sign_rsa_pkcs1_sha256(&self, message: &[u8]) -> Option<Result<Vec<u8>, SignError>> {
        let Signer::Rsa(pair) = &self.signer else {
            return None;
        };
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let mut out = vec![0; pair.public_modulus_len()];
        Some(
            pair.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut out)
                .map(|_| out)
                .map_err(|_| SignError {
                    kid: self.kid.clone(),
                    alg: self.alg.clone(),
                }),
        )
    }

    pub fn is_rsa(&self) -> bool {
        matches!(self.signer, Signer::Rsa(_))
    }

    /// A self-signed certificate
    /// for an RSA key, subject `CN={common_name}` (a UTF8String), the given
    /// serial and validity, critical digitalSignature key usage, signed with
    /// PKCS#1 SHA-256. `None` for an EC key.
    pub fn rsa_certificate(
        &self,
        common_name: &str,
        serial: &[u8],
        not_before: chrono::DateTime<chrono::Utc>,
        not_after: chrono::DateTime<chrono::Utc>,
    ) -> Option<Result<Vec<u8>, KeyError>> {
        let Signer::Rsa(pair) = &self.signer else {
            return None;
        };
        let failed = || KeyError::UnsupportedAlgorithm {
            kid: self.kid.clone(),
            alg: self.alg.clone(),
        };
        let to_offset = |t: chrono::DateTime<chrono::Utc>| {
            time::OffsetDateTime::from_unix_timestamp(t.timestamp()).map_err(|_| failed())
        };
        let build = || -> Result<Vec<u8>, KeyError> {
            let mut params = rcgen::CertificateParams::default();
            params.distinguished_name = rcgen::DistinguishedName::new();
            params.distinguished_name.push(
                rcgen::DnType::CommonName,
                rcgen::DnValue::Utf8String(common_name.to_owned()),
            );
            params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            params.serial_number = Some(rcgen::SerialNumber::from_slice(serial));
            params.not_before = to_offset(not_before)?;
            params.not_after = to_offset(not_after)?;
            let cert = params
                .self_signed(&RsaCertificateSigner(pair))
                .map_err(|_| failed())?;
            Ok(cert.der().to_vec())
        };
        Some(build())
    }
}

/// Signs a certificate with a loaded RSA key (PKCS#1 SHA-256).
struct RsaCertificateSigner<'a>(&'a rsa::KeyPair);

impl rcgen::PublicKeyData for RsaCertificateSigner<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_RSA_SHA256
    }
}

impl rcgen::SigningKey for RsaCertificateSigner<'_> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let mut out = vec![0; self.0.public_modulus_len()];
        self.0
            .sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut out)
            .map_err(|_| rcgen::Error::RingUnspecified)?;
        Ok(out)
    }
}

/// Where a key's DER came from, for error messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyOrigin {
    pub key: String,
    pub cert: Option<String>,
}

/// A newly generated private key: PKCS#8 DER for the algorithm's family.
/// RSA keys have `rsa_key_size` bits; EC keys use the algorithm's curve.
pub fn generate_pkcs8(alg: &str, rsa_key_size: u32) -> Result<Vec<u8>, KeyError> {
    use aws_lc_rs::encoding::AsDer;
    let unsupported = || KeyError::UnsupportedAlgorithm {
        kid: String::new(),
        alg: alg.to_owned(),
    };
    match family("", alg)? {
        Family::Rsa => {
            let size = match rsa_key_size {
                2048 => rsa::KeySize::Rsa2048,
                3072 => rsa::KeySize::Rsa3072,
                4096 => rsa::KeySize::Rsa4096,
                8192 => rsa::KeySize::Rsa8192,
                _ => return Err(unsupported()),
            };
            let pair = rsa::KeyPair::generate(size).map_err(|_| unsupported())?;
            let der: aws_lc_rs::encoding::Pkcs8V1Der<'static> =
                pair.as_der().map_err(|_| unsupported())?;
            Ok(der.as_ref().to_vec())
        }
        Family::Ec { alg: ec_alg, .. } => {
            let pair = signature::EcdsaKeyPair::generate(ec_alg).map_err(|_| unsupported())?;
            let der = pair.to_pkcs8v1().map_err(|_| unsupported())?;
            Ok(der.as_ref().to_vec())
        }
    }
}

/// A self-signed certificate for the key, subject
/// `CN={issuer}`, digital signature usage, server authentication extended
/// usage, valid from `not_before` to `not_after`. DER.
pub fn self_signed_certificate(
    alg: &str,
    pkcs8: &[u8],
    issuer: &str,
    not_before: chrono::DateTime<chrono::Utc>,
    not_after: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<u8>, KeyError> {
    let unsupported = || KeyError::UnsupportedAlgorithm {
        kid: String::new(),
        alg: alg.to_owned(),
    };
    // The certificate is signed with RSA PKCS#1 SHA-256 whatever the JWS
    // algorithm, and doesn't support certificates for EC keys.
    let sign_alg = match family("", alg)? {
        Family::Rsa => &rcgen::PKCS_RSA_SHA256,
        Family::Ec { .. } => return Err(unsupported()),
    };
    let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.to_vec()),
        sign_alg,
    )
    .map_err(|_| unsupported())?;
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, issuer);
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let to_offset = |t: chrono::DateTime<chrono::Utc>| {
        time::OffsetDateTime::from_unix_timestamp(t.timestamp()).map_err(|_| unsupported())
    };
    params.not_before = to_offset(not_before)?;
    params.not_after = to_offset(not_after)?;
    let cert = params.self_signed(&key).map_err(|_| unsupported())?;
    Ok(cert.der().to_vec())
}

impl LoadedKey {
    /// Signs `message` with this key's algorithm, producing a JWS signature
    /// (PKCS#1 v1.5 or PSS for RSA; fixed-length `r || s` for ECDSA).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let error = || SignError {
            kid: self.kid.clone(),
            alg: self.alg.clone(),
        };
        let rng = aws_lc_rs::rand::SystemRandom::new();
        match &self.signer {
            Signer::Rsa(pair) => {
                let padding: &'static dyn signature::RsaEncoding = match self.alg.as_str() {
                    "RS256" => &signature::RSA_PKCS1_SHA256,
                    "RS384" => &signature::RSA_PKCS1_SHA384,
                    "RS512" => &signature::RSA_PKCS1_SHA512,
                    "PS256" => &signature::RSA_PSS_SHA256,
                    "PS384" => &signature::RSA_PSS_SHA384,
                    "PS512" => &signature::RSA_PSS_SHA512,
                    _ => return Err(error()),
                };
                let mut out = vec![0; pair.public_modulus_len()];
                pair.sign(padding, &rng, message, &mut out)
                    .map_err(|_| error())?;
                Ok(out)
            }
            Signer::Ec(pair) => Ok(pair
                .sign(&rng, message)
                .map_err(|_| error())?
                .as_ref()
                .to_vec()),
        }
    }

    /// The public half, for verifying signatures made with this key.
    pub fn public_jwk(&self) -> crate::jwt::PublicJwk {
        crate::jwt::PublicJwk {
            kty: self.jwk.kty.clone(),
            kid: Some(self.jwk.kid.clone()),
            n: self.jwk.n.clone(),
            e: self.jwk.e.clone(),
            crv: self.jwk.crv.clone(),
            x: self.jwk.x.clone(),
            y: self.jwk.y.clone(),
            k: None,
        }
    }
}

impl KeyMaterial {
    ///
    /// The first signing key when no algorithms are required, otherwise the
    /// first signing key whose algorithm is allowed.
    pub fn signing_key_for(&self, allowed_algorithms: &[String]) -> Option<&LoadedKey> {
        if allowed_algorithms.is_empty() {
            return self.signing.first();
        }
        self.signing
            .iter()
            .find(|k| allowed_algorithms.contains(&k.alg))
    }

    pub fn load(signing: &[KeyConfig], validation_only: &[KeyConfig]) -> Result<Self, KeyError> {
        let mut seen = std::collections::HashSet::new();
        for k in signing.iter().chain(validation_only) {
            if !seen.insert(k.kid.as_str()) {
                return Err(KeyError::DuplicateKid { kid: k.kid.clone() });
            }
        }
        Ok(KeyMaterial {
            signing: signing
                .iter()
                .map(LoadedKey::load)
                .collect::<Result<_, _>>()?,
            validation_only: validation_only
                .iter()
                .map(LoadedKey::load)
                .collect::<Result<_, _>>()?,
        })
    }

    /// Signing keys first, then validation-only keys,
    /// get validation keys returns them.
    pub fn validation_keys(&self) -> impl Iterator<Item = &LoadedKey> {
        self.signing.iter().chain(&self.validation_only)
    }

    /// Distinct signing algorithms in configuration order.
    pub fn signing_algorithms(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for k in &self.signing {
            if !out.contains(&k.alg) {
                out.push(k.alg.clone());
            }
        }
        out
    }
}

/// An X.509 certificate's public key as a JWK (RSA, or EC on P-256, P-384
/// or P-521, told apart by the point's length), for verifying signatures
/// with an `X509CertificateBase64` secret. `None` for anything else.
pub fn certificate_jwk(cert: &[u8]) -> Option<crate::jwt::PublicJwk> {
    use crate::jwt::b64url;
    let key = certificate_public_key(cert)?;
    let jwk = |kty: &str| crate::jwt::PublicJwk {
        kty: kty.to_owned(),
        kid: None,
        n: None,
        e: None,
        crv: None,
        x: None,
        y: None,
        k: None,
    };
    if key.first() == Some(&0x04) {
        let crv = match key.len() {
            65 => "P-256",
            97 => "P-384",
            133 => "P-521",
            _ => return None,
        };
        let half = (key.len() - 1) / 2;
        return Some(crate::jwt::PublicJwk {
            crv: Some(crv.to_owned()),
            x: Some(b64url(&key[1..=half])),
            y: Some(b64url(&key[half + 1..])),
            ..jwk("EC")
        });
    }
    // PKCS#1 RSAPublicKey: SEQUENCE { modulus INTEGER, exponent INTEGER }.
    let (sequence, _) = der_element(key, 0x30)?;
    let (n, rest) = der_element(sequence, 0x02)?;
    let (e, _) = der_element(rest, 0x02)?;
    let unsigned = |i: &[u8]| {
        let start = i.iter().position(|b| *b != 0).unwrap_or(i.len());
        i[start..].to_vec()
    };
    Some(crate::jwt::PublicJwk {
        n: Some(b64url(&unsigned(n))),
        e: Some(b64url(&unsigned(e))),
        ..jwk("RSA")
    })
}

/// The subjectPublicKey bits of an X.509 certificate: PKCS#1 `RSAPublicKey`
/// for RSA or the uncompressed point for EC, the same encoding aws-lc-rs uses
/// for `public_key()`. `None` when the DER doesn't have the expected shape.
fn certificate_public_key(cert: &[u8]) -> Option<&[u8]> {
    let (certificate, _) = der_element(cert, 0x30)?;
    let (mut tbs, _) = der_element(certificate, 0x30)?;
    if tbs.first() == Some(&0xA0) {
        tbs = der_element(tbs, 0xA0)?.1; // explicit version
    }
    // SerialNumber, signature, issuer, validity, subject
    for tag in [0x02, 0x30, 0x30, 0x30, 0x30] {
        tbs = der_element(tbs, tag)?.1;
    }
    let (spki, _) = der_element(tbs, 0x30)?;
    let after_algorithm = der_element(spki, 0x30)?.1;
    let (bits, _) = der_element(after_algorithm, 0x03)?;
    match bits.split_first() {
        Some((0, key)) => Some(key), // no unused bits
        _ => None,
    }
}

/// Reads one DER element with the expected tag: (contents, remainder).
fn der_element(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&actual, rest) = input.split_first()?;
    if actual != tag {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let len = rest[..count]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, &rest[count..])
    };
    (rest.len() >= len).then(|| (&rest[..len], &rest[len..]))
}
