//! A local certificate authority and a server certificate it signed, so the
//! demo runs over HTTPS. Import `ca.pem` into a browser to trust it, or
//! accept the browser's warning once.

use std::path::{Path, PathBuf};

use anyhow::Context;

/// Where [`write`] put the files.
#[derive(Debug, Clone)]
pub struct CertificateFiles {
    /// The CA certificate clients trust.
    pub ca: PathBuf,
    /// The server certificate followed by the CA certificate.
    pub cert: PathBuf,
    /// The server certificate's private key.
    pub key: PathBuf,
}

/// Writes `ca.pem`, `cert.pem` and `key.pem` into `dir` for the given host
/// names. Existing files are kept unless `force` is set, so a browser that
/// trusts the CA keeps trusting it.
pub fn write(dir: &Path, hosts: &[String], force: bool) -> anyhow::Result<CertificateFiles> {
    let files = CertificateFiles {
        ca: dir.join("ca.pem"),
        cert: dir.join("cert.pem"),
        key: dir.join("key.pem"),
    };
    if !force && files.ca.is_file() && files.cert.is_file() && files.key.is_file() {
        return Ok(files);
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    let ca_key = rcgen::KeyPair::generate()?;
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "rustid demo CA");
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key)?;

    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(hosts.to_vec())?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        hosts.first().map_or("localhost", String::as_str),
    );
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.signed_by(&key, &ca)?;

    std::fs::write(&files.ca, ca.pem())?;
    std::fs::write(&files.cert, format!("{}{}", cert.pem(), ca.pem()))?;
    std::fs::write(&files.key, key.serialize_pem())?;
    Ok(files)
}
