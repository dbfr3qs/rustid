//! Fetching what clients publish by reference (request objects, sector
//! identifier documents, `jwks_uri` key sets) over HTTP, without following
//! redirects, within 10 seconds, and reading at most 1 MiB. The URI is the
//! client's; which hosts it may name is the operator's concern (enable
//! request URIs and dynamic registration only for trusted clients).

use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use rustid_core::request_uri::{Fetched, RequestUriFetcher};

/// The most of a response body read.
const MAX_BODY: usize = 1024 * 1024;

pub struct HttpRequestUriFetcher {
    client: reqwest::Client,
}

impl HttpRequestUriFetcher {
    pub fn new() -> anyhow::Result<Self> {
        Self::with_ca_file(None)
    }

    /// Also trusts the CA certificates in `ca_file` (PEM), for request
    /// objects hosted behind a private PKI.
    pub fn with_ca_file(ca_file: Option<&std::path::Path>) -> anyhow::Result<Self> {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10));
        if let Some(path) = ca_file {
            let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            for certificate in reqwest::Certificate::from_pem_bundle(&pem)
                .with_context(|| format!("parsing {}", path.display()))?
            {
                builder = builder.add_root_certificate(certificate);
            }
        }
        Ok(HttpRequestUriFetcher {
            client: builder.build()?,
        })
    }
}

#[async_trait]
impl RequestUriFetcher for HttpRequestUriFetcher {
    async fn fetch(&self, uri: &str) -> Option<Fetched> {
        let mut response = match self.client.get(uri).send().await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(%error, "fetching a request_uri failed");
                return None;
            }
        };
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(|v| v.trim().to_owned());
        let mut body = Vec::new();
        while let Ok(Some(chunk)) = response.chunk().await {
            if body.len() + chunk.len() > MAX_BODY {
                tracing::warn!("a request_uri answered more than 1 MiB");
                return None;
            }
            body.extend_from_slice(&chunk);
        }
        Some(Fetched {
            status,
            content_type,
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }
}
