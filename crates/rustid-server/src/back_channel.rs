//! the HTTP side: logout tokens posted as
//! the form field `logout_token`. Each post runs on its own task, within 10
//! seconds and without following redirects, so a slow or failing client
//! never holds up a sign-out; failures are logged.

use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use rustid_core::logout::BackChannelSender;

pub struct HttpBackChannelSender {
    client: reqwest::Client,
}

impl HttpBackChannelSender {
    pub fn new() -> anyhow::Result<Self> {
        Self::with_ca_file(None)
    }

    /// Also trusts the CA certificates in `ca_file` (PEM), for receivers
    /// behind a private PKI.
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
        Ok(HttpBackChannelSender {
            client: builder.build()?,
        })
    }
}

#[async_trait]
impl BackChannelSender for HttpBackChannelSender {
    async fn send(&self, uri: &str, logout_token: &str) {
        let request = self
            .client
            .post(uri)
            .form(&[("logout_token", logout_token)]);
        let uri = uri.to_owned();
        tokio::spawn(async move {
            match request.send().await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => {
                    tracing::warn!(%uri, status = %response.status(), "back-channel logout refused");
                }
                Err(error) => tracing::warn!(%uri, %error, "back-channel logout failed"),
            }
        });
    }
}
