//! The demo backchannel app: signs a user in with CIBA (OpenID
//! Client-Initiated Backchannel Authentication, poll mode), as a call
//! centre or a point-of-sale terminal would. It names the user, the server
//! asks them (on its `/ciba` page) whether to allow it, and the app polls
//! until they decide.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use serde::Deserialize;
use serde_json::Value;

use crate::device::{DeviceTokens, tokens};

/// Where the app finds the server and how it presents itself.
#[derive(Debug, Clone)]
pub struct CibaConfig {
    pub authority: String,
    pub client_id: String,
    pub client_secret: String,
    pub scope: String,
    /// A CA certificate to trust for the server, besides the system roots.
    pub ca_file: Option<PathBuf>,
    /// Host names to pin to addresses when calling the server.
    pub resolve: Vec<(String, SocketAddr)>,
}

/// The server's answer to the backchannel authentication request.
#[derive(Debug, Clone, Deserialize)]
pub struct CibaStart {
    pub auth_req_id: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Deserialize)]
struct Metadata {
    token_endpoint: String,
    backchannel_authentication_endpoint: String,
}

pub struct CibaClient {
    config: CibaConfig,
    http: reqwest::Client,
}

impl CibaClient {
    pub fn new(config: CibaConfig) -> anyhow::Result<Self> {
        let mut http = reqwest::Client::builder().timeout(Duration::from_secs(15));
        if let Some(ca) = &config.ca_file {
            let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
            http = http.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
        }
        for (host, addr) in &config.resolve {
            http = http.resolve(host, *addr);
        }
        Ok(CibaClient {
            config,
            http: http.build()?,
        })
    }

    async fn metadata(&self) -> anyhow::Result<Metadata> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.authority.trim_end_matches('/')
        );
        Ok(self
            .http
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    fn credentials(&self) -> Vec<(&str, &str)> {
        vec![
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
        ]
    }

    /// The backchannel authentication request for the user `login_hint`
    /// names, with a message they'll see on the server's page.
    pub async fn start(
        &self,
        login_hint: &str,
        binding_message: Option<&str>,
    ) -> anyhow::Result<CibaStart> {
        let metadata = self.metadata().await?;
        let mut form = self.credentials();
        form.push(("scope", &self.config.scope));
        form.push(("login_hint", login_hint));
        form.extend(binding_message.map(|m| ("binding_message", m)));
        let response = self
            .http
            .post(&metadata.backchannel_authentication_endpoint)
            .form(&form)
            .send()
            .await?;
        if !response.status().is_success() {
            bail!("the server refused: {}", response.text().await?);
        }
        Ok(response.json().await?)
    }

    /// Polls the token endpoint at the server's interval until the user
    /// allows or denies, or the request expires.
    pub async fn wait(&self, started: &CibaStart) -> anyhow::Result<DeviceTokens> {
        let metadata = self.metadata().await?;
        let mut interval = started.interval.max(1);
        let deadline = std::time::Instant::now() + Duration::from_secs(started.expires_in);
        loop {
            tokio::time::sleep(Duration::from_secs(interval)).await;
            if std::time::Instant::now() > deadline {
                bail!("the request expired before anyone answered it");
            }
            let mut form = self.credentials();
            form.push(("grant_type", "urn:openid:params:grant-type:ciba"));
            form.push(("auth_req_id", &started.auth_req_id));
            let response = self
                .http
                .post(&metadata.token_endpoint)
                .form(&form)
                .send()
                .await?;
            let ok = response.status().is_success();
            let body: Value = response.json().await?;
            if ok {
                return tokens(&body);
            }
            match body["error"].as_str() {
                Some("authorization_pending") => {}
                Some("slow_down") => interval += 5,
                Some("access_denied") => bail!("the request was denied"),
                Some("expired_token") => bail!("the request expired"),
                _ => bail!("the server refused: {body}"),
            }
        }
    }
}
