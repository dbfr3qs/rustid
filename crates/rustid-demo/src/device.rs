//! The demo device: signs in with the device authorization grant (RFC
//! 8628), as a TV or command line tool would. It asks the server for a user
//! code, shows where to enter it, and polls until the person decides.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use rustid_core::jwt::Jws;
use serde::Deserialize;
use serde_json::{Map, Value};

/// Where the device finds the server and how it presents itself.
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub authority: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scope: String,
    /// A CA certificate to trust for the server, besides the system roots.
    pub ca_file: Option<PathBuf>,
    /// Host names to pin to addresses when calling the server.
    pub resolve: Vec<(String, SocketAddr)>,
}

/// The server's answer to the device authorization request.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

/// The tokens the device got, with the identity token's claims.
#[derive(Debug, Clone)]
pub struct DeviceTokens {
    pub access_token: String,
    pub id_claims: Map<String, Value>,
    pub scope: String,
}

#[derive(Deserialize)]
struct Metadata {
    token_endpoint: String,
    device_authorization_endpoint: String,
    userinfo_endpoint: String,
}

pub struct DeviceClient {
    config: DeviceConfig,
    http: reqwest::Client,
}

impl DeviceClient {
    pub fn new(config: DeviceConfig) -> anyhow::Result<Self> {
        let mut http = reqwest::Client::builder().timeout(Duration::from_secs(15));
        if let Some(ca) = &config.ca_file {
            let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
            http = http.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
        }
        for (host, addr) in &config.resolve {
            http = http.resolve(host, *addr);
        }
        Ok(DeviceClient {
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
        let mut form = vec![("client_id", self.config.client_id.as_str())];
        if let Some(secret) = &self.config.client_secret {
            form.push(("client_secret", secret));
        }
        form
    }

    /// The device authorization request: a user code to show.
    pub async fn start(&self) -> anyhow::Result<DeviceStart> {
        let metadata = self.metadata().await?;
        let mut form = self.credentials();
        form.push(("scope", &self.config.scope));
        let response = self
            .http
            .post(&metadata.device_authorization_endpoint)
            .form(&form)
            .send()
            .await?;
        if !response.status().is_success() {
            bail!("the server refused: {}", response.text().await?);
        }
        Ok(response.json().await?)
    }

    /// The signed-in user's claims from the userinfo endpoint.
    pub async fn userinfo(&self, tokens: &DeviceTokens) -> anyhow::Result<Value> {
        let metadata = self.metadata().await?;
        Ok(self
            .http
            .get(&metadata.userinfo_endpoint)
            .bearer_auth(&tokens.access_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Polls the token endpoint at the server's interval until the person
    /// allows or denies, or the code expires.
    pub async fn wait(&self, started: &DeviceStart) -> anyhow::Result<DeviceTokens> {
        let metadata = self.metadata().await?;
        let mut interval = started.interval.max(1);
        let deadline = std::time::Instant::now() + Duration::from_secs(started.expires_in);
        loop {
            tokio::time::sleep(Duration::from_secs(interval)).await;
            if std::time::Instant::now() > deadline {
                bail!("the code expired before anyone entered it");
            }
            let mut form = self.credentials();
            form.push(("grant_type", "urn:ietf:params:oauth:grant-type:device_code"));
            form.push(("device_code", &started.device_code));
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
                // RFC 8628 3.5: back off by five seconds.
                Some("slow_down") => interval += 5,
                Some("access_denied") => bail!("the request was denied"),
                Some("expired_token") => bail!("the code expired"),
                _ => bail!("the server refused: {body}"),
            }
        }
    }
}

/// The token response as tokens, with the identity token's claims.
pub fn tokens(body: &Value) -> anyhow::Result<DeviceTokens> {
    let id_claims = body["id_token"]
        .as_str()
        .and_then(Jws::decode)
        .map(|jws| jws.payload)
        .unwrap_or_default();
    Ok(DeviceTokens {
        access_token: body["access_token"]
            .as_str()
            .context("no access token")?
            .to_owned(),
        id_claims,
        scope: body["scope"].as_str().unwrap_or_default().to_owned(),
    })
}
