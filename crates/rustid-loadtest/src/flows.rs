//! The core flows, each as a virtual user: an unmeasured setup (signing in,
//! getting the token the flow needs), then one measured operation per step.

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

/// The fixture clients the flows use (`fixtures/clients.json`).
const CODE_CLIENT: &str = "web";
const REDIRECT_URI: &str = "https://client.test/callback";
const CODE_SCOPE: &str = "openid profile api1 offline_access";

/// A flow the harness drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    ClientCredentials,
    AuthorizationCode,
    Refresh,
    Introspection,
    UserInfo,
    Discovery,
}

impl Flow {
    pub const ALL: [Flow; 6] = [
        Flow::ClientCredentials,
        Flow::AuthorizationCode,
        Flow::Refresh,
        Flow::Introspection,
        Flow::UserInfo,
        Flow::Discovery,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Flow::ClientCredentials => "client-credentials",
            Flow::AuthorizationCode => "authorization-code",
            Flow::Refresh => "refresh",
            Flow::Introspection => "introspection",
            Flow::UserInfo => "userinfo",
            Flow::Discovery => "discovery",
        }
    }

    /// What one measured operation is, for the report.
    pub fn operation(self) -> &'static str {
        match self {
            Flow::ClientCredentials => "a client credentials token request",
            Flow::AuthorizationCode => {
                "a signed-in authorize request and its code redemption (PKCE)"
            }
            Flow::Refresh => "a refresh token redemption (following rotation)",
            Flow::Introspection => "an introspection of a JWT access token",
            Flow::UserInfo => "a userinfo request",
            Flow::Discovery => "a discovery document request",
        }
    }

    pub fn parse(name: &str) -> anyhow::Result<Flow> {
        Flow::ALL
            .into_iter()
            .find(|f| f.name() == name)
            .with_context(|| format!("unknown flow {name}"))
    }
}

/// One virtual user: its own client (cookie jar, no redirects followed)
/// and whatever its flow carries between steps.
pub(crate) struct User {
    client: reqwest::Client,
    base: String,
    flow: Flow,
    /// The refresh token (Refresh) or access token (Introspection, UserInfo).
    token: String,
}

fn client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .no_proxy()
        .build()?)
}

async fn json(response: reqwest::Response, want: &str) -> anyhow::Result<Value> {
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("{status}: {body}");
    }
    let value: Value = serde_json::from_str(&body).with_context(|| format!("not JSON: {body}"))?;
    if value.get(want).is_none() {
        bail!("no {want} in {body}");
    }
    Ok(value)
}

impl User {
    pub(crate) async fn new(base: &str, flow: Flow) -> anyhow::Result<User> {
        let mut user = User {
            client: client()?,
            base: base.trim_end_matches('/').to_owned(),
            flow,
            token: String::new(),
        };
        match flow {
            Flow::AuthorizationCode => user.sign_in().await?,
            Flow::Refresh => {
                user.sign_in().await?;
                user.token = user.code_flow().await?["refresh_token"]
                    .as_str()
                    .context("no refresh_token")?
                    .to_owned();
            }
            Flow::UserInfo => {
                user.sign_in().await?;
                user.token = user.code_flow().await?["access_token"]
                    .as_str()
                    .context("no access_token")?
                    .to_owned();
            }
            Flow::Introspection => {
                user.token = user.client_credentials().await?["access_token"]
                    .as_str()
                    .context("no access_token")?
                    .to_owned();
            }
            Flow::ClientCredentials | Flow::Discovery => {}
        }
        Ok(user)
    }

    /// One measured operation.
    pub(crate) async fn step(&mut self) -> anyhow::Result<()> {
        match self.flow {
            Flow::ClientCredentials => {
                self.client_credentials().await?;
            }
            Flow::AuthorizationCode => {
                self.code_flow().await?;
            }
            Flow::Refresh => {
                let response = self
                    .client
                    .post(format!("{}/connect/token", self.base))
                    .form(&[
                        ("grant_type", "refresh_token"),
                        ("refresh_token", self.token.as_str()),
                        ("client_id", CODE_CLIENT),
                    ])
                    .send()
                    .await?;
                let tokens = json(response, "access_token").await?;
                // Rotation: the next refresh uses the token just returned.
                if let Some(next) = tokens["refresh_token"].as_str() {
                    self.token = next.to_owned();
                }
            }
            Flow::Introspection => {
                let response = self
                    .client
                    .post(format!("{}/connect/introspect", self.base))
                    .basic_auth("api", Some("secret"))
                    .form(&[("token", self.token.as_str())])
                    .send()
                    .await?;
                let answer = json(response, "active").await?;
                if answer["active"] != true {
                    bail!("the token is not active: {answer}");
                }
            }
            Flow::UserInfo => {
                let response = self
                    .client
                    .get(format!("{}/connect/userinfo", self.base))
                    .bearer_auth(&self.token)
                    .send()
                    .await?;
                json(response, "sub").await?;
            }
            Flow::Discovery => {
                let response = self
                    .client
                    .get(format!("{}/.well-known/openid-configuration", self.base))
                    .send()
                    .await?;
                json(response, "issuer").await?;
            }
        }
        Ok(())
    }

    async fn client_credentials(&self) -> anyhow::Result<Value> {
        let response = self
            .client
            .post(format!("{}/connect/token", self.base))
            .basic_auth("m2m", Some("secret"))
            .form(&[("grant_type", "client_credentials"), ("scope", "api1")])
            .send()
            .await?;
        json(response, "access_token").await
    }

    fn authorize_url(&self, challenge: &str, prompt: Option<&str>) -> anyhow::Result<url::Url> {
        let mut url = url::Url::parse(&format!("{}/connect/authorize", self.base))?;
        url.query_pairs_mut()
            .append_pair("client_id", CODE_CLIENT)
            .append_pair("response_type", "code")
            .append_pair("scope", CODE_SCOPE)
            .append_pair("redirect_uri", REDIRECT_URI)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", "s");
        if let Some(prompt) = prompt {
            url.query_pairs_mut().append_pair("prompt", prompt);
        }
        Ok(url)
    }

    async fn location(&self, url: &url::Url) -> anyhow::Result<url::Url> {
        let response = self.client.get(url.as_str()).send().await?;
        let status = response.status();
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .with_context(|| format!("{url} answered {status} without a redirect"))?
            .to_str()?
            .to_owned();
        Ok(url.join(&location)?)
    }

    /// Signs in through the target's scripted login page: follows the
    /// UI's redirects to the
    /// authorize callback, then answers it, so the cookie jar holds the
    /// session.
    async fn sign_in(&self) -> anyhow::Result<()> {
        let (_, challenge) = pkce();
        let mut url = self
            .location(&self.authorize_url(&challenge, Some("login"))?)
            .await?;
        for _ in 0..5 {
            let next = self.location(&url).await?;
            if next
                .path()
                .to_ascii_lowercase()
                .ends_with("/connect/authorize/callback")
            {
                self.location(&next).await?;
                return Ok(());
            }
            url = next;
        }
        bail!("the login page never led to the authorize callback")
    }

    /// A signed-in authorize request, then its code redeemed with PKCE.
    async fn code_flow(&self) -> anyhow::Result<Value> {
        let (verifier, challenge) = pkce();
        let callback = self
            .location(&self.authorize_url(&challenge, None)?)
            .await?;
        let code = callback
            .query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.into_owned())
            .with_context(|| format!("no code in {callback}"))?;
        let response = self
            .client
            .post(format!("{}/connect/token", self.base))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", CODE_CLIENT),
                ("code_verifier", verifier.as_str()),
            ])
            .send()
            .await?;
        json(response, "access_token").await
    }
}

/// A fresh PKCE verifier and its S256 challenge.
fn pkce() -> (String, String) {
    let mut bytes = [0u8; 32];
    aws_lc_rs::rand::fill(&mut bytes).expect("randomness");
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, verifier.as_bytes());
    (verifier, URL_SAFE_NO_PAD.encode(digest.as_ref()))
}
