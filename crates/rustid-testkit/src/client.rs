use std::collections::BTreeMap;
use std::sync::Arc;

use reqwest::redirect::Policy;

use crate::cookie_jar::CookieJar;
use crate::recorded::{Body, RECORDED_HEADERS, Recorded};

/// HTTP client that never follows redirects, keeps cookies for its lifetime,
/// and reduces every response to a [`Recorded`].
pub struct Client {
    inner: reqwest::Client,
    jar: Arc<CookieJar>,
}

impl Client {
    pub fn new() -> anyhow::Result<Self> {
        let jar = Arc::new(CookieJar::default());
        let inner = reqwest::Client::builder()
            .redirect(Policy::none())
            .cookie_provider(jar.clone())
            .build()?;
        Ok(Self { inner, jar })
    }

    /// The client's cookies.
    pub fn jar(&self) -> &CookieJar {
        &self.jar
    }

    /// GET of an absolute URL, e.g. a `Location` a previous response sent.
    pub async fn get(&self, url: &str) -> anyhow::Result<Recorded> {
        let response = self.inner.get(url).send().await?;
        Self::record(response).await
    }

    /// GET with an explicit Host header, as a client addressing a virtual
    /// host would send it.
    pub async fn get_with_host(&self, url: &str, host: &str) -> anyhow::Result<Recorded> {
        let response = self
            .inner
            .get(url)
            .header(reqwest::header::HOST, host)
            .send()
            .await?;
        Self::record(response).await
    }

    /// POST with no body.
    pub async fn post_empty(&self, url: &str) -> anyhow::Result<Recorded> {
        let response = self.inner.post(url).send().await?;
        Self::record(response).await
    }

    /// Any request: method, extra headers and an optional body with its
    /// content type, sent exactly as given.
    pub async fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<(&str, Vec<u8>)>,
    ) -> anyhow::Result<Recorded> {
        let mut request = self.inner.request(method, url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some((content_type, bytes)) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(bytes);
        }
        Self::record(request.send().await?).await
    }

    pub async fn post_form(&self, url: &str, form: &[(&str, &str)]) -> anyhow::Result<Recorded> {
        let response = self.inner.post(url).form(form).send().await?;
        Self::record(response).await
    }

    async fn record(response: reqwest::Response) -> anyhow::Result<Recorded> {
        let status = response.status().as_u16();
        let mut headers = BTreeMap::new();
        for name in RECORDED_HEADERS {
            if let Some(value) = response.headers().get(*name) {
                headers.insert((*name).to_owned(), value.to_str()?.to_owned());
            }
        }
        let set_cookies = response
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        let is_json = headers
            .get("content-type")
            .is_some_and(|ct| ct.starts_with("application/json"));
        let bytes = response.bytes().await?;
        let body = if bytes.is_empty() {
            Body::Empty
        } else if is_json {
            match serde_json::from_slice(&bytes) {
                Ok(value) => Body::Json(value),
                Err(_) => Body::Text(String::from_utf8_lossy(&bytes).into_owned()),
            }
        } else {
            Body::Text(String::from_utf8_lossy(&bytes).into_owned())
        };
        Ok(Recorded {
            status,
            headers,
            set_cookies,
            body,
        })
    }
}
