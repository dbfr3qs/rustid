//! Fetching request objects by reference.
//! The server supplies an HTTP fetcher; the default fetches nothing.

use async_trait::async_trait;

/// What a request URI answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub status: u16,
    /// The media type, without parameters.
    pub content_type: Option<String>,
    pub body: String,
}

#[async_trait]
pub trait RequestUriFetcher: Send + Sync {
    /// GETs the URI; `None` when it couldn't be reached.
    async fn fetch(&self, uri: &str) -> Option<Fetched>;
}

/// Fetches nothing: every request URI answers `None`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRequestUriFetcher;

#[async_trait]
impl RequestUriFetcher for NoRequestUriFetcher {
    async fn fetch(&self, _: &str) -> Option<Fetched> {
        None
    }
}
