//! `--probe`: one GET for container health checks, with no configuration
//! loaded. A listener configured with `[tls]` answers plain HTTP with a
//! TLS failure, so on loopback a failed `http://` request is retried once
//! over HTTPS without certificate verification: the probe only ever talks
//! to its own container's listener.

use std::time::Duration;

/// Whether `url` may be retried over HTTPS without verification: an
/// `http://` URL for a loopback host.
pub fn fallback_allowed(url: &str) -> bool {
    let Ok(url) = url::Url::parse(url) else {
        return false;
    };
    url.scheme() == "http"
        && match url.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
            None => false,
        }
}

/// `url` over https, whatever case its scheme was written in.
fn https_url(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return url.to_owned();
    };
    match parsed.set_scheme("https") {
        Ok(()) => parsed.to_string(),
        Err(()) => url.to_owned(),
    }
}

/// The exit code for one GET of `url`: 0 for a 2xx within 5 seconds.
pub async fn probe(url: &str) -> i32 {
    match get(url, false).await {
        Ok(code) => code,
        Err(error) if fallback_allowed(url) => {
            let https = https_url(url);
            match get(&https, true).await {
                Ok(code) => code,
                Err(tls_error) => {
                    eprintln!("probe: {url}: {error}; {https}: {tls_error}");
                    1
                }
            }
        }
        Err(error) => {
            eprintln!("probe: {url}: {error}");
            1
        }
    }
}

/// The exit code for an answer, or the request's failure.
async fn get(url: &str, accept_any_certificate: bool) -> Result<i32, reqwest::Error> {
    // No proxy: HTTP_PROXY in a container's environment would otherwise
    // carry a loopback probe off the host. No redirects: only the URL's own
    // answer counts.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(accept_any_certificate)
        .build()?;
    let response = client.get(url).send().await?;
    if response.status().is_success() {
        Ok(0)
    } else {
        eprintln!("probe: {url} answered {}", response.status());
        Ok(1)
    }
}

#[cfg(test)]
mod https_url_tests {
    #[test]
    fn the_scheme_is_swapped_in_any_case() {
        assert_eq!(
            super::https_url("HTTP://localhost:8080/ready"),
            "https://localhost:8080/ready"
        );
        assert_eq!(
            super::https_url("http://127.0.0.1/ready"),
            "https://127.0.0.1/ready"
        );
    }
}
