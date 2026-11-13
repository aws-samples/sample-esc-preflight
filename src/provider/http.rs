//! Minimal HTTPS client: fixed timeouts, bounded retries, and a host allowlist.

use std::time::Duration;

use crate::error::{Result, ScanError};

/// The only hosts the public tier may contact.
pub const ALLOWED_HOSTS: &[&str] = &[
    "knowledge-mcp.global.api.aws",
    "docs.aws.eu",
    // Terraform provider type maps, for Terraform input only.
    "registry.terraform.io",
    "raw.githubusercontent.com",
];

const RETRIES: u32 = 3;
/// Waits on HTTP 429 per request, each as long as `Retry-After` says, at most a minute.
const THROTTLE_WAITS: u32 = 2;
const MAX_WAIT_SECS: u64 = 60;

pub struct Client {
    inner: reqwest::blocking::Client,
}

impl Client {
    pub fn new(timeout: Duration) -> Result<Self> {
        let inner = reqwest::blocking::Client::builder()
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .timeout(timeout)
            .user_agent(concat!("esc-preflight/", env!("CARGO_PKG_VERSION")))
            // The allowlist checks the first URL only, so redirects stay off.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ScanError::DataSource(format!("cannot build HTTP client: {e}")))?;
        Ok(Self { inner })
    }

    /// GETs `url` and returns the body.
    pub fn get_text(&self, url: &str) -> Result<String> {
        self.send(url, || self.inner.get(url))
    }

    /// POSTs a JSON body to `url` and returns the response body.
    pub fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<String> {
        self.send(url, || {
            self.inner
                .post(url)
                .header("Accept", "application/json, text/event-stream")
                .json(body)
        })
    }

    /// 404 is not retried. 429 waits as long as `Retry-After` says, twice at most;
    /// other failures are retried with linear backoff.
    fn send(
        &self,
        url: &str,
        req: impl Fn() -> reqwest::blocking::RequestBuilder,
    ) -> Result<String> {
        check_allowed(url)?;
        let (mut last, mut attempt, mut waits) = (String::new(), 0, 0);
        while attempt < RETRIES {
            match req().send() {
                Ok(resp) if resp.status().is_success() => {
                    return resp
                        .text()
                        .map_err(|e| ScanError::DataSource(format!("{url}: {e}")));
                }
                Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
                    return Err(ScanError::DataSource(format!("{url}: 404 Not Found")));
                }
                Ok(resp) if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                    if waits == THROTTLE_WAITS {
                        return Err(ScanError::DataSource(format!(
                            "{url}: rate limit still reached after {waits} waits; try again later"
                        )));
                    }
                    let secs = resp
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok()?.trim().parse::<u64>().ok())
                        .unwrap_or(10)
                        .min(MAX_WAIT_SECS);
                    eprintln!("esc-preflight: rate limit reached at {url}; retrying in {secs} s");
                    std::thread::sleep(Duration::from_secs(secs));
                    waits += 1;
                    continue;
                }
                Ok(resp) => last = format!("HTTP {}", resp.status()),
                Err(e) => last = e.to_string(),
            }
            attempt += 1;
            if attempt < RETRIES {
                std::thread::sleep(Duration::from_millis(500 * u64::from(attempt)));
            }
        }
        Err(ScanError::DataSource(format!(
            "{url}: {last} after {RETRIES} attempts"
        )))
    }
}

fn check_allowed(url: &str) -> Result<()> {
    let host = url
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .ok_or_else(|| ScanError::DataSource(format!("not an https URL: {url}")))?;
    if ALLOWED_HOSTS.contains(&host) {
        Ok(())
    } else {
        Err(ScanError::DataSource(format!("host not allowed: {host}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_hosts_outside_the_allowlist() {
        assert!(check_allowed("https://docs.aws.eu/esc/latest/userguide/").is_ok());
        assert!(check_allowed("https://example.com/x").is_err());
        assert!(check_allowed("http://docs.aws.eu/x").is_err());
        assert!(check_allowed("https://docs.aws.eu.evil.test/x").is_err());
    }
}
