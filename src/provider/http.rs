//! Minimal HTTPS client: fixed timeouts, bounded retries, and a host allowlist.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crate::error::{Result, ScanError};

/// The only hosts the public tier may contact.
pub const ALLOWED_HOSTS: &[&str] = &[
    "knowledge-mcp.global.api.aws",
    "prod.capabilities.builder.aws.com",
    "docs.aws.eu",
    // Terraform provider type maps, for Terraform input only.
    "registry.terraform.io",
    "raw.githubusercontent.com",
];

/// CloudFormation resource schema bundles, one host per Region:
/// `schema.cloudformation.<region>.amazonaws.com`, `.amazonaws.com.cn` in China.
const SCHEMA_HOST_PREFIX: &str = "schema.cloudformation.";
const SCHEMA_HOST_SUFFIXES: &[&str] = &[".amazonaws.com", ".amazonaws.com.cn"];

/// The largest body read; the biggest schema bundle is about 3 MB.
const MAX_BODY: usize = 64 << 20;

const RETRIES: u32 = 3;
/// Waits on HTTP 429 per request, each as long as `Retry-After` says, at most a minute.
const THROTTLE_WAITS: u32 = 2;
const MAX_WAIT_SECS: u64 = 60;

pub struct Client {
    inner: reqwest::blocking::Client,
    /// HTTP 429 answers so far, for callers that adapt how many calls they run at once.
    throttled: AtomicU32,
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
        Ok(Self {
            inner,
            throttled: AtomicU32::new(0),
        })
    }

    /// How many HTTP 429 answers this client has seen.
    pub fn throttled(&self) -> u32 {
        self.throttled.load(Ordering::Relaxed)
    }

    /// GETs `url` and returns the body.
    pub fn get_text(&self, url: &str) -> Result<String> {
        String::from_utf8(self.get_bytes(url)?)
            .map_err(|e| ScanError::DataSource(format!("{url}: {e}")))
    }

    /// GETs `url` and returns the body as bytes.
    pub fn get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        self.send(url, || self.inner.get(url))
    }

    /// POSTs a JSON body to `url` and returns the response body.
    pub fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<String> {
        let bytes = self.send(url, || {
            self.inner
                .post(url)
                .header("Accept", "application/json, text/event-stream")
                .json(body)
        })?;
        String::from_utf8(bytes).map_err(|e| ScanError::DataSource(format!("{url}: {e}")))
    }

    /// 404 is not retried. 429 waits as long as `Retry-After` says, twice at most;
    /// other failures are retried with linear backoff.
    fn send(
        &self,
        url: &str,
        req: impl Fn() -> reqwest::blocking::RequestBuilder,
    ) -> Result<Vec<u8>> {
        check_allowed(url)?;
        let (mut last, mut attempt, mut waits) = (String::new(), 0, 0);
        while attempt < RETRIES {
            match req().send() {
                Ok(resp) if resp.status().is_success() => {
                    let too_big = || {
                        ScanError::DataSource(format!("{url}: body larger than {MAX_BODY} bytes"))
                    };
                    if resp.content_length().is_some_and(|n| n > MAX_BODY as u64) {
                        return Err(too_big());
                    }
                    let body = resp
                        .bytes()
                        .map_err(|e| ScanError::DataSource(format!("{url}: {e}")))?;
                    if body.len() > MAX_BODY {
                        return Err(too_big());
                    }
                    return Ok(body.to_vec());
                }
                Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
                    return Err(ScanError::DataSource(format!("{url}: 404 Not Found")));
                }
                Ok(resp) if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                    self.throttled.fetch_add(1, Ordering::Relaxed);
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
    if ALLOWED_HOSTS.contains(&host) || is_schema_host(host) {
        Ok(())
    } else {
        Err(ScanError::DataSource(format!("host not allowed: {host}")))
    }
}

/// `schema.cloudformation.<region>.amazonaws.com[.cn]` with a Region-shaped label.
fn is_schema_host(host: &str) -> bool {
    host.strip_prefix(SCHEMA_HOST_PREFIX).is_some_and(|rest| {
        SCHEMA_HOST_SUFFIXES.iter().any(|sfx| {
            rest.strip_suffix(sfx).is_some_and(|region| {
                !region.is_empty()
                    && region.split('-').count() >= 3
                    && region
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        })
    })
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
        let ok = "https://schema.cloudformation.eu-west-1.amazonaws.com/CloudformationSchema.zip";
        assert!(check_allowed(ok).is_ok());
        assert!(
            check_allowed("https://schema.cloudformation.cn-north-1.amazonaws.com.cn/x").is_ok()
        );
        for bad in [
            "https://schema.cloudformation.amazonaws.com/x",
            "https://schema.cloudformation.evil.test.amazonaws.com/x",
            "https://schema.cloudformation.eu-west-1.amazonaws.com.evil.test/x",
            "https://xschema.cloudformation.eu-west-1.amazonaws.com/x",
        ] {
            assert!(check_allowed(bad).is_err(), "{bad}");
        }
    }
}
