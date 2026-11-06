//! Minimal HTTPS client: fixed timeouts, bounded retries, and a host allowlist.

use std::time::Duration;

use crate::error::{Result, ScanError};

/// The only hosts the public tier may contact .
pub const ALLOWED_HOSTS: &[&str] = &[
    "pypi.org",
    "raw.githubusercontent.com",
    "api.regional-table.region-services.aws.a2z.com",
    "docs.aws.eu",
    "registry.terraform.io",
];

const RETRIES: u32 = 3;

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

    /// GETs `url` and returns the body. 404 is not retried; other failures are retried
    /// with linear backoff.
    pub fn get_text(&self, url: &str) -> Result<String> {
        check_allowed(url)?;
        let mut last = String::new();
        for attempt in 0..RETRIES {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(500 * u64::from(attempt)));
            }
            match self.inner.get(url).send() {
                Ok(resp) if resp.status().is_success() => {
                    return resp
                        .text()
                        .map_err(|e| ScanError::DataSource(format!("{url}: {e}")));
                }
                Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
                    return Err(ScanError::DataSource(format!("{url}: 404 Not Found")));
                }
                Ok(resp) => last = format!("HTTP {}", resp.status()),
                Err(e) => last = e.to_string(),
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
        assert!(check_allowed("https://pypi.org/pypi/botocore/json").is_ok());
        assert!(check_allowed("https://example.com/x").is_err());
        assert!(check_allowed("http://pypi.org/x").is_err());
        assert!(check_allowed("https://pypi.org.evil.test/x").is_err());
    }
}
