//! The ESC endpoints page, an official per-region endpoint list.
//!
//! Like botocore, a listed endpoint prefix is evidence and an absent one is no claim.
//! The page is HTML, so parsing is defensive: too few entries or no entry for the
//! target region is a data-source failure (exit 3), never an empty result.

use std::collections::BTreeSet;

use super::http::Client;
use crate::error::{Result, ScanError};

pub const URL: &str = "https://docs.aws.eu/general/latest/gr/endpoints.html";
/// The partition the page documents. Other partitions skip this source.
pub const PARTITION: &str = "aws-eusc";
/// The page listed 205 prefixes on 2026-10-29. Far fewer means the layout changed.
const MIN_PREFIXES: usize = 100;
const SUFFIXES: &[&str] = &["amazonaws.eu", "api.amazonwebservices.eu"];

#[derive(Debug, Clone)]
pub struct EndpointsPageData {
    pub url: String,
    /// Endpoint prefixes the page lists for the target region (plus global endpoints).
    pub target_services: BTreeSet<String>,
}

pub fn fetch(client: &Client, target_region: &str) -> Result<EndpointsPageData> {
    parse(&client.get_text(URL)?, target_region)
}

pub fn parse(html: &str, target_region: &str) -> Result<EndpointsPageData> {
    let mut prefixes = BTreeSet::new();
    for token in html.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')) {
        if let Some(p) = prefix(token, target_region) {
            prefixes.insert(p);
        }
    }
    if prefixes.len() < MIN_PREFIXES {
        return Err(ScanError::DataSource(format!(
            "{URL}: found {} endpoint prefixes for {target_region}, expected at least {MIN_PREFIXES}; the page layout may have changed",
            prefixes.len()
        )));
    }
    Ok(EndpointsPageData {
        url: URL.into(),
        target_services: prefixes,
    })
}

/// `api.ecr.eusc-de-east-1.amazonaws.eu` -> `api.ecr`, `s3.dualstack.<region>...` -> `s3`,
/// `route53.amazonaws.eu` (global) -> `route53`.
fn prefix(host: &str, region: &str) -> Option<String> {
    let host = host.trim_matches('.');
    for suffix in SUFFIXES {
        let Some(rest) = host.strip_suffix(suffix).and_then(|r| r.strip_suffix('.')) else {
            continue;
        };
        let p = match rest.strip_suffix(region).and_then(|r| r.strip_suffix('.')) {
            Some(p) => p,
            // Global endpoint: no region label at all.
            None if !rest.contains('.') => rest,
            None => return None,
        };
        let p = p.strip_suffix(".dualstack").unwrap_or(p);
        return (!p.is_empty() && !p.contains("..")).then(|| p.to_string());
    }
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn fixture() -> EndpointsPageData {
        parse(
            include_str!("../../tests/fixtures/endpoints-page.html"),
            "eusc-de-east-1",
        )
        .unwrap()
    }

    #[test]
    fn reads_esc_prefixes() {
        let d = fixture();
        for s in [
            "iam",
            "organizations",
            "route53",
            "sts",
            "eks",
            "api.sagemaker",
            "s3",
            "api.ecr",
            "rolesanywhere",
        ] {
            assert!(d.target_services.contains(s), "{s}");
        }
        for s in [
            "cloudfront",
            "codebuild",
            "codepipeline",
            "codecommit",
            "qbusiness",
        ] {
            assert!(!d.target_services.contains(s), "{s}");
        }
    }

    #[test]
    fn prefix_forms() {
        let r = "eusc-de-east-1";
        assert_eq!(
            prefix("api.ecr.eusc-de-east-1.amazonaws.eu", r).as_deref(),
            Some("api.ecr")
        );
        assert_eq!(
            prefix("s3.dualstack.eusc-de-east-1.amazonaws.eu", r).as_deref(),
            Some("s3")
        );
        assert_eq!(
            prefix("route53.amazonaws.eu", r).as_deref(),
            Some("route53")
        );
        assert_eq!(prefix("x.eusc-de-west-9.amazonaws.eu", r), None);
        assert_eq!(prefix("lambda.eu-central-1.amazonaws.com", r), None);
    }

    #[test]
    fn a_changed_layout_fails_loudly() {
        assert!(
            parse(
                "<html><p>iam.eusc-de-east-1.amazonaws.eu</p></html>",
                "eusc-de-east-1"
            )
            .is_err()
        );
        assert!(
            parse(
                include_str!("../../tests/fixtures/endpoints-page.html"),
                "eu-central-1"
            )
            .is_err()
        );
    }
}
