//! One SigV4-signed call to any AWS service, driven by the bundled service table.
//! Replaces per-service SDK crates; only the credential chain comes from `aws-config`.

use std::time::{Duration, SystemTime};

use aws_credential_types::Credentials;
use aws_credential_types::provider::ProvideCredentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use aws_sigv4::sign::v4;

use crate::error::{Result, ScanError};
use crate::services::Service;

pub struct Caller {
    creds: Credentials,
    region: String,
    dns_suffix: String,
    http: reqwest::blocking::Client,
}

/// Throttled calls are retried with exponential backoff, about 15 s in total.
const MAX_ATTEMPTS: u32 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Ok(String),
    /// The service answered with an error code.
    Error(String),
    /// The host name does not resolve: the service has no endpoint in the region.
    NoEndpoint,
    Failed(String),
}

impl Outcome {
    pub fn is_denied(&self) -> bool {
        matches!(self, Outcome::Error(code)
            if code.starts_with("AccessDenied") || code.starts_with("Unauthorized"))
    }

    fn is_throttled(&self) -> bool {
        matches!(self, Outcome::Error(code)
            if code.contains("Throttl") || code == "TooManyRequestsException" || code == "RequestLimitExceeded")
    }

    /// The body of a successful call, or an error for anything else.
    pub fn body(self, what: &str) -> Result<String> {
        match self {
            Outcome::Ok(b) => Ok(b),
            o if o.is_denied() => Err(ScanError::Auth(format!("{what}: {o:?}"))),
            o => Err(ScanError::DataSource(format!("{what}: {o:?}"))),
        }
    }
}

impl Caller {
    pub fn new(
        region: &str,
        dns_suffix: &str,
        profile: Option<&str>,
        role_arn: Option<&str>,
        timeout: Duration,
    ) -> Result<Self> {
        check_endpoint_parts(region, dns_suffix)?;
        let creds = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ScanError::DataSource(format!("cannot start runtime: {e}")))?
            .block_on(credentials(region, profile, role_arn))?;
        let http = reqwest::blocking::Client::builder()
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .timeout(timeout)
            // A redirect would carry the signed request and session token to another host.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ScanError::DataSource(format!("cannot build HTTP client: {e}")))?;
        Ok(Self {
            creds,
            region: region.into(),
            dns_suffix: dns_suffix.into(),
            http,
        })
    }

    /// Calls `op`. Query and EC2 protocols send `params` in the form body; REST
    /// protocols send them as the query string of `method uri`; JSON sends `{}`.
    pub fn call(
        &self,
        svc: &Service,
        op: &str,
        method: &str,
        uri: &str,
        params: &[(&str, &str)],
    ) -> Outcome {
        let host = format!(
            "{}.{}.{}",
            svc.endpoint_prefix, self.region, self.dns_suffix
        );
        let mut attempt = 0;
        loop {
            let (req, body) = request(svc, op, uri, params);
            let url = format!("https://{host}{}", req.path_and_query);
            let mut headers = req.headers;
            headers.push(("host".into(), host.clone()));
            let outcome = match self.send(svc, method, &url, headers, body) {
                Ok(o) => o,
                Err(e) => Outcome::Failed(e),
            };
            attempt += 1;
            if !outcome.is_throttled() || attempt == MAX_ATTEMPTS {
                return outcome;
            }
            std::thread::sleep(std::time::Duration::from_millis(500 << attempt));
        }
    }

    fn send(
        &self,
        svc: &Service,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: String,
    ) -> std::result::Result<Outcome, String> {
        let identity = self.creds.clone().into();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(&svc.signing_name)
            .time(SystemTime::now())
            .settings(SigningSettings::default())
            .build()
            .map_err(|e| e.to_string())?
            .into();
        let signable = SignableRequest::new(
            method,
            url,
            headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            SignableBody::Bytes(body.as_bytes()),
        )
        .map_err(|e| e.to_string())?;
        let (signed, _) = sign(signable, &params)
            .map_err(|e| e.to_string())?
            .into_parts();
        let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
        let mut req = self.http.request(method, url).body(body);
        for (k, v) in headers.iter().filter(|(k, _)| k != "host") {
            req = req.header(k, v);
        }
        for (k, v) in signed.headers() {
            req = req.header(k, v);
        }
        let resp = match req.send() {
            Ok(r) => r,
            Err(e) if is_dns_failure(&e) => return Ok(Outcome::NoEndpoint),
            Err(e) => return Err(e.to_string()),
        };
        let status = resp.status();
        let header_code = resp
            .headers()
            .get("x-amzn-errortype")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(':').next().unwrap_or(s).to_string());
        let text = resp.text().map_err(|e| e.to_string())?;
        if status.is_success() {
            return Ok(Outcome::Ok(text));
        }
        match header_code.or_else(|| error_code(&text)) {
            Some(code) => Ok(Outcome::Error(code)),
            None => Err(format!("HTTP {status} without an error code")),
        }
    }
}

struct Request {
    path_and_query: String,
    headers: Vec<(String, String)>,
}

fn request(svc: &Service, op: &str, uri: &str, params: &[(&str, &str)]) -> (Request, String) {
    match svc.protocol.as_str() {
        "query" | "ec2" => {
            let mut form = vec![("Action", op), ("Version", svc.api_version.as_str())];
            form.extend_from_slice(params);
            let body = encode(&form);
            let headers = vec![(
                "content-type".into(),
                "application/x-www-form-urlencoded; charset=utf-8".into(),
            )];
            (req("/", headers), body)
        }
        "json" => {
            let headers = vec![
                (
                    "x-amz-target".into(),
                    format!("{}.{op}", svc.target_prefix.as_deref().unwrap_or_default()),
                ),
                (
                    "content-type".into(),
                    format!(
                        "application/x-amz-json-{}",
                        svc.json_version.as_deref().unwrap_or("1.0")
                    ),
                ),
            ];
            (req("/", headers), "{}".into())
        }
        _ => {
            let q = encode(params);
            let path = if q.is_empty() {
                uri.to_string()
            } else {
                format!("{uri}?{q}")
            };
            (req(&path, Vec::new()), String::new())
        }
    }
}

fn req(path_and_query: &str, headers: Vec<(String, String)>) -> Request {
    Request {
        path_and_query: path_and_query.into(),
        headers,
    }
}

/// RFC 3986 form encoding, as SigV4 expects.
fn encode(pairs: &[(&str, &str)]) -> String {
    let esc = |s: &str| -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    };
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", esc(k), esc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// `<Code>X</Code>` for XML protocols, `__type`/`code` for JSON ones.
fn error_code(body: &str) -> Option<String> {
    if let Some(c) = xml_values(body, "Code").into_iter().next() {
        return Some(c);
    }
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let raw = v["__type"]
        .as_str()
        .or(v["code"].as_str())
        .or(v["Code"].as_str())?;
    Some(raw.rsplit('#').next().unwrap_or(raw).to_string())
}

/// Text of every `<tag>...</tag>` element. AWS responses carry no CDATA or attributes on
/// the elements read here, so a scan is enough.
pub fn xml_values(body: &str, tag: &str) -> Vec<String> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    body.split(&open)
        .skip(1)
        .filter_map(|s| s.split_once(&close).map(|(v, _)| unescape(v)))
        .collect()
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// DNS suffixes of AWS partitions. The suffix comes from downloaded botocore data,
/// so it is checked before any request is signed: a tampered `partitions.json` must
/// not be able to send the signed request and session token to another host.
const AWS_DNS_SUFFIXES: &[&str] = &[
    "amazonaws.com",
    "amazonaws.com.cn",
    "amazonaws.eu",
    "c2s.ic.gov",
    "sc2s.sgov.gov",
    "cloud.adc-e.uk",
    "csp.hci.ic.gov",
];

fn check_endpoint_parts(region: &str, dns_suffix: &str) -> Result<()> {
    let region_ok = !region.is_empty()
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !region_ok {
        return Err(ScanError::DataSource(format!(
            "refusing to sign requests: invalid region {region:?}"
        )));
    }
    if !AWS_DNS_SUFFIXES.contains(&dns_suffix) {
        return Err(ScanError::DataSource(format!(
            "refusing to sign requests: {dns_suffix:?} is not an AWS DNS suffix"
        )));
    }
    Ok(())
}

fn is_dns_failure(e: &reqwest::Error) -> bool {
    let mut src: Option<&dyn std::error::Error> = Some(e);
    while let Some(s) = src {
        let msg = s.to_string();
        if msg.contains("dns error") || msg.contains("failed to lookup address") {
            return true;
        }
        src = s.source();
    }
    false
}

async fn credentials(
    region: &str,
    profile: Option<&str>,
    role_arn: Option<&str>,
) -> Result<Credentials> {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()));
    if let Some(p) = profile {
        loader = loader.profile_name(p);
    }
    let base = loader.load().await;
    let auth = |e: aws_credential_types::provider::error::CredentialsError| {
        ScanError::Auth(format!("cannot load credentials: {e}"))
    };
    match role_arn {
        None => base
            .credentials_provider()
            .ok_or_else(|| ScanError::Auth("no credentials found".into()))?
            .provide_credentials()
            .await
            .map_err(auth),
        Some(arn) => aws_config::sts::AssumeRoleProvider::builder(arn)
            .session_name("esc-preflight")
            .configure(&base)
            .build()
            .await
            .provide_credentials()
            .await
            .map_err(auth),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services;

    #[test]
    fn only_aws_endpoints_are_signed_for() {
        assert!(check_endpoint_parts("eusc-de-east-1", "amazonaws.eu").is_ok());
        assert!(check_endpoint_parts("eusc-de-east-1", "attacker.example").is_err());
        assert!(check_endpoint_parts("eusc-de-east-1", "amazonaws.eu.attacker.example").is_err());
        assert!(check_endpoint_parts("x.attacker.example/", "amazonaws.eu").is_err());
        assert!(check_endpoint_parts("", "amazonaws.eu").is_err());
    }

    #[test]
    fn builds_each_protocol() {
        let i = services::index();
        let (r, body) = request(
            i.by_endpoint_prefix("cloudformation").unwrap(),
            "ListTypes",
            "/",
            &[("Filters.Category", "AWS_TYPES"), ("NextToken", "a+b/c=")],
        );
        assert_eq!(r.path_and_query, "/");
        assert_eq!(
            body,
            "Action=ListTypes&Version=2010-05-15&Filters.Category=AWS_TYPES&NextToken=a%2Bb%2Fc%3D"
        );
        let (r, body) = request(
            i.by_endpoint_prefix("dynamodb").unwrap(),
            "ListTables",
            "/",
            &[],
        );
        assert_eq!(body, "{}");
        assert!(
            r.headers
                .contains(&("x-amz-target".into(), "DynamoDB_20120810.ListTables".into()))
        );
        assert!(
            r.headers
                .contains(&("content-type".into(), "application/x-amz-json-1.0".into()))
        );
        let (r, body) = request(
            i.by_endpoint_prefix("bedrock").unwrap(),
            "ListInferenceProfiles",
            "/inference-profiles",
            &[("nextToken", "x y")],
        );
        assert_eq!(r.path_and_query, "/inference-profiles?nextToken=x%20y");
        assert!(body.is_empty());
    }

    #[test]
    fn reads_error_codes() {
        assert_eq!(
            error_code("<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code></Error></ErrorResponse>").as_deref(),
            Some("AccessDenied")
        );
        assert_eq!(
            error_code(
                r#"{"__type":"com.amazonaws.codepipeline#AccessDeniedException","message":"x"}"#
            )
            .as_deref(),
            Some("AccessDeniedException")
        );
        assert!(Outcome::Error("AccessDeniedException".into()).is_denied());
        assert!(!Outcome::Error("ValidationException".into()).is_denied());
        assert!(Outcome::Error("Throttling".into()).is_throttled());
        assert!(Outcome::Error("ThrottlingException".into()).is_throttled());
    }

    #[test]
    fn xml_scan() {
        assert_eq!(
            xml_values("<a><b>x&amp;y</b><b>z</b></a>", "b"),
            ["x&y", "z"]
        );
    }
}
