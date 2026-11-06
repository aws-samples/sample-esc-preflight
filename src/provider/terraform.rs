//! Terraform type maps from HashiCorp's own provider data, fetched at the latest release.
//!
//! - aws: `names/data/names_data.hcl` gives each service's resource-name prefix pattern
//!   and its SDK service id.
//! - awscc: `internal/provider/all_schemas.hcl` gives each type's CloudFormation type.

use std::collections::BTreeMap;

use regex_lite::Regex;

use super::http::Client;
use crate::error::{Result, ScanError};

const MIN_AWS_SERVICES: usize = 300;
const MIN_AWSCC_TYPES: usize = 1000;

#[derive(Debug, Clone)]
pub struct TfMaps {
    pub aws_version: String,
    pub awscc_version: String,
    pub urls: Vec<String>,
    prefixes: Vec<(Regex, String)>,
    awscc: BTreeMap<String, String>,
    services: usize,
}

impl TfMaps {
    /// SDK service id for an `aws_*` type. The longest matching prefix wins, which is
    /// what upstream's negative lookaheads express (`aws_cloudwatch_` vs
    /// `aws_cloudwatch_log_`).
    pub fn aws_service_id(&self, tf_type: &str) -> Option<&str> {
        self.prefixes
            .iter()
            .filter_map(|(re, id)| re.find(tf_type).map(|m| (m.end(), id)))
            .max_by_key(|(len, _)| *len)
            .map(|(_, id)| id.as_str())
    }

    /// CloudFormation type for an `awscc_*` type.
    pub fn awscc_cfn_type(&self, tf_type: &str) -> Option<&str> {
        self.awscc.get(tf_type).map(String::as_str)
    }
}

pub fn fetch(client: &Client) -> Result<TfMaps> {
    let (aws_version, aws_url) = locate(client, "aws", "names/data/names_data.hcl")?;
    let (awscc_version, awscc_url) = locate(client, "awscc", "internal/provider/all_schemas.hcl")?;
    let mut maps = parse(
        &aws_version,
        &client.get_text(&aws_url)?,
        &awscc_version,
        &client.get_text(&awscc_url)?,
    )?;
    check_complete(&maps)?;
    maps.urls = vec![aws_url, awscc_url];
    Ok(maps)
}

/// The fetched files must be complete; a truncated or reshaped file must not pass as
/// "this service is unknown".
fn check_complete(m: &TfMaps) -> Result<()> {
    if m.services < MIN_AWS_SERVICES || m.awscc.len() < MIN_AWSCC_TYPES {
        return Err(ScanError::DataSource(format!(
            "Terraform provider data looks malformed: {} aws services (v{}), {} awscc types (v{})",
            m.services,
            m.aws_version,
            m.awscc.len(),
            m.awscc_version
        )));
    }
    Ok(())
}

fn locate(client: &Client, provider: &str, path: &str) -> Result<(String, String)> {
    let reg = format!("https://registry.terraform.io/v1/providers/hashicorp/{provider}");
    let v: serde_json::Value = serde_json::from_str(&client.get_text(&reg)?)
        .map_err(|e| ScanError::DataSource(format!("{reg}: {e}")))?;
    let version = v["version"]
        .as_str()
        .ok_or_else(|| ScanError::DataSource(format!("{reg}: no version")))?
        .to_string();
    let url = format!(
        "https://raw.githubusercontent.com/hashicorp/terraform-provider-{provider}/v{version}/{path}"
    );
    Ok((version, url))
}

pub fn parse(aws_version: &str, names: &str, awscc_version: &str, schemas: &str) -> Result<TfMaps> {
    let id_re = Regex::new(r#"(?m)^\s*id\s*=\s*"([^"]+)""#).unwrap();
    let prefix_re = Regex::new(r"resource_prefix\s*\{([^}]*)\}").unwrap();
    let actual_re = Regex::new(r#"actual\s*=\s*"((?:[^"\\]|\\.)*)""#).unwrap();
    let correct_re = Regex::new(r#"correct\s*=\s*"([^"]*)""#).unwrap();
    let mut prefixes = Vec::new();
    let mut services = 0;
    for block in names.split("\nservice \"").skip(1) {
        // Sub-services (EBS, VPC, ...) carry an empty id and belong to the parent's SDK.
        let Some(id) = id_re.captures(block).map(|c| c[1].to_string()) else {
            continue;
        };
        services += 1;
        for p in prefix_re.captures_iter(block) {
            let pattern = if let Some(a) = actual_re.captures(&p[1]) {
                strip_lookaheads(&a[1].replace("\\\\", "\\"))
            } else if let Some(c) = correct_re.captures(&p[1]) {
                regex_lite::escape(&c[1])
            } else {
                continue;
            };
            let re = Regex::new(&format!("^(?:{pattern})")).map_err(|e| {
                ScanError::DataSource(format!("names_data.hcl {aws_version}: {id}: {e}"))
            })?;
            prefixes.push((re, id.clone()));
        }
    }
    let schema_re = Regex::new(
        r#"resource_schema\s+"([^"]+)"\s*\{\s*cloudformation_type_name\s*=\s*"([^"]+)""#,
    )
    .unwrap();
    let awscc: BTreeMap<String, String> = schema_re
        .captures_iter(schemas)
        .filter_map(|c| {
            Some((
                format!("awscc_{}", c[1].strip_prefix("aws_")?),
                c[2].to_string(),
            ))
        })
        .collect();
    Ok(TfMaps {
        aws_version: aws_version.into(),
        awscc_version: awscc_version.into(),
        urls: Vec::new(),
        prefixes,
        awscc,
        services,
    })
}

/// Removes `(?!...)` groups, which `regex-lite` does not support.
fn strip_lookaheads(p: &str) -> String {
    let mut out = String::new();
    let mut rest = p;
    while let Some(i) = rest.find("(?!") {
        out.push_str(&rest[..i]);
        let mut depth = 0;
        let end = rest[i..]
            .char_indices()
            .find(|&(_, c)| {
                depth += match c {
                    '(' => 1,
                    ')' => -1,
                    _ => 0,
                };
                depth == 0
            })
            .map_or(rest.len(), |(j, _)| i + j + 1);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn fixture() -> TfMaps {
        let v = crate::test_inputs::TF_PROVIDER_VERSIONS;
        let mut v = v.lines();
        parse(
            v.next().unwrap(),
            include_str!("../../tests/fixtures/tf-aws-names.hcl"),
            v.next().unwrap(),
            crate::test_inputs::TF_AWSCC_SCHEMAS,
        )
        .unwrap()
    }

    #[test]
    fn aws_types_map_to_sdk_ids() {
        let m = fixture();
        for (t, id) in [
            ("aws_lb", "Elastic Load Balancing v2"),
            ("aws_lb_listener", "Elastic Load Balancing v2"),
            ("aws_lb_cookie_stickiness_policy", "Elastic Load Balancing"),
            ("aws_cloudwatch_log_group", "CloudWatch Logs"),
            ("aws_cloudwatch_metric_alarm", "CloudWatch"),
            ("aws_cloudwatch_event_rule", "EventBridge"),
            ("aws_route53_resolver_endpoint", "Route53Resolver"),
            ("aws_route53_zone", "Route 53"),
            ("aws_cognito_identity_pool", "Cognito Identity"),
            ("aws_cognito_user_pool", "Cognito Identity Provider"),
            ("aws_vpc_ipam", "EC2"),
            ("aws_security_group", "EC2"),
            ("aws_instance", "EC2"),
            ("aws_db_instance", "RDS"),
            ("aws_s3_bucket", "S3"),
            ("aws_dynamodb_table", "DynamoDB"),
        ] {
            assert_eq!(m.aws_service_id(t), Some(id), "{t}");
        }
        assert_eq!(m.aws_service_id("aws_not_a_service_thing"), None);
    }

    #[test]
    fn awscc_types_map_to_cfn_types() {
        assert_eq!(
            fixture().awscc_cfn_type("awscc_s3_bucket"),
            Some("AWS::S3::Bucket")
        );
    }

    #[test]
    fn lookahead_groups_are_removed() {
        assert_eq!(
            strip_lookaheads("aws_cloudwatch_(?!(event_|log_|query_))"),
            "aws_cloudwatch_"
        );
        assert_eq!(strip_lookaheads("a(vpc(?!_ipam)|b)"), "a(vpc|b)");
    }

    #[test]
    fn truncated_data_fails_loud() {
        let m = parse("1", "", "1", "").unwrap();
        assert_eq!(check_complete(&m).unwrap_err().exit_code(), 3);
        assert!(check_complete(&fixture()).is_err(), "fixture is a subset");
    }
}
