//! Public availability for AWS China, which neither the capabilities API nor the
//! Knowledge MCP server covers. Resource types are the Region's CloudFormation schema
//! bundle; services are the AWS SDK endpoint data (botocore `endpoints.json`). China
//! publishes no machine-readable products, roadmap or config values.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use super::http::Client;
use super::knowledge::{Knowledge, Needs};
use super::{capabilities, schema};
use crate::error::{Result, ScanError};
use crate::extractor::PartitionFacts;

pub const PARTITION: &str = "aws-cn";
/// The endpoint data of the AWS SDK for Python, current branch.
pub const ENDPOINTS_URL: &str =
    "https://raw.githubusercontent.com/boto/botocore/develop/botocore/data/endpoints.json";

/// China availability for one Region, with the downloaded schema bundle so property
/// checks read it without a second download.
pub struct China {
    pub knowledge: Knowledge,
    pub bundle_url: String,
    /// `None` when the input has no resource types.
    pub bundle: Option<Vec<u8>>,
}

/// With `needs`: the input's types and services. Without: every type the Region
/// registers, for `compare`. A type the bundle lacks is not available when the
/// capabilities API knows it from another Region, and unknown otherwise.
pub fn fetch(client: &Client, facts: &PartitionFacts, needs: Option<&Needs>) -> Result<China> {
    let region = facts.target_region.as_str();
    let bundle_url = schema::bundle_url(facts)
        .ok_or_else(|| ScanError::DataSource(format!("no schema bundle for {region}")))?;
    let want_types = needs.is_none_or(|n| !n.types.is_empty());
    let (bundle, endpoints, known) = std::thread::scope(|s| {
        let e = s.spawn(|| needs.map(|_| client.get_text(ENDPOINTS_URL)).transpose());
        let k = s.spawn(|| {
            needs
                .filter(|n| !n.types.is_empty())
                .map(|_| capabilities::known_types(client))
        });
        let b = want_types
            .then(|| client.get_bytes(&bundle_url))
            .transpose();
        (
            b,
            e.join().expect("endpoint data fetch does not panic"),
            k.join().expect("capabilities fetch does not panic"),
        )
    });
    let bundle = bundle?;
    let registered: BTreeSet<String> = match &bundle {
        Some(zip) => schema::read_bundle(zip, &bundle_url, None, false)?
            .into_keys()
            .collect(),
        None => BTreeSet::new(),
    };
    let knowledge = match needs {
        None => Knowledge {
            types: registered.iter().map(|t| (t.clone(), true)).collect(),
            ..Knowledge::default()
        },
        Some(n) => {
            // Without it, a type the bundle lacks stays unknown.
            let known = known.and_then(|k| {
                k.map_err(|e| {
                    crate::tui::note(&format!(
                        "esc-preflight: {e}; resource types {region} does not register are reported as unknown"
                    ));
                })
                .ok()
            });
            let offered = match endpoints? {
                Some(text) => services(&text, region)?,
                None => BTreeSet::new(),
            };
            merge(n, &registered, known.as_ref(), &offered)
        }
    };
    Ok(China {
        knowledge,
        bundle_url,
        bundle,
    })
}

/// The input's types and services against what the Region registers and offers.
fn merge(
    needs: &Needs,
    registered: &BTreeSet<String>,
    known: Option<&BTreeSet<String>>,
    offered: &BTreeSet<String>,
) -> Knowledge {
    let mut k = Knowledge::default();
    for t in &needs.types {
        if registered.contains(t) {
            k.types.insert(t.clone(), true);
        } else if known.is_some_and(|all| all.contains(t)) {
            k.types.insert(t.clone(), false);
        }
    }
    k.mark_unknown_types(needs);
    for id in &needs.services {
        match crate::services::index().by_service_id(id) {
            Some(s) => {
                k.services
                    .insert(id.clone(), offered.contains(&s.endpoint_prefix));
            }
            None => {
                k.unknown.insert(id.clone());
            }
        }
    }
    k
}

#[derive(Deserialize)]
struct Endpoints {
    partitions: Vec<Partition>,
}

#[derive(Deserialize)]
struct Partition {
    partition: String,
    services: BTreeMap<String, EndpointService>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EndpointService {
    #[serde(default)]
    endpoints: BTreeMap<String, serde_json::Value>,
    is_regionalized: Option<bool>,
}

/// Endpoint prefixes with an endpoint in `region`; a partition-wide service (IAM,
/// CloudFront) counts for every Region of the partition.
fn services(text: &str, region: &str) -> Result<BTreeSet<String>> {
    let bad = |m: String| ScanError::DataSource(format!("{ENDPOINTS_URL}: {m}"));
    let e: Endpoints = serde_json::from_str(text).map_err(|e| bad(e.to_string()))?;
    let p = e
        .partitions
        .into_iter()
        .find(|p| p.partition == PARTITION)
        .ok_or_else(|| bad(format!("no {PARTITION} partition")))?;
    let out: BTreeSet<String> = p
        .services
        .into_iter()
        .filter(|(_, s)| s.is_regionalized == Some(false) || s.endpoints.contains_key(region))
        .map(|(prefix, _)| prefix)
        .collect();
    if out.len() < 50 {
        return Err(bad(format!(
            "{} services in {region}; the file's shape may have changed",
            out.len()
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_bundle_capabilities_and_endpoints() {
        let set = |l: &[&str]| l.iter().map(|s| (*s).to_string()).collect::<BTreeSet<_>>();
        let needs = Needs {
            types: set(&[
                "AWS::Lambda::Function",
                "AWS::Cognito::UserPool",
                "AWS::Nope::T",
            ]),
            services: set(&["Lambda", "Cognito Identity Provider", "Not A Service"]),
            ..Needs::default()
        };
        let registered = set(&["AWS::Lambda::Function", "AWS::S3::Bucket"]);
        let known = set(&["AWS::Lambda::Function", "AWS::Cognito::UserPool"]);
        let offered = set(&["lambda", "s3"]);
        let k = merge(&needs, &registered, Some(&known), &offered);
        assert_eq!(k.types.get("AWS::Lambda::Function"), Some(&true));
        assert_eq!(k.types.get("AWS::Cognito::UserPool"), Some(&false));
        assert!(!k.types.contains_key("AWS::Nope::T"));
        assert_eq!(k.services.get("Lambda"), Some(&true));
        assert_eq!(k.services.get("Cognito Identity Provider"), Some(&false));
        let unknown: Vec<&str> = k.unknown.iter().map(String::as_str).collect();
        assert_eq!(unknown, ["AWS::Nope::T", "Not A Service"]);
        // Without the capabilities API, a type the bundle lacks is unknown.
        let k = merge(&needs, &registered, None, &offered);
        assert!(k.unknown.contains("AWS::Cognito::UserPool"));
    }

    #[test]
    fn regional_and_partition_wide_services() {
        let mut all = serde_json::Map::new();
        for i in 0..60 {
            all.insert(
                format!("s{i}"),
                serde_json::json!({"endpoints": {"cn-north-1": {}}}),
            );
        }
        all.insert(
            "lambda".into(),
            serde_json::json!({"endpoints": {"cn-north-1": {}, "cn-northwest-1": {}}}),
        );
        all.insert(
            "appstream2".into(),
            serde_json::json!({"endpoints": {"cn-northwest-1": {}}}),
        );
        all.insert(
            "iam".into(),
            serde_json::json!({"endpoints": {"aws-cn-global": {}}, "isRegionalized": false, "partitionEndpoint": "aws-cn-global"}),
        );
        let text = serde_json::json!({"partitions": [
            {"partition": "aws", "services": {"bedrock": {"endpoints": {"cn-north-1": {}}}}},
            {"partition": "aws-cn", "services": all},
        ]})
        .to_string();
        let s = services(&text, "cn-north-1").unwrap();
        assert!(s.contains("lambda") && s.contains("iam"));
        assert!(!s.contains("appstream2") && !s.contains("bedrock"));
        assert!(services(&text, "cn-northwest-1").is_err());
    }

    /// Hits the real sources. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn live_china() {
        let client = Client::new(std::time::Duration::from_secs(60)).unwrap();
        let needs = Needs {
            types: [
                "AWS::Lambda::Function",
                "AWS::Cognito::UserPool",
                "AWS::Nope::Thing",
            ]
            .map(String::from)
            .into(),
            services: ["Lambda", "Bedrock Runtime"].map(String::from).into(),
            ..Needs::default()
        };
        let facts = super::super::partition::facts("cn-north-1").unwrap();
        let k = fetch(&client, &facts, Some(&needs)).unwrap().knowledge;
        assert_eq!(k.types.get("AWS::Lambda::Function"), Some(&true));
        assert_eq!(k.types.get("AWS::Cognito::UserPool"), Some(&false));
        assert!(k.unknown.contains("AWS::Nope::Thing"));
        assert_eq!(k.services.get("Lambda"), Some(&true));
        assert_eq!(k.services.get("Bedrock Runtime"), Some(&false));
    }
}
