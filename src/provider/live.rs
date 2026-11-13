//! Live mode: the target account, read-only. Each check runs only if the input needs it.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::aws_call::{Caller, Outcome, xml_values};
use crate::depth::{self, DepthCheck, DepthKind, DepthSource, Offered};
use crate::error::{Result, ScanError};
use crate::matcher::{Live, ServiceStatus};
use crate::services::{self, Service};

/// What the input asks live mode to check.
#[derive(Debug, Default)]
pub struct Needs {
    pub registry: bool,
    /// SDK service ids to probe.
    pub services: BTreeSet<String>,
    pub depth: BTreeMap<String, Vec<DepthCheck>>,
    /// Count the target's zones, because the input spreads over its own environment's.
    pub zones: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveProvenance {
    pub account_id: String,
    pub region: String,
    pub registry_types: Option<usize>,
    pub service_probes: usize,
    pub depth_probes: Vec<DepthKind>,
    /// The caller's role has ReadOnlyAccess (or AdministratorAccess) attached, so an
    /// AccessDenied from a service means the service is not offered.
    pub read_only_access: Option<bool>,
}

pub fn run(caller: &Caller, region: &str, needs: Needs) -> Result<(Live, LiveProvenance)> {
    let sts = svc("sts");
    let identity = caller
        .call(sts, "GetCallerIdentity", "POST", "/", &[])
        .body("GetCallerIdentity")?;
    let account_id = first(&identity, "Account");
    let arn = first(&identity, "Arn");

    let registry = needs.registry.then(|| registry_types(caller)).transpose()?;
    let mut read_only = None;
    let mut services = BTreeMap::new();
    for id in &needs.services {
        let status = match services::index()
            .by_service_id(id)
            .filter(|s| s.probe.is_some())
        {
            None => ServiceStatus::Unverified(
                "No read-only probe call is known for this service".into(),
            ),
            Some(s) => {
                let p = s.probe.as_ref().expect("filtered");
                match caller.call(s, &p.op, &p.method, &p.uri, &[]) {
                    Outcome::NoEndpoint => ServiceStatus::NotOffered,
                    o if o.is_denied() => {
                        if *read_only.get_or_insert_with(|| has_read_only(caller, &arn)) {
                            ServiceStatus::Refused
                        } else {
                            ServiceStatus::Unverified(format!(
                                "{} returned access denied and the caller has no ReadOnlyAccess attached",
                                p.op
                            ))
                        }
                    }
                    Outcome::Ok(_) | Outcome::Error(_) => ServiceStatus::Offered,
                    Outcome::Failed(e) => ServiceStatus::Unverified(format!("{}: {e}", p.op)),
                }
            }
        };
        services.insert(id.clone(), status);
    }

    let mut checks = needs.depth;
    let mut kinds = depth::kinds(&checks);
    if needs.zones {
        kinds.insert(DepthKind::AvailabilityZone);
    }
    let mut offered = Offered::new();
    for kind in &kinds {
        if let Some(set) = depth_probe(caller, *kind, &checks) {
            offered.insert(*kind, set);
        }
    }
    depth::resolve(&mut checks, &offered, DepthSource::Live);
    let target_zones = needs
        .zones
        .then(|| offered.get(&DepthKind::AvailabilityZone).map(BTreeSet::len))
        .flatten();

    let prov = LiveProvenance {
        account_id,
        region: region.into(),
        registry_types: registry.as_ref().map(BTreeSet::len),
        service_probes: services.len(),
        depth_probes: offered.keys().copied().collect(),
        read_only_access: read_only,
    };
    Ok((
        Live {
            registry,
            services,
            depth: checks,
            target_zones,
            offered,
        },
        prov,
    ))
}

fn svc(prefix: &str) -> &'static Service {
    services::index()
        .by_endpoint_prefix(prefix)
        .expect("core service is in the bundled table")
}

fn first(body: &str, tag: &str) -> String {
    xml_values(body, tag).into_iter().next().unwrap_or_default()
}

/// Every public AWS resource type the CloudFormation registry offers.
fn registry_types(caller: &Caller) -> Result<BTreeSet<String>> {
    let types = paginate(
        caller,
        svc("cloudformation"),
        "ListTypes",
        &[
            ("Visibility", "PUBLIC"),
            ("Type", "RESOURCE"),
            ("Filters.Category", "AWS_TYPES"),
            ("MaxResults", "100"),
        ],
        "NextToken",
        "TypeName",
    )?;
    if types.is_empty() {
        return Err(ScanError::DataSource(
            "CloudFormation type registry returned no resource types".into(),
        ));
    }
    Ok(types.into_iter().collect())
}

/// Calls a query/EC2-protocol list operation until its token runs out.
fn paginate(
    caller: &Caller,
    s: &Service,
    op: &str,
    params: &[(&str, &str)],
    token: &str,
    tag: &str,
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut next = String::new();
    loop {
        let mut p = params.to_vec();
        if !next.is_empty() {
            p.push((token, &next));
        }
        let body = caller.call(s, op, "POST", "/", &p).body(op)?;
        out.extend(xml_values(&body, tag));
        next = first(&body, token);
        if next.is_empty() {
            return Ok(out);
        }
    }
}

/// `assumed-role/<name>/<session>` -> whether ReadOnlyAccess or AdministratorAccess is
/// attached to the role. Anything else, including IAM refusing to say, is `false`.
fn has_read_only(caller: &Caller, arn: &str) -> bool {
    let Some(role) = arn
        .split("assumed-role/")
        .nth(1)
        .and_then(|r| r.split('/').next())
    else {
        return false;
    };
    match caller.call(
        svc("iam"),
        "ListAttachedRolePolicies",
        "POST",
        "/",
        &[("RoleName", role)],
    ) {
        Outcome::Ok(body) => xml_values(&body, "PolicyName")
            .iter()
            .any(|p| p == "ReadOnlyAccess" || p == "AdministratorAccess"),
        _ => false,
    }
}

/// The values the region offers for one depth kind, or `None` when the probe failed.
fn depth_probe(
    caller: &Caller,
    kind: DepthKind,
    checks: &BTreeMap<String, Vec<DepthCheck>>,
) -> Option<BTreeSet<String>> {
    let ec2 = svc("ec2");
    let set = |v: Result<Vec<String>>| v.ok().map(|v| v.into_iter().collect());
    match kind {
        DepthKind::InstanceType => set(paginate(
            caller,
            ec2,
            "DescribeInstanceTypeOfferings",
            &[("LocationType", "region"), ("MaxResults", "1000")],
            "nextToken",
            "instanceType",
        )),
        DepthKind::AvailabilityZone => set(paginate(
            caller,
            ec2,
            "DescribeAvailabilityZones",
            &[],
            "nextToken",
            "zoneName",
        )),
        DepthKind::FoundationModel => bedrock(
            caller,
            "ListFoundationModels",
            "/foundation-models",
            "modelSummaries",
            "modelId",
        ),
        DepthKind::InferenceProfile => bedrock(
            caller,
            "ListInferenceProfiles",
            "/inference-profiles",
            "inferenceProfileSummaries",
            "inferenceProfileId",
        ),
        DepthKind::RdsEngineVersion => engine_versions(
            caller,
            "rds",
            "DescribeDBEngineVersions",
            "DBEngineVersion",
            "Marker",
            &depth::engines(checks, kind),
        ),
        DepthKind::CacheEngineVersion => engine_versions(
            caller,
            "elasticache",
            "DescribeCacheEngineVersions",
            "CacheEngineVersion",
            "Marker",
            &depth::engines(checks, kind),
        ),
        // Covered by the Knowledge MCP data only.
        DepthKind::CacheNodeType
        | DepthKind::NeptuneEngineVersion
        | DepthKind::DocumentDbEngineVersion
        | DepthKind::RedshiftNodeType => None,
    }
}

/// A Bedrock list call. No endpoint means no models are offered.
fn bedrock(caller: &Caller, op: &str, uri: &str, list: &str, id: &str) -> Option<BTreeSet<String>> {
    let s = svc("bedrock");
    let mut out = BTreeSet::new();
    let mut next = String::new();
    loop {
        let params: Vec<(&str, &str)> = if next.is_empty() {
            vec![]
        } else {
            vec![("nextToken", &next)]
        };
        let body = match caller.call(s, op, "GET", uri, &params) {
            Outcome::Ok(b) => b,
            Outcome::NoEndpoint => return Some(out),
            _ => return None,
        };
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        out.extend(
            v[list]
                .as_array()?
                .iter()
                .filter_map(|m| m[id].as_str().map(str::to_string)),
        );
        match v["nextToken"].as_str() {
            Some(t) if !t.is_empty() => next = t.to_string(),
            _ => return Some(out),
        }
    }
}

/// `engine version` pairs for each engine. Each listed version element is read only up
/// to its first `<EngineVersion>`, so upgrade targets nested inside are not counted.
fn engine_versions(
    caller: &Caller,
    prefix: &str,
    op: &str,
    member: &str,
    token: &str,
    engines: &BTreeSet<String>,
) -> Option<BTreeSet<String>> {
    let s = svc(prefix);
    let mut out = BTreeSet::new();
    for engine in engines {
        let mut next = String::new();
        loop {
            let mut p = vec![("Engine", engine.as_str())];
            if !next.is_empty() {
                p.push((token, &next));
            }
            let Outcome::Ok(body) = caller.call(s, op, "POST", "/", &p) else {
                return None;
            };
            for m in xml_values(&body, member) {
                if let Some(v) = xml_values(&m, "EngineVersion").first() {
                    out.insert(format!("{engine} {v}"));
                }
            }
            next = first(&body, token);
            if next.is_empty() {
                break;
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_policy_is_read_only() {
        let p: serde_json::Value =
            serde_json::from_str(include_str!("../../iam/esc-preflight-readonly.json")).unwrap();
        for st in p["Statement"].as_array().unwrap() {
            assert_eq!(st["Effect"], "Allow");
            for a in st["Action"].as_array().unwrap() {
                let a = a.as_str().unwrap();
                let verb = a.split(':').nth(1).unwrap();
                assert!(
                    ["List", "Describe", "Get"]
                        .iter()
                        .any(|v| verb.starts_with(v)),
                    "non-read action {a}"
                );
            }
        }
    }

    /// Against a real ESC account. Run with
    /// `ESC_PREFLIGHT_PROFILE=<profile> cargo test -- --ignored live_esc`.
    #[test]
    #[ignore = "network and credentials"]
    fn live_esc() {
        let profile = std::env::var("ESC_PREFLIGHT_PROFILE").unwrap();
        let caller = Caller::new(
            "eusc-de-east-1",
            "amazonaws.eu",
            Some(&profile),
            None,
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let needs = Needs {
            registry: true,
            services: [
                "EKS",
                "RDS",
                "DynamoDB",
                "CodePipeline",
                "CodeBuild",
                "QBusiness",
            ]
            .map(String::from)
            .into(),
            depth: BTreeMap::from([(
                "r".to_string(),
                vec![
                    DepthCheck {
                        kind: DepthKind::AvailabilityZone,
                        path: "p".into(),
                        value: "eusc-de-east-1a".into(),
                        offered: None,
                        source: None,
                    },
                    DepthCheck {
                        kind: DepthKind::InstanceType,
                        path: "p".into(),
                        value: "m7g.large".into(),
                        offered: None,
                        source: None,
                    },
                    DepthCheck {
                        kind: DepthKind::RdsEngineVersion,
                        path: "p".into(),
                        value: "postgres 16".into(),
                        offered: None,
                        source: None,
                    },
                    DepthCheck {
                        kind: DepthKind::FoundationModel,
                        path: "p".into(),
                        value: "amazon.titan-embed-text-v2:0".into(),
                        offered: None,
                        source: None,
                    },
                ],
            )]),
            zones: true,
        };
        let (live, prov) = run(&caller, "eusc-de-east-1", needs).unwrap();
        eprintln!("{prov:?}\n{:?}\n{:?}", live.services, live.depth);
        assert!(prov.registry_types.unwrap() > 500);
        for s in ["EKS", "RDS", "DynamoDB", "CodePipeline", "CodeBuild"] {
            assert_eq!(live.services[s], ServiceStatus::Offered, "{s}");
        }
        assert_eq!(live.services["QBusiness"], ServiceStatus::NotOffered);
        assert_eq!(live.target_zones, Some(2));
        let d = &live.depth["r"];
        assert_eq!(d[0].offered, Some(true));
        assert!(d.iter().all(|c| c.offered.is_some()), "{d:?}");
    }
}
