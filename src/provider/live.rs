//! Live mode: the target account, read-only. Each check runs only if the input needs it.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::aws_call::{Call, Caller, Outcome, xml_first, xml_values};
use crate::depth::{self, DepthCheck, DepthKind, DepthSource, Offered};
use crate::error::{Result, ScanError};
use crate::matcher::{Live, ServiceStatus};
use crate::services::{self, Service, service};

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

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct LiveProvenance {
    pub account_id: String,
    /// When the account was read.
    pub fetched_at: String,
    pub depth_probes: Vec<DepthKind>,
    /// The caller's role has ReadOnlyAccess (or AdministratorAccess) attached, so an
    /// AccessDenied from a service means the service is not offered.
    pub read_only_access: Option<bool>,
}

/// The caller's account id and ARN, from `GetCallerIdentity`: the first live call, so
/// it also tells credentials that do not work in the Region apart from other failures.
pub fn identity(caller: &Caller) -> Result<(String, String)> {
    // In an opt-in Region that is not enabled, the first call already fails.
    let body = caller
        .call(service("sts"), "GetCallerIdentity", "POST", "/", &[])
        .body("GetCallerIdentity")
        .map_err(|e| match e {
            ScanError::Auth(m) | ScanError::DataSource(m)
                if ["InvalidClientTokenId", "UnrecognizedClient", "AuthFailure"]
                    .iter()
                    .any(|c| m.contains(c)) =>
            {
                ScanError::Auth(format!(
                    "{}. If the target is an opt-in Region, check that it is enabled for the account.",
                    m.trim_end_matches('.')
                ))
            }
            e => e,
        })?;
    let account = xml_first(&body, "Account").unwrap_or_default();
    if account.is_empty() {
        return Err(ScanError::DataSource(
            "GetCallerIdentity returned no account".into(),
        ));
    }
    Ok((account, xml_first(&body, "Arn").unwrap_or_default()))
}

pub fn run(caller: &Caller, needs: Needs) -> Result<(Live, LiveProvenance)> {
    let (account_id, arn) = identity(caller)?;

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
        fetched_at: crate::report::now_utc(),
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

/// Every public AWS resource type the CloudFormation registry offers.
pub fn registry_types(caller: &Caller) -> Result<BTreeSet<String>> {
    let types = paginate(
        caller,
        service("cloudformation"),
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
        next = xml_first(&body, token).unwrap_or_default();
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
        service("iam"),
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
    let ec2 = service("ec2");
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
        DepthKind::RdsInstanceClass => orderable_classes(caller, checks),
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
        // Read from the resource schemas, not probed.
        DepthKind::Property => None,
    }
}

/// A Bedrock list call. No endpoint means no models are offered.
fn bedrock(caller: &Caller, op: &str, uri: &str, list: &str, id: &str) -> Option<BTreeSet<String>> {
    let s = service("bedrock");
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

/// The input's `engine class` values that RDS can order in the region: one call per
/// pair, filtered by engine and class.
fn orderable_classes(
    caller: &Caller,
    checks: &BTreeMap<String, Vec<DepthCheck>>,
) -> Option<BTreeSet<String>> {
    let s = service("rds");
    let wanted: BTreeSet<&str> = checks
        .values()
        .flatten()
        .filter(|c| c.kind == DepthKind::RdsInstanceClass)
        .map(|c| c.value.as_str())
        .collect();
    let mut out = BTreeSet::new();
    for v in wanted {
        let Some((engine, class)) = v.split_once(' ') else {
            continue;
        };
        let p = [
            ("Engine", engine),
            ("DBInstanceClass", class),
            ("MaxRecords", "20"),
        ];
        match caller.call(s, "DescribeOrderableDBInstanceOptions", "POST", "/", &p) {
            Outcome::Ok(body) if body.contains("<OrderableDBInstanceOption>") => {
                out.insert(v.to_string());
            }
            Outcome::Ok(_) | Outcome::NoEndpoint => {}
            _ => return None,
        }
    }
    Some(out)
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
    let s = service(prefix);
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
            next = xml_first(&body, token).unwrap_or_default();
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
        let (live, _) = run(&caller, needs).unwrap();
        assert!(live.registry.as_ref().unwrap().len() > 500);
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
