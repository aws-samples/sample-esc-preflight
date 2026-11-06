//! Depth checks: property values that exist only in some regions, such as
//! instance types, Availability Zones, Bedrock models and engine versions.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use crate::model::Template;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DepthKind {
    InstanceType,
    AvailabilityZone,
    FoundationModel,
    InferenceProfile,
    RdsEngineVersion,
    CacheEngineVersion,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DepthCheck {
    pub kind: DepthKind,
    pub path: String,
    /// The value as written, `engine version` for engine checks.
    pub value: String,
    /// `None` until a live probe answered, or when it could not.
    pub offered: Option<bool>,
}

/// What the target region offers, per kind. A missing kind was not probed.
pub type Offered = BTreeMap<DepthKind, BTreeSet<String>>;

use DepthKind::*;

/// `(resource type, property path, kind)`. `[]` marks a list of values.
const SINGLE: &[(&str, &str, DepthKind)] = &[
    ("AWS::EC2::Instance", "InstanceType", InstanceType),
    (
        "AWS::EC2::LaunchTemplate",
        "LaunchTemplateData.InstanceType",
        InstanceType,
    ),
    (
        "AWS::AutoScaling::LaunchConfiguration",
        "InstanceType",
        InstanceType,
    ),
    ("AWS::EKS::Nodegroup", "InstanceTypes[]", InstanceType),
    ("AWS::EC2::Subnet", "AvailabilityZone", AvailabilityZone),
    ("AWS::EC2::Instance", "AvailabilityZone", AvailabilityZone),
    ("aws_instance", "instance_type", InstanceType),
    ("aws_launch_template", "instance_type", InstanceType),
    ("aws_eks_node_group", "instance_types[]", InstanceType),
    ("aws_subnet", "availability_zone", AvailabilityZone),
    ("aws_instance", "availability_zone", AvailabilityZone),
];

/// `(resource type, engine property, version property, kind)`.
const ENGINES: &[(&str, &str, &str, DepthKind)] = &[
    (
        "AWS::RDS::DBInstance",
        "Engine",
        "EngineVersion",
        RdsEngineVersion,
    ),
    (
        "AWS::RDS::DBCluster",
        "Engine",
        "EngineVersion",
        RdsEngineVersion,
    ),
    (
        "aws_db_instance",
        "engine",
        "engine_version",
        RdsEngineVersion,
    ),
    (
        "aws_rds_cluster",
        "engine",
        "engine_version",
        RdsEngineVersion,
    ),
    (
        "AWS::ElastiCache::CacheCluster",
        "Engine",
        "EngineVersion",
        CacheEngineVersion,
    ),
    (
        "AWS::ElastiCache::ReplicationGroup",
        "Engine",
        "EngineVersion",
        CacheEngineVersion,
    ),
    (
        "aws_elasticache_cluster",
        "engine",
        "engine_version",
        CacheEngineVersion,
    ),
    (
        "aws_elasticache_replication_group",
        "engine",
        "engine_version",
        CacheEngineVersion,
    ),
];

/// Every literal value worth checking, keyed by logical id. AZ names are checked only
/// when they belong to the target region; foreign ones are partition hazards already.
pub fn checks(template: &Template, target_region: &str) -> BTreeMap<String, Vec<DepthCheck>> {
    let mut out: BTreeMap<String, Vec<DepthCheck>> = BTreeMap::new();
    for r in template.resources.values() {
        let mut found = Vec::new();
        let p = &r.properties;
        for (_, path, kind) in SINGLE.iter().filter(|(t, ..)| *t == r.resource_type) {
            let (key, list) = match path.strip_suffix("[]") {
                Some(k) => (k, true),
                None => (*path, false),
            };
            let v = key.split('.').fold(p, |v, k| &v[k]);
            let values: Vec<&str> = if list {
                v.as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect()
            } else {
                v.as_str().into_iter().collect()
            };
            for value in values {
                if *kind != AvailabilityZone || value.starts_with(target_region) {
                    found.push(check(*kind, path, value));
                }
            }
        }
        for (_, e, v, kind) in ENGINES.iter().filter(|(t, ..)| *t == r.resource_type) {
            if let (Some(engine), Some(version)) = (p[*e].as_str(), p[*v].as_str()) {
                found.push(check(*kind, v, &format!("{engine} {version}")));
            }
        }
        model_arns(p, "", &mut found);
        if !found.is_empty() {
            found.sort();
            found.dedup();
            out.insert(r.logical_id.clone(), found);
        }
    }
    out
}

fn check(kind: DepthKind, path: &str, value: &str) -> DepthCheck {
    DepthCheck {
        kind,
        path: path.into(),
        value: value.into(),
        offered: None,
    }
}

/// Bedrock model and inference-profile ids inside any string, including JSON-encoded
/// IAM policies. Wildcards are not checkable and are skipped.
fn model_arns(v: &Value, path: &str, out: &mut Vec<DepthCheck>) {
    match v {
        Value::String(s) => {
            for (marker, kind) in [
                ("foundation-model/", FoundationModel),
                ("inference-profile/", InferenceProfile),
            ] {
                for (i, _) in s.match_indices(marker) {
                    let id: String = s[i + marker.len()..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || "-.:_".contains(*c))
                        .collect();
                    let next = s[i + marker.len() + id.len()..].chars().next();
                    if !id.is_empty() && next != Some('*') {
                        out.push(check(kind, path, &id));
                    }
                }
            }
        }
        Value::Array(a) => a
            .iter()
            .enumerate()
            .for_each(|(i, x)| model_arns(x, &format!("{path}[{i}]"), out)),
        Value::Object(m) => m.iter().for_each(|(k, x)| {
            let p = if path.is_empty() {
                k.clone()
            } else {
                format!("{path}.{k}")
            };
            model_arns(x, &p, out)
        }),
        _ => {}
    }
}

/// Fills `offered` from what the probes returned.
pub fn resolve(checks: &mut BTreeMap<String, Vec<DepthCheck>>, offered: &Offered) {
    for c in checks.values_mut().flatten() {
        c.offered = offered.get(&c.kind).map(|set| match c.kind {
            // `16` or `8.0` names a version family; any offered member satisfies it.
            RdsEngineVersion | CacheEngineVersion => set
                .iter()
                .any(|o| *o == c.value || o.starts_with(&format!("{}.", c.value))),
            _ => set.contains(&c.value),
        });
    }
}

/// Engines whose versions must be probed, per kind.
pub fn engines(checks: &BTreeMap<String, Vec<DepthCheck>>, kind: DepthKind) -> BTreeSet<String> {
    checks
        .values()
        .flatten()
        .filter(|c| c.kind == kind)
        .filter_map(|c| c.value.split_once(' ').map(|(e, _)| e.to_string()))
        .collect()
}

pub fn kinds(checks: &BTreeMap<String, Vec<DepthCheck>>) -> BTreeSet<DepthKind> {
    checks.values().flatten().map(|c| c.kind).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_checks() -> BTreeMap<String, Vec<DepthCheck>> {
        let t = crate::reader::parse(include_str!("../tests/fixtures/tf-plan.json")).unwrap();
        checks(&t, "eusc-de-east-1")
    }

    #[test]
    fn extracts_values_from_a_plan() {
        let c = plan_checks();
        let v = |id: &str| -> Vec<(DepthKind, String)> {
            c[id].iter().map(|x| (x.kind, x.value.clone())).collect()
        };
        assert_eq!(
            v("aws_instance.this"),
            [(InstanceType, "g6.xlarge".to_string())]
        );
        assert_eq!(
            v("aws_db_instance.this"),
            [(RdsEngineVersion, "postgres 16.4".to_string())]
        );
        assert_eq!(
            v("aws_iam_policy.bedrock"),
            [(FoundationModel, "amazon.titan-embed-text-v2:0".to_string())]
        );
        assert_eq!(
            v("module.net.aws_subnet.private[2]"),
            [(AvailabilityZone, "eusc-de-east-1c".to_string())]
        );
    }

    #[test]
    fn resolves_against_offered_values() {
        let mut c = plan_checks();
        let mut offered = Offered::new();
        offered.insert(
            AvailabilityZone,
            ["eusc-de-east-1a", "eusc-de-east-1b"]
                .map(String::from)
                .into(),
        );
        offered.insert(RdsEngineVersion, ["postgres 16.4".to_string()].into());
        resolve(&mut c, &offered);
        assert_eq!(c["module.net.aws_subnet.private[0]"][0].offered, Some(true));
        assert_eq!(
            c["module.net.aws_subnet.private[2]"][0].offered,
            Some(false)
        );
        assert_eq!(c["aws_db_instance.this"][0].offered, Some(true));
        assert_eq!(c["aws_instance.this"][0].offered, None);
    }

    #[test]
    fn version_family_matches_minor_versions() {
        let mut c = BTreeMap::from([(
            "r".to_string(),
            vec![check(RdsEngineVersion, "v", "postgres 16")],
        )]);
        let mut offered = Offered::new();
        offered.insert(
            RdsEngineVersion,
            ["postgres 16.4".to_string(), "postgres 160.1".to_string()].into(),
        );
        resolve(&mut c, &offered);
        assert_eq!(c["r"][0].offered, Some(true));
    }

    #[test]
    fn wildcard_model_arns_are_skipped() {
        let mut out = Vec::new();
        model_arns(
            &Value::String("arn:aws-eusc:bedrock:*::foundation-model/*".into()),
            "p",
            &mut out,
        );
        assert!(out.is_empty());
    }
}
