//! Depth checks: property values that exist only in some regions, such as
//! instance types, Availability Zones, Bedrock models and engine versions. Public mode
//! resolves them from the Knowledge MCP config values; live mode overrides what it probes.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use crate::model::Template;
use crate::provider::knowledge::Knowledge;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DepthKind {
    InstanceType,
    AvailabilityZone,
    FoundationModel,
    InferenceProfile,
    RdsEngineVersion,
    CacheEngineVersion,
    CacheNodeType,
    NeptuneEngineVersion,
    DocumentDbEngineVersion,
    RedshiftNodeType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DepthSource {
    Knowledge,
    Live,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DepthCheck {
    pub kind: DepthKind,
    pub path: String,
    /// The value as written, `engine version` for engine checks.
    pub value: String,
    /// `None` until a source answered, or when none could.
    pub offered: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<DepthSource>,
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
    (
        "AWS::ElastiCache::CacheCluster",
        "CacheNodeType",
        CacheNodeType,
    ),
    (
        "AWS::ElastiCache::ReplicationGroup",
        "CacheNodeType",
        CacheNodeType,
    ),
    ("aws_elasticache_cluster", "node_type", CacheNodeType),
    (
        "aws_elasticache_replication_group",
        "node_type",
        CacheNodeType,
    ),
    ("AWS::Redshift::Cluster", "NodeType", RedshiftNodeType),
    ("aws_redshift_cluster", "node_type", RedshiftNodeType),
];

/// `(resource type, version property, engine, kind)` for services with one engine.
const FIXED_ENGINES: &[(&str, &str, &str, DepthKind)] = &[
    (
        "AWS::Neptune::DBCluster",
        "EngineVersion",
        "neptune",
        NeptuneEngineVersion,
    ),
    (
        "aws_neptune_cluster",
        "engine_version",
        "neptune",
        NeptuneEngineVersion,
    ),
    (
        "AWS::DocDB::DBCluster",
        "EngineVersion",
        "docdb",
        DocumentDbEngineVersion,
    ),
    (
        "aws_docdb_cluster",
        "engine_version",
        "docdb",
        DocumentDbEngineVersion,
    ),
];

/// The Knowledge MCP config parent of each kind it covers. Engine values are keyed
/// `<engine>-<version>` there.
const CONFIG: &[(DepthKind, &str)] = &[
    (InstanceType, "AWS::EC2::Instance::InstanceType"),
    (RdsEngineVersion, "AWS::RDS::DBInstance::EngineVersion"),
    (
        CacheEngineVersion,
        "AWS::ElastiCache::CacheCluster::EngineVersion",
    ),
    (
        CacheNodeType,
        "AWS::ElastiCache::CacheCluster::CacheNodeType",
    ),
    (
        NeptuneEngineVersion,
        "AWS::Neptune::DBCluster::EngineVersion",
    ),
    (
        DocumentDbEngineVersion,
        "AWS::DocDB::DBCluster::EngineVersion",
    ),
    (RedshiftNodeType, "AWS::Redshift::Cluster::NodeType"),
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
                // Engine names are case-insensitive in the APIs and lowercase in the data.
                let engine = engine.to_ascii_lowercase();
                found.push(check(*kind, v, &format!("{engine} {version}")));
            }
        }
        for (_, v, engine, kind) in FIXED_ENGINES.iter().filter(|(t, ..)| *t == r.resource_type) {
            if let Some(version) = p[*v].as_str() {
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
        source: None,
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

/// The checks contain a kind the Knowledge MCP config values cover.
pub fn needs_config(checks: &BTreeMap<String, Vec<DepthCheck>>) -> bool {
    checks
        .values()
        .flatten()
        .any(|c| CONFIG.iter().any(|(k, _)| *k == c.kind))
}

/// What the Knowledge MCP config values offer, in the shape the checks use.
pub fn public_offered(k: &Knowledge) -> Offered {
    let mut out = Offered::new();
    for (kind, parent) in CONFIG {
        let Some(values) = k.config.get(*parent) else {
            continue;
        };
        let engine = matches!(
            kind,
            RdsEngineVersion | CacheEngineVersion | NeptuneEngineVersion | DocumentDbEngineVersion
        );
        let set = values
            .iter()
            .filter_map(|v| {
                if !engine {
                    return Some(v.clone());
                }
                // `aurora-mysql-8.0.mysql_aurora.3.08.0`: the version starts at the first
                // `-` followed by a digit.
                let i = v
                    .char_indices()
                    .find(|&(i, c)| {
                        c == '-' && v[i + 1..].starts_with(|d: char| d.is_ascii_digit())
                    })?
                    .0;
                Some(format!("{} {}", &v[..i], &v[i + 1..]))
            })
            .collect();
        out.insert(*kind, set);
    }
    out
}

/// Fills `offered` for the kinds a source answered; other kinds keep their answer.
pub fn resolve(
    checks: &mut BTreeMap<String, Vec<DepthCheck>>,
    offered: &Offered,
    source: DepthSource,
) {
    for c in checks.values_mut().flatten() {
        let Some(set) = offered.get(&c.kind) else {
            continue;
        };
        c.offered = Some(match c.kind {
            // `16` or `8.0` names a version family; any offered member satisfies it.
            RdsEngineVersion
            | CacheEngineVersion
            | NeptuneEngineVersion
            | DocumentDbEngineVersion => set
                .iter()
                .any(|o| *o == c.value || o.starts_with(&format!("{}.", c.value))),
            _ => set.contains(&c.value),
        });
        c.source = Some(source);
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
        let t = crate::reader::parse_text(include_str!("../tests/fixtures/tf-plan.json")).unwrap();
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
        resolve(&mut c, &offered, DepthSource::Live);
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
        resolve(&mut c, &offered, DepthSource::Live);
        assert_eq!(c["r"][0].offered, Some(true));
    }

    #[test]
    fn public_values_come_from_knowledge_config_keys() {
        let o = public_offered(&crate::provider::knowledge::tests::fixture());
        assert!(o[&InstanceType].contains("m7i.large"));
        assert!(
            o[&RdsEngineVersion]
                .iter()
                .any(|v| v.starts_with("aurora-mysql 8.0"))
        );
        assert!(
            o[&RdsEngineVersion]
                .iter()
                .any(|v| v.starts_with("postgres 16"))
        );
        assert!(o[&CacheEngineVersion].contains("valkey 7.2"));
        assert!(
            o[&NeptuneEngineVersion]
                .iter()
                .all(|v| v.starts_with("neptune 1."))
        );
        assert!(!o.contains_key(&AvailabilityZone));
        let mut c = plan_checks();
        resolve(&mut c, &o, DepthSource::Knowledge);
        let db = &c["aws_db_instance.this"][0];
        assert_eq!(db.source, Some(DepthSource::Knowledge));
        assert!(db.offered.is_some());
        // Zones are left to live mode.
        assert_eq!(c["module.net.aws_subnet.private[0]"][0].offered, None);
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
