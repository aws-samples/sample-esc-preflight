//! Walks template properties and flags hardcoded Region, zone, partition, DNS suffix
//! and account literals, for every Region including the target.
//!
//! Only literal strings are inspected. Values built from `AWS::Partition`, `AWS::Region`
//! or `AWS::URLSuffix` contain no literal, so they pass naturally. Values that CDK
//! synthesis or a Terraform plan wrote for its own environment are counted separately:
//! producing the input for the target removes them all at once.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{DeployEnv, OUTPUT_TYPE, Origin, Template};
use serde::Serialize;
use serde_json::Value;

/// Partition facts from the bundled botocore `partitions.json`, never hardcoded.
#[derive(Debug, Clone)]
pub struct PartitionFacts {
    pub target_region: String,
    /// Partition id of the target region, e.g. `aws-eusc`.
    pub target_partition: String,
    /// DNS suffix of the target partition, e.g. `amazonaws.eu`.
    pub target_dns_suffix: String,
    /// Every partition id.
    pub partitions: Vec<String>,
    /// Every partition DNS suffix, with the partitions that use it.
    pub dns_suffixes: BTreeMap<String, BTreeSet<String>>,
    /// The dual-stack ones among them, such as `api.aws`.
    pub dual_stack: BTreeSet<String>,
    /// Every Region id, with its partition.
    pub region_partition: BTreeMap<String, String>,
    /// Regions in the target partition. With one, no cross-Region feature can exist.
    pub target_regions: usize,
    /// The account the input moves to, when the move is to another account.
    pub target_account: Option<String>,
    /// The partition the input was produced for, when its environments name Regions of
    /// one partition.
    pub source_partition: Option<String>,
}

impl PartitionFacts {
    /// The target partition uses this DNS suffix.
    pub fn is_target_suffix(&self, suffix: &str) -> bool {
        self.dns_suffixes
            .get(suffix)
            .is_some_and(|ps| ps.contains(&self.target_partition))
    }
}

/// The partition the input's environments are in, when they name Regions of exactly one.
pub fn source_partition(template: &Template, facts: &PartitionFacts) -> Option<String> {
    let found: BTreeSet<&String> = template
        .envs()
        .into_iter()
        .filter_map(|e| e.region)
        .filter_map(|r| facts.region_partition.get(&r))
        .collect();
    match found.len() {
        1 => found.into_iter().next().cloned(),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HazardKind {
    /// `arn:<partition>:` in a literal.
    ArnPartition,
    /// An endpoint host with a partition DNS suffix.
    DnsSuffix,
    /// An endpoint host with a partition's dual-stack DNS suffix, such as `api.aws`.
    DualStackSuffix,
    /// A service principal with another partition's suffix, e.g. `lambda.amazonaws.com.cn`.
    ServicePrincipal,
    /// A Region id.
    RegionLiteral,
    /// An Availability Zone name or id.
    AvailabilityZone,
    /// A 12-digit account id: in an ARN, an AWS principal, an account condition key such
    /// as `aws:SourceAccount`, or an ECR registry host.
    AccountId,
    /// The id of a resource that exists in one Region and account, such as `ami-` or
    /// `subnet-`.
    ResourceId,
    /// A form that works only in some Regions, from a literal rule (`rule`).
    LegacyEndpoint,
}

/// What a hardcoded literal does when the input is deployed to the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Impact {
    /// It refers to another Region or partition, so the deployment fails or misbehaves.
    Breaks,
    /// It is right for the target, but ties the input to it.
    Portability,
}

/// One place to fix: a property value with every hazardous literal found in it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct Hazard {
    pub logical_id: String,
    pub path: String,
    pub literals: Vec<Literal>,
    /// The environment the resource was produced for, when the input states it.
    #[serde(skip)]
    pub env: Option<DeployEnv>,
    /// The whole string the literals were found in.
    #[serde(skip)]
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
pub struct Literal {
    pub kind: HazardKind,
    pub value: String,
    pub impact: Impact,
    /// The literal rule that found it.
    pub rule: Option<String>,
}

/// Values written for the environment the input was produced for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct EnvLiterals {
    pub env: DeployEnv,
    /// Number of property values that contain at least one such literal.
    pub places: usize,
    /// Distinct zones of the environment the input uses.
    pub zones: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scan {
    pub hazards: Vec<Hazard>,
    pub env_literals: Vec<EnvLiterals>,
}

/// Returns all hazards in the template, sorted for deterministic output.
pub fn hazards(template: &Template, facts: &PartitionFacts) -> Scan {
    let mut out = Vec::new();
    let mut env_places: BTreeMap<DeployEnv, (usize, BTreeSet<String>)> = BTreeMap::new();
    // An input produced for the target itself has nothing to re-produce.
    let known = |e: &DeployEnv| {
        e.region
            .as_ref()
            .is_none_or(|r| *r != facts.target_region && facts.region_partition.contains_key(r))
    };
    // Environments in the target still match, so their values are not hazards, but
    // they are not reported as environment literals.
    let all_envs = template.envs();
    for r in template.resources.values().chain(template.outputs.values()) {
        let mut props = r.properties.clone();
        let root = if r.resource_type == OUTPUT_TYPE {
            "Value"
        } else if r.origin == Origin::Cfn {
            "Properties"
        } else {
            // The provider writes its region into every resource; that is the plan
            // region, reported once in provenance, not a hardcoded literal.
            if let Some(m) = props.as_object_mut() {
                m.remove("region");
            }
            "values"
        };
        // The resource's own environment first, then the input's other environments:
        // a CDK pipeline or a multi-region plan writes in the environments it deploys to.
        let envs: Vec<&DeployEnv> = r
            .env
            .iter()
            .chain(all_envs.iter().filter(|e| Some(*e) != r.env.as_ref()))
            .collect();
        walk(&props, root, &mut |path, s| {
            let mut found = scan_literal(s, facts);
            if is_account_position(path) && is_account_id(s) {
                found.push((HazardKind::AccountId, s.to_string()));
            }
            // An account next to another partition's ARN prefix belongs to that partition.
            let foreign_arn = found.iter().any(|(kind, lit)| {
                *kind == HazardKind::ArnPartition
                    && impact(*kind, lit, false, facts) == Impact::Breaks
            });
            let mut hits: BTreeMap<&DeployEnv, Vec<String>> = BTreeMap::new();
            let hand_written = |lit: &str| {
                template
                    .constants
                    .iter()
                    // A constant that is only the literal, such as a Region tag, proves
                    // nothing about other values that contain it.
                    .any(|c| {
                        c.contains(lit) && (c.contains(s) || (c != lit && s.contains(c.as_str())))
                    })
            };
            found.retain(|(kind, lit)| {
                // A Region the property requires, such as us-east-1 for a CloudFront
                // certificate, is no hazard there.
                if *kind == HazardKind::RegionLiteral
                    && crate::rules::exempt(&r.resource_type, path, lit, facts)
                {
                    return false;
                }
                // A plan resolves references and lookups to ids; only typed ones count.
                if *kind == HazardKind::ResourceId && r.origin != Origin::Cfn && !hand_written(lit)
                {
                    return false;
                }
                let env = envs.iter().find(|env| {
                    // A plan resolves `data.aws_partition` to a literal, so in a Terraform
                    // plan the planning partition's ARNs and hosts are indistinguishable
                    // from hardcoded ones. CDK keeps them as `AWS::Partition` tokens.
                    let partition = (r.origin != Origin::Cfn)
                        .then(|| {
                            env.region
                                .as_ref()
                                .and_then(|r| facts.region_partition.get(r))
                        })
                        .flatten();
                    from_env(*kind, lit, env, partition, facts)
                });
                match env {
                    Some(env) if !hand_written(lit) && !known(env) => false,
                    Some(env) if !hand_written(lit) => {
                        let zones = hits.entry(env).or_default();
                        if *kind == HazardKind::AvailabilityZone {
                            zones.push(lit.clone());
                        }
                        false
                    }
                    _ => true,
                }
            });
            // A value counts once, for the first environment it matches; a value naming
            // only an account belongs to the first environment with that account.
            let first = envs.iter().find(|e| hits.contains_key(*e)).or_else(|| {
                envs.iter().filter(|e| known(e)).find(|e| {
                    e.account
                        .as_deref()
                        .is_some_and(|a| !occurrences(s, a).is_empty())
                })
            });
            if let Some(env) = first {
                env_places.entry((*env).clone()).or_default().0 += 1;
            }
            for (env, zones) in hits {
                env_places.entry(env.clone()).or_default().1.extend(zones);
            }
            if found.is_empty() {
                return;
            }
            let mut literals: Vec<Literal> = found
                .into_iter()
                .map(|(kind, value)| literal(kind, value, s, foreign_arn, facts))
                .collect();
            literals.sort();
            literals.dedup();
            out.push(Hazard {
                logical_id: r.logical_id.clone(),
                path: path.to_string(),
                literals,
                env: r.env.clone(),
                value: s.to_string(),
            });
        });
    }
    out.sort();
    out.dedup();
    Scan {
        hazards: out,
        env_literals: env_places
            .into_iter()
            .map(|(env, (places, zones))| EnvLiterals {
                env,
                places,
                zones: zones.into_iter().collect(),
            })
            .collect(),
    }
}

/// A literal found in `s`. A literal rule's match names its rule and Region within `s`.
fn literal(
    kind: HazardKind,
    value: String,
    s: &str,
    foreign_arn: bool,
    facts: &PartitionFacts,
) -> Literal {
    let by_rule = (kind == HazardKind::LegacyEndpoint)
        .then(|| {
            crate::rules::literals(s, facts)
                .into_iter()
                .find(|(_, lit, ..)| *lit == value)
        })
        .flatten();
    Literal {
        impact: match by_rule {
            Some((_, _, region, _)) if region == facts.target_region => Impact::Portability,
            Some(_) => Impact::Breaks,
            None => impact(kind, &value, foreign_arn, facts),
        },
        rule: by_rule.map(|(r, ..)| r.id.clone()),
        kind,
        value,
    }
}

fn from_env(
    kind: HazardKind,
    lit: &str,
    env: &DeployEnv,
    partition: Option<&String>,
    facts: &PartitionFacts,
) -> bool {
    match kind {
        HazardKind::RegionLiteral => env.region.as_deref() == Some(lit),
        HazardKind::AvailabilityZone => env.region.as_deref().is_some_and(|r| zone_of(lit, r)),
        HazardKind::AccountId => env.account.as_deref() == Some(lit),
        HazardKind::ResourceId | HazardKind::LegacyEndpoint => false,
        HazardKind::ArnPartition => partition.is_some_and(|p| lit == format!("arn:{p}:")),
        HazardKind::DnsSuffix | HazardKind::DualStackSuffix | HazardKind::ServicePrincipal => {
            partition
                .and_then(|p| facts.dns_suffixes.get(lit).map(|ps| ps.contains(p)))
                .unwrap_or(false)
        }
    }
}

fn impact(kind: HazardKind, lit: &str, foreign_arn: bool, facts: &PartitionFacts) -> Impact {
    let breaks = match kind {
        HazardKind::ArnPartition => {
            lit.strip_prefix("arn:").and_then(|p| p.strip_suffix(':'))
                != Some(&facts.target_partition)
        }
        HazardKind::DnsSuffix | HazardKind::DualStackSuffix => !facts.is_target_suffix(lit),
        HazardKind::ServicePrincipal | HazardKind::ResourceId | HazardKind::LegacyEndpoint => true,
        HazardKind::RegionLiteral => lit != facts.target_region,
        // A zone id does not name its Region.
        HazardKind::AvailabilityZone => !zone_of(lit, &facts.target_region),
        HazardKind::AccountId => {
            foreign_arn || facts.target_account.as_deref().is_some_and(|a| a != lit)
        }
    };
    if breaks {
        Impact::Breaks
    } else {
        Impact::Portability
    }
}

/// `lit` is a zone name of `region`: the Region and one zone letter.
fn zone_of(lit: &str, region: &str) -> bool {
    lit.strip_prefix(region)
        .is_some_and(|z| z.len() == 1 && z.chars().all(|c| c.is_ascii_lowercase()))
}

pub fn is_account_id(s: &str) -> bool {
    s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit())
}

fn walk(v: &Value, path: &str, f: &mut dyn FnMut(&str, &str)) {
    match v {
        // Terraform keeps policies as JSON strings; walk them as structure so a service
        // principal is still seen as a whole literal.
        Value::String(s) if s.starts_with(['{', '[']) => match serde_json::from_str(s) {
            Ok(inner @ (Value::Object(_) | Value::Array(_))) => walk(&inner, path, f),
            _ => f(path, s),
        },
        Value::String(s) => f(path, s),
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                walk(x, &format!("{path}[{i}]"), f);
            }
        }
        Value::Object(m) => {
            for (k, x) in m {
                walk(x, &format!("{path}.{k}"), f);
            }
        }
        _ => {}
    }
}

/// `s` has a breaking Region or zone hazard (a Region or zone of another Region, or a
/// zone id), so that hazard's fix changes `s`.
pub fn names_other_region(s: &str, facts: &PartitionFacts) -> bool {
    scan_literal(s, facts).iter().any(|(kind, lit)| {
        matches!(
            kind,
            HazardKind::RegionLiteral | HazardKind::AvailabilityZone
        ) && impact(*kind, lit, false, facts) == Impact::Breaks
    })
}

fn scan_literal(s: &str, facts: &PartitionFacts) -> Vec<(HazardKind, String)> {
    let mut found = Vec::new();
    for p in &facts.partitions {
        let needle = format!("arn:{p}:");
        if s.contains(&needle) {
            found.push((HazardKind::ArnPartition, needle));
        }
    }
    match principal_suffix(s, facts) {
        // `<service>.amazonaws.com` is the documented service principal, also regional.
        Some((SERVICE_PRINCIPAL_SUFFIX, _)) => {}
        Some((suffix, false)) if facts.is_target_suffix(suffix) => {}
        Some((suffix, false)) => found.push((HazardKind::ServicePrincipal, suffix.to_string())),
        // A bare host with a Region label, such as an SQS endpoint.
        Some((suffix, true)) => found.push((suffix_kind(suffix, facts), suffix.to_string())),
        None => {
            for suffix in facts.dns_suffixes.keys() {
                if contains_suffix(s, suffix) {
                    found.push((suffix_kind(suffix, facts), suffix.clone()));
                }
            }
        }
    }
    // A literal rule's match replaces its Region too, so the Region is not reported twice.
    let rule_spans: Vec<std::ops::Range<usize>> = crate::rules::literals(s, facts)
        .into_iter()
        .map(|(_, lit, _, span)| {
            found.push((HazardKind::LegacyEndpoint, lit.to_string()));
            span
        })
        .collect();
    for region in facts.region_partition.keys() {
        for (start, end) in occurrences(s, region) {
            if rule_spans.iter().any(|r| r.start <= start && end <= r.end) {
                continue;
            }
            let next = s[end..].chars().next();
            match next {
                Some(c)
                    if c.is_ascii_lowercase()
                        && !s[end + 1..].starts_with(|c: char| c.is_ascii_alphanumeric()) =>
                {
                    found.push((HazardKind::AvailabilityZone, s[start..end + 1].to_string()));
                }
                Some(c) if c.is_ascii_alphanumeric() || c == '-' => {}
                _ => found.push((HazardKind::RegionLiteral, region.clone())),
            }
        }
    }
    for token in s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
        if is_az_id(token) {
            found.push((HazardKind::AvailabilityZone, token.to_string()));
        }
        if is_resource_id(token) {
            found.push((HazardKind::ResourceId, token.to_string()));
        }
    }
    // The account of an ECR registry host, `<account>.dkr.ecr.<region>.<suffix>`.
    for (i, _) in s.match_indices(".dkr.ecr") {
        let account = s[..i]
            .rsplit(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap_or("");
        if is_account_id(account) {
            found.push((HazardKind::AccountId, account.to_string()));
        }
    }
    // The account field of an ARN, also inside an `Fn::Join` piece such as
    // `:secretsmanager:us-east-1:111122223333:secret:x`.
    if s.contains(':') {
        for piece in s.split(':') {
            if is_account_id(piece) {
                found.push((HazardKind::AccountId, piece.to_string()));
            }
        }
    }
    found
}

/// A position that holds a bare account ID: an AWS principal, a condition key that
/// compares accounts (case-insensitive, as IAM reads them), or the principal and
/// source account of a Lambda permission.
fn is_account_position(path: &str) -> bool {
    let bare = path.trim_end_matches(|c: char| c == ']' || c.is_ascii_digit());
    let bare = bare.strip_suffix('[').unwrap_or(bare).to_ascii_lowercase();
    [
        "principal.aws",
        "principal",
        "sourceaccount",
        "source_account",
        "aws:sourceaccount",
        "aws:sourceowner",
        "aws:principalaccount",
        "aws:resourceaccount",
        "kms:calleraccount",
    ]
    .iter()
    .any(|k| bare.ends_with(&format!(".{k}")))
}

fn suffix_kind(suffix: &str, facts: &PartitionFacts) -> HazardKind {
    if facts.dual_stack.contains(suffix) {
        HazardKind::DualStackSuffix
    } else {
        HazardKind::DnsSuffix
    }
}

/// The suffix of service principals in every partition but some `aws-cn` ones, which
/// end in `amazonaws.com.cn`.
const SERVICE_PRINCIPAL_SUFFIX: &str = "amazonaws.com";

/// For a whole literal of the form `<svc>.<partition-suffix>`, as used in IAM trust
/// policies, with a leading wildcard in `iam:AWSServiceName` conditions, and in
/// service-linked role paths: the suffix, and whether a label is a Region id.
fn principal_suffix<'a>(s: &str, facts: &'a PartitionFacts) -> Option<(&'a str, bool)> {
    let s = s.strip_prefix('*').unwrap_or(s);
    let s = s
        .split_once("aws-service-role/")
        .map_or(s, |(_, rest)| rest.split('/').next().unwrap_or(rest));
    facts.dns_suffixes.keys().find_map(|suffix| {
        let svc = s.strip_suffix(suffix.as_str())?.strip_suffix('.')?;
        let shaped = !svc.is_empty()
            && svc
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.');
        shaped.then(|| {
            let regional = svc
                .split('.')
                .any(|l| facts.region_partition.contains_key(l));
            (suffix.as_str(), regional)
        })
    })
}

/// True when `suffix` appears as a DNS suffix (not followed by a further label character).
fn contains_suffix(s: &str, suffix: &str) -> bool {
    occurrences(s, suffix).into_iter().any(|(start, end)| {
        let before_ok = start > 0 && s.as_bytes()[start - 1] == b'.';
        let after_ok = s[end..].chars().next().is_none_or(|c| {
            !(c.is_ascii_alphanumeric()
                || c == '.' && s[end + 1..].starts_with(|c: char| c.is_ascii_alphabetic()))
        });
        before_ok && after_ok
    })
}

/// Non-overlapping occurrences of `needle` that start at a token boundary.
fn occurrences(s: &str, needle: &str) -> Vec<(usize, usize)> {
    s.match_indices(needle)
        .filter(|(i, _)| *i == 0 || !s.as_bytes()[i - 1].is_ascii_alphanumeric())
        .map(|(i, m)| (i, i + m.len()))
        .collect()
}

/// Prefixes of resource ids that name one resource in one Region and account.
const RESOURCE_ID_PREFIXES: &[&str] = &[
    "ami", "snap", "vol", "vpc", "subnet", "sg", "igw", "eipalloc", "rtb", "nat", "eni", "vpce",
    "tgw", "pl", "lt", "acl", "dopt", "cgw", "vgw",
];

/// A resource id such as `ami-0abcdef1234567890`: a known prefix and 8 or 17 hex digits.
fn is_resource_id(t: &str) -> bool {
    t.split_once('-').is_some_and(|(p, hex)| {
        RESOURCE_ID_PREFIXES.contains(&p)
            && matches!(hex.len(), 8 | 17)
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// AZ id shape such as `euc1-az1` or `use1-az6`.
fn is_az_id(t: &str) -> bool {
    let Some((head, tail)) = t.split_once("-az") else {
        return false;
    };
    let letters = head.trim_end_matches(|c: char| c.is_ascii_digit());
    !tail.is_empty()
        && tail.chars().all(|c| c.is_ascii_digit())
        && head.len() > letters.len()
        && (2..=4).contains(&letters.len())
        && letters.chars().all(|c| c.is_ascii_lowercase())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::reader;

    pub fn facts() -> PartitionFacts {
        crate::provider::partition::facts("eusc-de-east-1").unwrap()
    }

    fn kinds(json: &str) -> Vec<(HazardKind, String)> {
        lits(json, &facts())
            .into_iter()
            .map(|(k, v, _)| (k, v))
            .collect()
    }

    /// The CDK container asset host of the stack's own environment is an environment
    /// literal, re-synthesized for the target, not a hazard.
    #[test]
    fn a_cdk_asset_host_of_the_environment_is_an_environment_literal() {
        let mut t = reader::parse_text(
            r#"{"Resources":{"T":{"Type":"AWS::ECS::TaskDefinition","Properties":{"Image":
            "444455556666.dkr.ecr.eu-central-1.amazonaws.com/cdk-hnb659fds-container-assets-444455556666-eu-central-1:abc"}}}}"#,
        )
        .unwrap();
        t.resources.get_mut("T").unwrap().env = Some(DeployEnv {
            region: Some("eu-central-1".into()),
            account: Some("444455556666".into()),
        });
        let mut f = crate::provider::partition::facts("eu-west-1").unwrap();
        f.target_account = Some("111122223333".into());
        let scan = hazards(&t, &f);
        let left: Vec<_> = scan.hazards.iter().flat_map(|h| &h.literals).collect();
        assert!(
            left.iter().all(|l| l.kind != HazardKind::AccountId),
            "the environment's account, though another is the target: {left:?}"
        );
        assert_eq!(scan.env_literals.len(), 1);
    }

    /// CDK writes the partition as an `AWS::Partition` token, so a literal one was typed.
    #[test]
    fn values_of_an_environment_in_the_target_are_neither_hazards_nor_reported() {
        let mut t = reader::parse_text(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{"Arn":"arn:aws-eusc:sqs:eusc-de-east-1:444455556666:q"}}}}"#,
        )
        .unwrap();
        t.resources.get_mut("R").unwrap().env = Some(DeployEnv {
            region: Some("eusc-de-east-1".into()),
            account: Some("444455556666".into()),
        });
        let scan = hazards(&t, &facts());
        let left: Vec<_> = scan.hazards.iter().flat_map(|h| &h.literals).collect();
        assert_eq!(
            left,
            [&Literal {
                kind: HazardKind::ArnPartition,
                value: "arn:aws-eusc:".into(),
                impact: Impact::Portability,
                rule: None
            }]
        );
        assert!(scan.env_literals.is_empty());
    }

    #[test]
    fn literals_of_the_target_tie_the_input_to_it() {
        let t = reader::parse_text(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{
            "A":"arn:aws-eusc:s3:::b","H":"sqs.eusc-de-east-1.amazonaws.eu",
            "U":"https://sqs.eusc-de-east-1.amazonaws.eu/q","Z":"eusc-de-east-1b"}}}}"#,
        )
        .unwrap();
        let lits: Vec<_> = hazards(&t, &facts())
            .hazards
            .into_iter()
            .flat_map(|h| h.literals)
            .collect();
        assert_eq!(lits.len(), 6, "{lits:?}");
        assert!(
            lits.iter().all(|l| l.impact == Impact::Portability),
            "{lits:?}"
        );
        assert_eq!(
            lits.iter()
                .filter(|l| l.kind == HazardKind::DnsSuffix)
                .count(),
            2,
            "a bare host with a Region label is a host, not a principal: {lits:?}"
        );
    }

    fn lits(json: &str, f: &PartitionFacts) -> Vec<(HazardKind, String, Impact)> {
        hazards(&reader::parse_text(json).unwrap(), f)
            .hazards
            .into_iter()
            .flat_map(|h| h.literals)
            .map(|l| (l.kind, l.value, l.impact))
            .collect()
    }

    #[test]
    fn resource_ids_name_one_region_and_account() {
        let json = r#"{"Resources":{"R":{"Type":"AWS::EC2::Instance","Properties":{
            "ImageId":"ami-0123456789abcdef0","SubnetId":"subnet-0abc1234",
            "Name":"ami-builder","Tag":"sg-zzzzzzzz","Other":"vpc-0123"}}}}"#;
        for f in [
            facts(),
            crate::provider::partition::facts("eu-west-1").unwrap(),
        ] {
            let l = lits(json, &f);
            assert_eq!(
                l,
                [
                    (
                        HazardKind::ResourceId,
                        "ami-0123456789abcdef0".into(),
                        Impact::Breaks
                    ),
                    (
                        HazardKind::ResourceId,
                        "subnet-0abc1234".into(),
                        Impact::Breaks
                    )
                ],
                "{l:?}"
            );
        }
    }

    #[test]
    fn plan_resolved_ids_are_not_hazards() {
        let plan = |constant: &str| {
            format!(
                r#"{{"format_version":"1.2","planned_values":{{"root_module":{{"resources":[
                {{"address":"aws_instance.i","mode":"managed","type":"aws_instance",
                 "provider_name":"registry.terraform.io/hashicorp/aws",
                 "values":{{"ami":"ami-0123456789abcdef0","subnet_id":"subnet-0abc1234"}}}}]}}}},
                "configuration":{{"root_module":{{"resources":[{{"expressions":{{"ami":{{"constant_value":"{constant}"}}}}}}]}}}}}}"#
            )
        };
        let ids = |c: &str| -> Vec<String> {
            lits(&plan(c), &facts())
                .into_iter()
                .filter(|(k, _, _)| *k == HazardKind::ResourceId)
                .map(|(_, v, _)| v)
                .collect()
        };
        assert_eq!(ids("ami-0123456789abcdef0"), ["ami-0123456789abcdef0"]);
        assert!(
            ids("x").is_empty(),
            "looked-up and referenced ids are not typed"
        );
    }

    #[test]
    fn s3_dash_region_endpoints_get_the_standard_form() {
        let f = crate::provider::partition::facts("eu-west-1").unwrap();
        let l = lits(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{
            "U":"b.s3-us-west-2.amazonaws.com/k","Own":"b.s3-eu-west-1.amazonaws.com/k",
            "Logs":"archive-logs-s3-us-west-2"}}}}"#,
            &f,
        );
        assert!(l.contains(&(
            HazardKind::LegacyEndpoint,
            "s3-us-west-2".into(),
            Impact::Breaks
        )));
        assert!(l.contains(&(
            HazardKind::LegacyEndpoint,
            "s3-eu-west-1".into(),
            Impact::Portability
        )));
        let regions: Vec<_> = l
            .iter()
            .filter(|(k, _, _)| *k == HazardKind::RegionLiteral)
            .map(|(_, v, _)| v.as_str())
            .collect();
        assert_eq!(
            regions,
            ["us-west-2"],
            "only the bucket name's Region: {l:?}"
        );
    }

    #[test]
    fn source_partition_needs_one_known_partition() {
        let f = facts();
        let with = |regions: &[&str]| {
            let mut t = Template::default();
            for (i, r) in regions.iter().enumerate() {
                t.resources.insert(
                    format!("R{i}"),
                    crate::model::Resource {
                        logical_id: format!("R{i}"),
                        resource_type: "AWS::S3::Bucket".into(),
                        properties: Value::Null,
                        origin: Origin::Cfn,
                        env: Some(DeployEnv {
                            region: Some(r.to_string()),
                            account: None,
                        }),
                        cdk_path: None,
                    },
                );
            }
            source_partition(&t, &f)
        };
        assert_eq!(with(&[]), None, "no environment");
        assert_eq!(with(&["eu-west-1", "us-east-1"]).as_deref(), Some("aws"));
        assert_eq!(
            with(&["eu-west-1", "eusc-de-east-1"]),
            None,
            "two partitions"
        );
        assert_eq!(with(&["xx-nowhere-1"]), None, "an unknown Region");
    }

    /// CloudFront takes certificates from us-east-1 only, so that Region is required
    /// there; elsewhere, and in other partitions, it stays a hazard.
    #[test]
    fn a_required_region_is_no_hazard_at_its_property() {
        let euw1 = crate::provider::partition::facts("eu-west-1").unwrap();
        let json = r#"{"Resources":{"D":{"Type":"AWS::CloudFront::Distribution","Properties":{
            "DistributionConfig":{"ViewerCertificate":{
                "AcmCertificateArn":"arn:aws:acm:us-east-1:111122223333:certificate/x"},
              "Comment":"us-east-1"}}}}}"#;
        let regions = |f: &PartitionFacts| -> Vec<String> {
            lits(json, f)
                .into_iter()
                .filter(|(k, _, _)| *k == HazardKind::RegionLiteral)
                .map(|(_, v, _)| v)
                .collect()
        };
        assert_eq!(regions(&euw1), ["us-east-1"], "only the comment");
        assert_eq!(regions(&facts()), ["us-east-1", "us-east-1"]);
    }

    /// Bare account IDs count where a policy names an account, and in ECR hosts.
    #[test]
    fn bare_account_ids_in_principals_conditions_and_registries() {
        let mut f = crate::provider::partition::facts("eu-west-1").unwrap();
        f.target_account = Some("111122223333".into());
        let json = r#"{"Resources":{"R":{"Type":"AWS::IAM::Role","Properties":{
            "AssumeRolePolicyDocument":{"Statement":[{"Principal":{"AWS":["444455556666"]},
              "Condition":{"StringEquals":{"aws:SourceAccount":"111122223333"}}}]},
            "Description":"444455556666",
            "Image":"444455556666.dkr.ecr.eu-west-1.amazonaws.com/app:1"}},
          "P":{"Type":"AWS::Lambda::Permission","Properties":{
            "Principal":"444455556666","SourceAccount":"111122223333"}},
          "Q":{"Type":"aws_lambda_permission","Properties":{
            "principal":"444455556666","source_account":"111122223333","function_name":"444455556666"}},
          "K":{"Type":"AWS::KMS::Key","Properties":{"KeyPolicy":{"Statement":[{
            "Condition":{"StringEquals":{"kms:callerAccount":"444455556666"}}}]}}}}}"#;
        let accounts: Vec<(String, Impact)> = lits(json, &f)
            .into_iter()
            .filter(|(k, _, _)| *k == HazardKind::AccountId)
            .map(|(_, v, i)| (v, i))
            .collect();
        assert_eq!(
            accounts,
            // Sorted by resource and path.
            [
                ("444455556666".to_string(), Impact::Breaks),
                ("444455556666".to_string(), Impact::Breaks),
                ("111122223333".to_string(), Impact::Portability),
                ("444455556666".to_string(), Impact::Breaks),
                ("111122223333".to_string(), Impact::Portability),
                ("111122223333".to_string(), Impact::Portability),
                ("444455556666".to_string(), Impact::Breaks),
                ("444455556666".to_string(), Impact::Breaks),
            ],
            "not the description"
        );
    }

    #[test]
    fn other_regions_of_the_target_partition_break() {
        let mut f = crate::provider::partition::facts("eu-west-1").unwrap();
        let lits = lits(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{
            "Q":"https://sqs.eu-central-1.amazonaws.com/111122223333/q",
            "Arn":"arn:aws:sqs:eu-west-1:111122223333:q",
            "Z":"eu-central-1a","Own":"eu-west-1",
            "P":{"Service":["lambda.amazonaws.com","s3.ap-east-1.amazonaws.com"]}}}}}"#,
            &f,
        );
        use HazardKind::*;
        use Impact::*;
        for want in [
            (RegionLiteral, "eu-central-1", Breaks),
            (AvailabilityZone, "eu-central-1a", Breaks),
            (DnsSuffix, "amazonaws.com", Portability),
            (AccountId, "111122223333", Portability),
            (ArnPartition, "arn:aws:", Portability),
            (RegionLiteral, "eu-west-1", Portability),
            (RegionLiteral, "ap-east-1", Breaks),
        ] {
            assert!(
                lits.contains(&(want.0, want.1.into(), want.2)),
                "{want:?} in {lits:?}"
            );
        }
        assert!(
            !lits.iter().any(|(k, _, _)| *k == ServicePrincipal),
            "{lits:?}"
        );
        // An account next to another partition's ARN prefix is that partition's.
        f = crate::provider::partition::facts("eusc-de-east-1").unwrap();
        let t = reader::parse_text(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{"Role":"arn:aws:iam::111122223333:role/r"}}}}"#,
        )
        .unwrap();
        let lits: Vec<_> = hazards(&t, &f)
            .hazards
            .into_iter()
            .flat_map(|h| h.literals)
            .collect();
        assert!(lits.iter().all(|l| l.impact == Breaks), "{lits:?}");
    }

    #[test]
    fn scans_terraform_root_outputs() {
        let t = reader::parse_text(
            r#"{"format_version":"1.2","planned_values":{"outputs":{"queue":{"sensitive":false,"value":"arn:aws:sqs:eusc-de-east-1:444455556666:q"}}}}"#,
        )
        .unwrap();
        let h = hazards(&t, &facts()).hazards;
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].logical_id, "Outputs/queue");
        assert_eq!(h[0].path, "Value");
    }

    #[test]
    fn scans_output_values() {
        let t = reader::parse_text(
            r#"{"Resources":{"B":{"Type":"AWS::S3::Bucket"}},"Outputs":{"KeyArn":{"Value":{"Fn::Sub":"arn:aws:kms:${AWS::Region}:${AWS::AccountId}:key/x"},"Export":{"Name":"k"}}}}"#,
        )
        .unwrap();
        let h = hazards(&t, &facts()).hazards;
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].logical_id, "Outputs/KeyArn");
        assert_eq!(h[0].path, "Value.Fn::Sub");
        assert!(
            !t.resources.contains_key("Outputs/KeyArn"),
            "outputs are not resources"
        );
    }

    #[test]
    fn flags_each_hardcoded_hazard_kind() {
        let h = kinds(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{
            "Arn":"arn:aws:s3:::bucket",
            "Url":"https://sqs.eu-central-1.amazonaws.com/123/q",
            "Az":"eu-central-1a",
            "AzId":"euc1-az2",
            "Principal":{"Service":"lambda.amazonaws.com"}}}}}"#,
        );
        assert!(h.contains(&(HazardKind::ArnPartition, "arn:aws:".into())));
        assert!(h.contains(&(HazardKind::DnsSuffix, "amazonaws.com".into())));
        assert!(h.contains(&(HazardKind::RegionLiteral, "eu-central-1".into())));
        assert!(h.contains(&(HazardKind::AvailabilityZone, "eu-central-1a".into())));
        assert!(h.contains(&(HazardKind::AvailabilityZone, "euc1-az2".into())));
        assert!(
            !h.iter().any(|(_, l)| l.contains("lambda")),
            "service principals are not hazards: {h:?}"
        );
    }

    #[test]
    fn intrinsic_derived_values_are_safe() {
        let h = kinds(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{
            "Arn":{"Fn::Join":["",["arn:",{"Ref":"AWS::Partition"},":s3:::b"]]},
            "Sub":{"Fn::Sub":"arn:${AWS::Partition}:sqs:${AWS::Region}:${AWS::AccountId}:q"},
            "Host":{"Fn::Join":["",["sqs.",{"Ref":"AWS::Region"},".",{"Ref":"AWS::URLSuffix"}]]},
            "Az":{"Fn::Select":[0,{"Fn::GetAZs":""}]}}}}}"#,
        );
        assert!(h.is_empty(), "{h:?}");
    }

    #[test]
    fn hardcoded_arn_inside_sub_is_still_a_hazard() {
        let h = kinds(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{"A":{"Fn::Sub":"arn:aws:s3:::${B}"}}}}}"#,
        );
        assert_eq!(h, vec![(HazardKind::ArnPartition, "arn:aws:".into())]);
    }

    #[test]
    fn principals_inside_json_encoded_policies_are_safe() {
        let h = kinds(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{
            "Policy":"{\"Statement\":[{\"Principal\":{\"Service\":\"pods.eks.amazonaws.com\"},\"Resource\":\"arn:aws:s3:::b\"}]}"}}}}"#,
        );
        assert_eq!(h, vec![(HazardKind::ArnPartition, "arn:aws:".into())]);
    }

    #[test]
    fn no_false_positives_on_lookalikes() {
        let h = kinds(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{
            "B":"notamazonaws.community","C":"xeu-central-10","D":"amazonaws.eu.example.com"}}}}"#,
        );
        assert!(h.is_empty(), "{h:?}");
    }

    #[test]
    fn wildcard_principals_and_service_linked_role_paths_are_safe() {
        let h = kinds(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{
            "Cond":"*bedrock-agentcore.amazonaws.com",
            "Path":"/aws-service-role/guardduty.amazonaws.com/"}}}}"#,
        );
        assert!(h.is_empty(), "{h:?}");
    }

    #[test]
    fn china_service_principals_are_hazards() {
        let h = kinds(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{
            "Principal":{"Service":"lambda.amazonaws.com.cn"}}}}}"#,
        );
        assert_eq!(
            h,
            vec![(HazardKind::ServicePrincipal, "amazonaws.com.cn".into())]
        );
    }

    #[test]
    fn account_ids_in_arns() {
        let h = kinds(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{
            "A":{"Fn::Join":["",["arn:",{"Ref":"AWS::Partition"},":secretsmanager:eusc-de-east-1:444455556666:secret:x"]]},
            "B":"123456789012","C":"build-123456789012-x"}}}}"#,
        );
        assert_eq!(
            h,
            vec![
                (HazardKind::RegionLiteral, "eusc-de-east-1".into()),
                (HazardKind::AccountId, "444455556666".into())
            ]
        );
    }

    #[test]
    fn one_place_per_value() {
        let t = reader::parse_text(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{
            "A":"arn:aws:secretsmanager:us-east-1:444455556666:secret:x"}}}}"#,
        )
        .unwrap();
        let s = hazards(&t, &facts());
        assert_eq!(s.hazards.len(), 1);
        assert_eq!(s.hazards[0].literals.len(), 3);
    }

    #[test]
    fn synthesis_environment_literals_are_counted_once() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cdk.out");
        let t = reader::read(dir, "eusc-de-east-1").unwrap();
        let s = hazards(&t, &facts());
        assert_eq!(s.env_literals.len(), 1);
        assert_eq!(s.env_literals[0].places, 2);
        let left: Vec<_> = s.hazards.iter().flat_map(|h| &h.literals).collect();
        assert_eq!(
            left.iter().map(|l| l.kind).collect::<Vec<_>>(),
            [
                HazardKind::ArnPartition,
                HazardKind::RegionLiteral,
                HazardKind::AccountId
            ],
            "the foreign secret ARN stays: {left:?}"
        );
    }

    #[test]
    fn values_for_the_inputs_other_environments() {
        // A CDK pipeline stack writes in the regions and accounts it deploys to.
        let env = |r: &str, a: &str| crate::model::DeployEnv {
            region: Some(r.into()),
            account: Some(a.into()),
        };
        let mut t = reader::parse_text(
            r#"{"Resources":{
            "Pipeline":{"Type":"AWS::X::Y","Properties":{
                "Region":"us-east-1","Role":"arn:aws:iam::444455556666:role/deploy",
                "Bucket":"assets-111122223333-eu-central-1"}},
            "Replica":{"Type":"AWS::X::Y","Properties":{"Name":"replica-us-east-1"}}}}"#,
        )
        .unwrap();
        t.resources.get_mut("Pipeline").unwrap().env = Some(env("eu-central-1", "111122223333"));
        t.resources.get_mut("Replica").unwrap().env = Some(env("us-east-1", "444455556666"));
        let s = hazards(&t, &facts());
        // The hand-written partition is still a hazard; the other values are not.
        assert_eq!(
            s.hazards
                .iter()
                .map(|h| h.path.as_str())
                .collect::<Vec<_>>(),
            ["Properties.Role"]
        );
        let places: usize = s.env_literals.iter().map(|e| e.places).sum();
        assert_eq!(places, 4, "each value counts once: {:?}", s.env_literals);
    }

    #[test]
    fn terraform_plan_partition_literals_count_as_environment() {
        let t = reader::parse_text(
            r#"{"format_version":"1.2","planned_values":{"root_module":{"resources":[
            {"address":"aws_iam_role_policy.p","mode":"managed","type":"aws_iam_role_policy",
             "provider_name":"registry.terraform.io/hashicorp/aws",
             "values":{"policy":"arn:aws:s3:::b"}}]}},
            "configuration":{"provider_config":{"aws":{"expressions":{"region":{"constant_value":"eu-central-1"}}}}}}"#,
        )
        .unwrap();
        let s = hazards(&t, &facts());
        assert!(s.hazards.is_empty(), "{:?}", s.hazards);
        assert_eq!(s.env_literals[0].places, 1);
        let mut t = t;
        t.constants.insert("arn:aws:".into());
        assert!(
            hazards(&t, &facts()).hazards.is_empty(),
            "a constant of only the literal does not make the value hand-written"
        );
        t.constants.insert("arn:aws:s3:::b".into());
        let s = hazards(&t, &facts());
        assert_eq!(
            s.hazards.len(),
            1,
            "a constant in the configuration is hand-written"
        );
    }
}
