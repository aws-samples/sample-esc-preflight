//! Walks template properties and flags hardcoded partition-specific literals.
//!
//! Only literal strings are inspected. Values built from `AWS::Partition`, `AWS::Region`
//! or `AWS::URLSuffix` never contain a commercial literal, so they pass naturally.
//! Values that CDK synthesis or a Terraform plan wrote for its own environment are
//! counted separately: producing the input for the target removes them all at once.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{DeployEnv, OUTPUT_TYPE, Origin, Template};
use serde::Serialize;
use serde_json::Value;

/// Partition facts read from the live botocore `partitions.json`, never hardcoded.
#[derive(Debug, Clone)]
pub struct PartitionFacts {
    /// Partition id of the target region, e.g. `aws-eusc`.
    pub target_partition: String,
    /// DNS suffix of the target partition, e.g. `amazonaws.eu`.
    pub target_dns_suffix: String,
    /// Partition ids other than the target.
    pub foreign_partitions: Vec<String>,
    /// DNS suffixes of other partitions that the target does not share.
    pub foreign_dns_suffixes: Vec<String>,
    /// Region ids that belong to other partitions.
    pub foreign_regions: Vec<String>,
    /// Partition id of each foreign region.
    pub region_partition: BTreeMap<String, String>,
    /// Foreign DNS suffixes per foreign partition.
    pub partition_dns: BTreeMap<String, Vec<String>>,
    /// Regions in the target partition. With one, no cross-Region feature can exist.
    pub target_regions: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HazardKind {
    /// `arn:<other-partition>:` in a literal.
    ArnPartition,
    /// An endpoint host with another partition's DNS suffix.
    DnsSuffix,
    /// A service principal with another partition's suffix, e.g. `lambda.amazonaws.com.cn`.
    ServicePrincipal,
    /// A region id of another partition.
    RegionLiteral,
    /// An Availability Zone name or id of another partition.
    AvailabilityZone,
    /// A 12-digit account id in an ARN. An ESC account always has a different id.
    AccountId,
}

/// One place to fix: a property value with every hazardous literal found in it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Literal {
    pub kind: HazardKind,
    pub value: String,
}

/// Values written for the environment the input was produced for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
            .is_none_or(|r| facts.region_partition.contains_key(r))
    };
    // Environments in the target still match, so their values are not hazards, but
    // they are not reported as environment literals.
    let all_envs: Vec<DeployEnv> = template.envs();
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
            let mut hits: BTreeMap<&DeployEnv, Vec<String>> = BTreeMap::new();
            let hand_written = |lit: &str| {
                template
                    .constants
                    .iter()
                    .any(|c| c.contains(lit) && (s.contains(c.as_str()) || c.contains(s)))
            };
            found.retain(|(kind, lit)| {
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
                .map(|(kind, value)| Literal { kind, value })
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

fn from_env(
    kind: HazardKind,
    lit: &str,
    env: &DeployEnv,
    partition: Option<&String>,
    facts: &PartitionFacts,
) -> bool {
    match kind {
        HazardKind::RegionLiteral => env.region.as_deref() == Some(lit),
        HazardKind::AvailabilityZone => env.region.as_deref().is_some_and(|r| {
            lit.strip_prefix(r)
                .is_some_and(|z| z.len() == 1 && z.chars().all(|c| c.is_ascii_lowercase()))
        }),
        HazardKind::AccountId => env.account.as_deref() == Some(lit),
        HazardKind::ArnPartition => partition.is_some_and(|p| lit == format!("arn:{p}:")),
        HazardKind::DnsSuffix | HazardKind::ServicePrincipal => partition
            .and_then(|p| facts.partition_dns.get(p))
            .is_some_and(|s| s.iter().any(|x| x == lit)),
    }
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

fn scan_literal(s: &str, facts: &PartitionFacts) -> Vec<(HazardKind, String)> {
    let mut found = Vec::new();
    for p in &facts.foreign_partitions {
        let needle = format!("arn:{p}:");
        if s.contains(&needle) {
            found.push((HazardKind::ArnPartition, needle));
        }
    }
    match principal_suffix(s, facts) {
        Some(SERVICE_PRINCIPAL_SUFFIX) => {}
        Some(suffix) => found.push((HazardKind::ServicePrincipal, suffix.to_string())),
        None => {
            for suffix in &facts.foreign_dns_suffixes {
                if contains_suffix(s, suffix) {
                    found.push((HazardKind::DnsSuffix, suffix.clone()));
                }
            }
        }
    }
    for region in &facts.foreign_regions {
        for (start, end) in occurrences(s, region) {
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
    }
    // The account field of an ARN, also inside an `Fn::Join` piece such as
    // `:secretsmanager:us-east-1:111122223333:secret:x`.
    if s.contains(':') {
        for piece in s.split(':') {
            if piece.len() == 12 && piece.bytes().all(|b| b.is_ascii_digit()) {
                found.push((HazardKind::AccountId, piece.to_string()));
            }
        }
    }
    found
}

/// The suffix of service principals in the target. ESC trust policies use
/// `lambda.amazonaws.com`, while some `aws-cn` principals end in `amazonaws.com.cn`.
const SERVICE_PRINCIPAL_SUFFIX: &str = "amazonaws.com";

/// The foreign suffix of a whole literal of the form `<svc>.<foreign-suffix>`, as used
/// in IAM trust policies, with a leading wildcard in `iam:AWSServiceName` conditions,
/// and in service-linked role paths.
fn principal_suffix<'a>(s: &str, facts: &'a PartitionFacts) -> Option<&'a str> {
    let s = s.strip_prefix('*').unwrap_or(s);
    let s = s
        .split_once("aws-service-role/")
        .map_or(s, |(_, rest)| rest.split('/').next().unwrap_or(rest));
    facts
        .foreign_dns_suffixes
        .iter()
        .map(String::as_str)
        .find(|suffix| {
            s.strip_suffix(suffix)
                .and_then(|head| head.strip_suffix('.'))
                .is_some_and(|svc| {
                    !svc.is_empty()
                        && svc.chars().all(|c| {
                            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'
                        })
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
        PartitionFacts {
            target_partition: "aws-eusc".into(),
            target_dns_suffix: "amazonaws.eu".into(),
            foreign_partitions: vec!["aws".into(), "aws-cn".into(), "aws-us-gov".into()],
            foreign_dns_suffixes: vec!["amazonaws.com".into(), "amazonaws.com.cn".into()],
            foreign_regions: vec!["eu-central-1".into(), "us-east-1".into()],
            region_partition: [("eu-central-1", "aws"), ("us-east-1", "aws")]
                .map(|(r, p)| (r.to_string(), p.to_string()))
                .into(),
            partition_dns: [("aws".to_string(), vec!["amazonaws.com".to_string()])].into(),
            target_regions: 1,
        }
    }

    fn kinds(json: &str) -> Vec<(HazardKind, String)> {
        let t = reader::parse(json).unwrap();
        hazards(&t, &facts())
            .hazards
            .into_iter()
            .flat_map(|h| h.literals)
            .map(|l| (l.kind, l.value))
            .collect()
    }

    #[test]
    fn values_of_an_environment_in_the_target_are_neither_hazards_nor_reported() {
        let mut t = reader::parse(
            r#"{"Resources":{"R":{"Type":"AWS::X::Y","Properties":{"Arn":"arn:aws-eusc:sqs:eusc-de-east-1:444455556666:q"}}}}"#,
        )
        .unwrap();
        t.resources.get_mut("R").unwrap().env = Some(DeployEnv {
            region: Some("eusc-de-east-1".into()),
            account: Some("444455556666".into()),
        });
        let scan = hazards(&t, &facts());
        assert!(scan.hazards.is_empty(), "{:?}", scan.hazards);
        assert!(scan.env_literals.is_empty());
    }

    #[test]
    fn scans_terraform_root_outputs() {
        let t = reader::parse(
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
        let t = reader::parse(
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
            "A":"arn:aws-eusc:s3:::b","B":"notamazonaws.community","C":"xeu-central-10","D":"sqs.eusc-de-east-1.amazonaws.eu"}}}}"#,
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
        assert_eq!(h, vec![(HazardKind::AccountId, "444455556666".into())]);
    }

    #[test]
    fn one_place_per_value() {
        let t = reader::parse(
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
        let t = reader::read(dir).unwrap();
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
        let mut t = reader::parse(
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
        let t = reader::parse(
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
        t.constants.insert("arn:aws:s3:::b".into());
        let s = hazards(&t, &facts());
        assert_eq!(
            s.hazards.len(),
            1,
            "a constant in the configuration is hand-written"
        );
    }
}
