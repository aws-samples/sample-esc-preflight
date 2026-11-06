//! What to do about each required change, and how sure the tool is about it.
//!
//! `fix`: the change keeps the value the input has today, is valid in the target and
//! touches one property value. `propose`: one documented change exists, but it holds
//! only under a stated precondition or replaces a resource. `flag`: the owner decides.

use serde::Serialize;

use crate::depth::{DepthCheck, DepthKind, Offered};
use crate::deviation::Deviation;
use crate::extractor::{Hazard, HazardKind, Literal};
use crate::model::DeployEnv;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    Fix,
    Propose,
    Flag,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequiredChange {
    pub logical_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdk_path: Option<String>,
    pub tier: Tier,
    pub reason: String,
    pub change: String,
    /// What must hold for a proposed change to be right.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub precondition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consequence: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub edits: Vec<Edit>,
    /// Values the target offers, for the owner to choose from.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

impl RequiredChange {
    pub fn new(logical_id: &str, tier: Tier, reason: String, change: String) -> Self {
        Self {
            logical_id: logical_id.into(),
            cdk_path: None,
            tier,
            reason,
            change,
            precondition: None,
            consequence: None,
            edits: Vec::new(),
            candidates: Vec::new(),
            doc: None,
        }
    }
}

/// Replace `find` in the string value at `path` with the expression for the source the
/// input was produced from. A CloudFormation expression in `${}` goes into `Fn::Sub`; a
/// zone replacement is the whole value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Edit {
    pub path: String,
    pub find: String,
    pub replace: Replacement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Replacement {
    pub cloudformation: String,
    pub cdk: String,
    pub terraform: String,
}

/// What the target is known to be and offer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Context<'a> {
    /// The target partition has one region, so no cross-Region feature can exist.
    pub single_region: bool,
    /// Zones the target region offers (live mode).
    pub target_zones: Option<usize>,
    pub offered: Option<&'a Offered>,
}

struct Decision {
    tier: Tier,
    change: String,
    precondition: Option<&'static str>,
    replace: Option<Replacement>,
}

fn rep(cloudformation: &str, cdk: &str, terraform: &str) -> Option<Replacement> {
    Some(Replacement {
        cloudformation: cloudformation.into(),
        cdk: cdk.into(),
        terraform: terraform.into(),
    })
}

fn decide(l: &Literal, h: &Hazard, ctx: &Context) -> Decision {
    let v = &l.value;
    let env = h.env.as_ref();
    // Unknown environment: likely the deployment's own value, but not provable.
    let own = |field: Option<&String>| match field {
        None => Tier::Propose,
        Some(x) if x == v => Tier::Fix,
        Some(_) => Tier::Flag,
    };
    match l.kind {
        HazardKind::ArnPartition => Decision {
            tier: Tier::Fix,
            change: "Build the ARN from the partition instead of the literal.".into(),
            precondition: None,
            replace: rep(
                "arn:${AWS::Partition}:",
                "arn:${Aws.PARTITION}:",
                "arn:${data.aws_partition.current.partition}:",
            ),
        },
        HazardKind::DnsSuffix => Decision {
            // Hosts without a Region label, such as `s3.amazonaws.com`, mostly have no
            // counterpart under another partition's suffix.
            tier: if has_region_label(&h.value) {
                Tier::Fix
            } else {
                Tier::Propose
            },
            change: "Build the host name from the partition's DNS suffix instead of the literal."
                .into(),
            precondition: (!has_region_label(&h.value)).then_some(
                "The target serves this host without a Region in its name. Most global host names exist only with a Region in other partitions; check the target's endpoints.",
            ),
            replace: rep(
                "${AWS::URLSuffix}",
                "${Aws.URL_SUFFIX}",
                "${data.aws_partition.current.dns_suffix}",
            ),
        },
        HazardKind::ServicePrincipal => Decision {
            tier: Tier::Fix,
            change: "Use the `amazonaws.com` form of the service principal.".into(),
            precondition: None,
            replace: rep("amazonaws.com", "amazonaws.com", "amazonaws.com"),
        },
        HazardKind::RegionLiteral => match own(env.and_then(|e| e.region.as_ref())) {
            Tier::Flag => Decision {
                tier: Tier::Flag,
                change: format!(
                    "`{v}` is not the Region this resource deploys to, so it refers to something in another Region. Decide what replaces it in the target."
                ),
                precondition: None,
                replace: None,
            },
            tier => Decision {
                tier,
                change: format!("Use the deployment Region instead of `{v}`."),
                precondition: (tier == Tier::Propose).then_some(
                    "The value means the Region the stack deploys to. The input does not say which Region it was written for.",
                ),
                replace: rep(
                    "${AWS::Region}",
                    "${Aws.REGION}",
                    "${data.aws_region.current.region}",
                ),
            },
        },
        HazardKind::AccountId => match own(env.and_then(|e| e.account.as_ref())) {
            Tier::Flag => Decision {
                tier: Tier::Flag,
                change: format!(
                    "`{v}` is not the account this resource deploys to. Name the account that has this role in the target partition; for an AWS-owned account, look up its value for the target Region."
                ),
                precondition: None,
                replace: None,
            },
            tier => Decision {
                tier,
                change: format!("Use the deployment account instead of `{v}`."),
                precondition: (tier == Tier::Propose).then_some(
                    "The value is the account the stack deploys to, not another account such as a central logging or an AWS-owned account.",
                ),
                replace: rep(
                    "${AWS::AccountId}",
                    "${Aws.ACCOUNT_ID}",
                    "${data.aws_caller_identity.current.account_id}",
                ),
            },
        },
        HazardKind::AvailabilityZone => zone(v, &h.value, env, ctx),
    }
}

/// A zone name `<region><letter>` becomes the zone at the same index in the target,
/// when the target has that many zones and the region is the resource's own.
fn zone(v: &str, whole: &str, env: Option<&DeployEnv>, ctx: &Context) -> Decision {
    let flag = |why: String| Decision {
        tier: Tier::Flag,
        change: format!("Choose the zone for `{v}` in the target. {why}"),
        precondition: None,
        replace: None,
    };
    let letter = v.chars().last().filter(char::is_ascii_lowercase);
    let region = &v[..v.len().saturating_sub(1)];
    let Some(letter) = letter.filter(|_| region.ends_with(|c: char| c.is_ascii_digit())) else {
        return flag("Zone IDs name a physical zone of another partition.".into());
    };
    if env
        .and_then(|e| e.region.as_deref())
        .is_some_and(|r| r != region)
    {
        return flag("It is in another Region than the resource.".into());
    }
    if whole != v {
        return flag("It is part of a longer value.".into());
    }
    let i = letter as usize - 'a' as usize;
    match ctx.target_zones {
        None => flag("Run in live mode to compare with the target's zones.".into()),
        Some(n) if i >= n => flag(format!("The target offers {n} zones.")),
        Some(_) => Decision {
            tier: Tier::Propose,
            change: format!("Use the target's zone at index {i} instead of `{v}`."),
            precondition: Some(
                "Any zone of the target serves here. Zone names are per Region, so the index picks a different physical zone.",
            ),
            replace: rep(
                &format!(r#"{{"Fn::Select": [{i}, {{"Fn::GetAZs": ""}}]}}"#),
                &format!("Stack.of(this).availabilityZones[{i}]"),
                &format!("data.aws_availability_zones.available.names[{i}]"),
            ),
        },
    }
}

/// An AWS principal of another partition in a policy. IAM trust does not cross
/// partitions, so rewriting its ARN would produce a principal that cannot exist.
fn foreign_principal(h: &Hazard) -> Option<RequiredChange> {
    let in_principal = h.path.contains("Principal.AWS") || h.path.ends_with("Principal");
    // With the account built from `AWS::AccountId` the principal is the deployment's
    // own account, and the partition fix is right. A literal account is one of the
    // other partition, because no ESC account shares an id with another partition.
    let has = |k| h.literals.iter().any(|l| l.kind == k);
    let foreign = has(HazardKind::ArnPartition) && has(HazardKind::AccountId);
    (in_principal && foreign).then(|| {
        let mut c = RequiredChange::new(
            &h.logical_id,
            Tier::Flag,
            format!("principal of another partition at {}", h.path),
            "IAM trust does not cross partitions. Replace the principal with an identity in the target partition, for example a role there or an OIDC provider or IAM Roles Anywhere trust anchor for the caller.".into(),
        );
        c.consequence = Some(
            "Changing only the partition of the ARN produces a principal that does not exist in the target."
                .into(),
        );
        c
    })
}

/// An Amazon ECR image host. Fixing its DNS suffix points to a registry in the target
/// partition, which holds the image only after the pipeline copies it there.
const ECR_IMAGE_CONSEQUENCE: &str = "The image must exist in an ECR repository in the target partition. ECR replication and pull-through cache do not cross partitions, so copy the image there, by digest, before deploying.";

/// One change per tier among the hazard's literals, so a fix is never held back by a
/// flag in the same value.
pub fn hazard(h: &Hazard, ctx: &Context) -> Vec<RequiredChange> {
    if let Some(c) = foreign_principal(h) {
        return vec![c];
    }
    let decided: Vec<(&Literal, Decision)> =
        h.literals.iter().map(|l| (l, decide(l, h, ctx))).collect();
    let mut out = Vec::new();
    for tier in [Tier::Fix, Tier::Propose, Tier::Flag] {
        let mine: Vec<_> = decided.iter().filter(|(_, d)| d.tier == tier).collect();
        if mine.is_empty() {
            continue;
        }
        let values: Vec<_> = mine.iter().map(|(l, _)| format!("`{}`", l.value)).collect();
        let mut c = RequiredChange::new(
            &h.logical_id,
            tier,
            format!("hardcoded {} at {}", values.join(", "), h.path),
            join_unique(mine.iter().map(|(_, d)| d.change.as_str())),
        );
        let pre = join_unique(mine.iter().filter_map(|(_, d)| d.precondition));
        c.precondition = (!pre.is_empty()).then_some(pre);
        if h.value.contains(".dkr.ecr.")
            && mine.iter().any(|(l, _)| l.kind == HazardKind::DnsSuffix)
        {
            c.consequence = Some(ECR_IMAGE_CONSEQUENCE.into());
        }
        c.edits = mine
            .iter()
            .filter_map(|(l, d)| {
                d.replace.clone().map(|replace| Edit {
                    path: h.path.clone(),
                    find: l.value.clone(),
                    replace,
                })
            })
            .collect();
        out.push(c);
    }
    out
}

fn join_unique<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    let mut seen: Vec<&str> = Vec::new();
    for p in parts {
        if !seen.contains(&p) {
            seen.push(p);
        }
    }
    seen.join(" ")
}

pub fn deviation(d: &Deviation, ctx: &Context) -> RequiredChange {
    let reason = format!(
        "{} uses a feature the ESC User Guide documents as different: \"{}\" ({})",
        d.resource_type, d.documented, d.source
    );
    match d.remediation.as_ref().filter(|_| ctx.single_region) {
        Some(m) => {
            let mut c = RequiredChange::new(&d.logical_id, Tier::Propose, reason, m.change.clone());
            c.consequence = Some(m.consequence.clone());
            c.doc = Some(m.doc.clone());
            c
        }
        None => {
            let mut c = RequiredChange::new(
                &d.logical_id,
                Tier::Flag,
                reason,
                "Decide how to remove or replace the feature in the target.".into(),
            );
            c.doc = Some(d.source.clone());
            c
        }
    }
}

pub fn depth(
    logical_id: &str,
    d: &DepthCheck,
    target_region: &str,
    ctx: &Context,
) -> RequiredChange {
    let reason = format!(
        "{} `{}` at {} is not offered in {target_region}",
        kind_label(d.kind),
        d.value,
        d.path
    );
    let set = ctx.offered.and_then(|o| o.get(&d.kind));
    let (candidates, consequence) = match (d.kind, set) {
        (DepthKind::InstanceType, Some(s)) => (
            instance_candidates(&d.value, s),
            "Price and performance differ between instance families.",
        ),
        (DepthKind::RdsEngineVersion | DepthKind::CacheEngineVersion, Some(s)) => (
            version_candidates(&d.value, s),
            "Versions differ in features and fixes; test the application against the chosen one.",
        ),
        _ => (Vec::new(), ""),
    };
    if candidates.is_empty() {
        return RequiredChange::new(
            logical_id,
            Tier::Flag,
            reason,
            "Choose a value the target region offers.".into(),
        );
    }
    let mut c = RequiredChange::new(
        logical_id,
        Tier::Propose,
        reason,
        "Choose one of the candidates the target offers.".into(),
    );
    c.candidates = candidates;
    c.consequence = Some(consequence.into());
    c
}

fn kind_label(k: DepthKind) -> &'static str {
    match k {
        DepthKind::InstanceType => "instance type",
        DepthKind::AvailabilityZone => "zone",
        DepthKind::FoundationModel => "foundation model",
        DepthKind::InferenceProfile => "inference profile",
        DepthKind::RdsEngineVersion => "RDS engine version",
        DepthKind::CacheEngineVersion => "ElastiCache engine version",
    }
}

/// `m7g.large` -> class `m`, generation 7, attributes `g`, size `large`.
fn instance_parts(t: &str) -> Option<(&str, u32, &str, &str)> {
    let (family, size) = t.split_once('.')?;
    let digits = family.find(|c: char| c.is_ascii_digit())?;
    let rest = &family[digits..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let class = &family[..digits];
    if class.is_empty() || !class.chars().all(|c| c.is_ascii_lowercase()) {
        return None;
    }
    Some((class, rest[..end].parse().ok()?, &rest[end..], size))
}

/// A DNS label shaped like a Region id, such as `eu-central-1`.
fn has_region_label(host: &str) -> bool {
    host.split(['.', '/', ':']).any(|label| {
        let mut parts = label.split('-');
        let first = parts.next().unwrap_or_default();
        let rest: Vec<_> = parts.collect();
        rest.len() >= 2
            && !first.is_empty()
            && first.chars().all(|c| c.is_ascii_lowercase())
            && rest
                .last()
                .is_some_and(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()))
            && rest[..rest.len() - 1]
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase()))
    })
}

/// Same class and size and the same processor architecture (a `g` attribute marks
/// Graviton), newest generation first, at most five.
fn instance_candidates(value: &str, offered: &std::collections::BTreeSet<String>) -> Vec<String> {
    let Some((class, _, attrs, size)) = instance_parts(value) else {
        return Vec::new();
    };
    let arm = attrs.contains('g');
    let mut c: Vec<(u32, &String)> = offered
        .iter()
        .filter_map(|o| {
            let (oc, og, oa, os) = instance_parts(o)?;
            (oc == class && os == size && oa.contains('g') == arm).then_some((og, o))
        })
        .collect();
    c.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
    c.into_iter().take(5).map(|(_, o)| o.clone()).collect()
}

/// Offered versions of the same engine and major version, newest first, at most five.
/// Values are `engine version`.
fn version_candidates(value: &str, offered: &std::collections::BTreeSet<String>) -> Vec<String> {
    let Some((engine, version)) = value.split_once(' ') else {
        return Vec::new();
    };
    let major = version.split('.').next().unwrap_or(version);
    let key = |v: &str| -> Vec<u64> { v.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    let mut c: Vec<&str> = offered
        .iter()
        .filter_map(|o| o.strip_prefix(engine)?.strip_prefix(' '))
        .filter(|v| v.split('.').next() == Some(major))
        .collect();
    c.sort_by_key(|v| std::cmp::Reverse(key(v)));
    c.into_iter()
        .take(5)
        .map(|v| format!("{engine} {v}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn at(path: &str, value: &str, literals: Vec<Literal>) -> Vec<RequiredChange> {
        hazard(
            &Hazard {
                logical_id: "R".into(),
                path: path.into(),
                value: value.into(),
                literals,
                env: None,
            },
            &Context::default(),
        )
    }

    #[test]
    fn foreign_principals_are_one_flag_not_a_partition_fix() {
        let c = at(
            "Properties.AssumeRolePolicyDocument.Statement[0].Principal.AWS",
            "arn:aws:iam::111122223333:role/deployer",
            vec![
                lit(HazardKind::ArnPartition, "arn:aws:"),
                lit(HazardKind::AccountId, "111122223333"),
            ],
        );
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].tier, Tier::Flag);
        assert!(c[0].edits.is_empty());
        assert!(c[0].change.contains("does not cross partitions"));
    }

    #[test]
    fn own_account_principal_keeps_the_partition_fix() {
        let c = at(
            "Properties.KeyPolicy.Statement[0].Principal.AWS",
            "arn:aws:iam::${AWS::AccountId}:root",
            vec![lit(HazardKind::ArnPartition, "arn:aws:")],
        );
        assert_eq!(c[0].tier, Tier::Fix);
    }

    #[test]
    fn ecr_image_fix_says_the_image_must_be_copied() {
        let c = at(
            "Properties.ContainerDefinitions[0].Image",
            "111122223333.dkr.ecr.eu-central-1.amazonaws.com/app:1",
            vec![lit(HazardKind::DnsSuffix, "amazonaws.com")],
        );
        let fix = c.iter().find(|c| c.tier == Tier::Fix).unwrap();
        assert!(
            fix.consequence
                .as_deref()
                .unwrap()
                .contains("copy the image")
        );
    }

    fn lit(kind: HazardKind, value: &str) -> Literal {
        Literal {
            kind,
            value: value.into(),
        }
    }

    fn env(region: &str, account: Option<&str>) -> DeployEnv {
        DeployEnv {
            region: Some(region.into()),
            account: account.map(Into::into),
        }
    }

    fn tiers(literals: Vec<Literal>, env: Option<DeployEnv>, ctx: &Context) -> Vec<Tier> {
        hazard(
            &Hazard {
                logical_id: "R".into(),
                path: "Properties.X".into(),
                value: literals
                    .iter()
                    .map(|l| l.value.as_str())
                    .collect::<Vec<_>>()
                    .join("."),
                literals,
                env,
            },
            ctx,
        )
        .into_iter()
        .map(|c| c.tier)
        .collect()
    }

    #[test]
    fn partition_and_suffix_are_fixes() {
        let c = hazard(
            &Hazard {
                logical_id: "R".into(),
                path: "Properties.Arn".into(),
                literals: vec![
                    lit(HazardKind::ArnPartition, "arn:aws:"),
                    lit(HazardKind::DnsSuffix, "amazonaws.com"),
                ],
                env: None,
                value: "arn:aws:x sqs.eu-central-1.amazonaws.com/q".into(),
            },
            &Context::default(),
        );
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].tier, Tier::Fix);
        assert_eq!(c[0].edits.len(), 2);
        assert_eq!(
            c[0].edits[0].replace.cloudformation,
            "arn:${AWS::Partition}:"
        );
        assert!(c[0].precondition.is_none());
    }

    #[test]
    fn region_and_account_depend_on_the_known_environment() {
        let ctx = Context::default();
        let region = || vec![lit(HazardKind::RegionLiteral, "eu-central-1")];
        let account = || vec![lit(HazardKind::AccountId, "111122223333")];
        assert_eq!(tiers(region(), None, &ctx), [Tier::Propose]);
        assert_eq!(
            tiers(region(), Some(env("eu-central-1", None)), &ctx),
            [Tier::Fix]
        );
        assert_eq!(
            tiers(region(), Some(env("us-east-1", None)), &ctx),
            [Tier::Flag]
        );
        assert_eq!(
            tiers(account(), Some(env("us-east-1", None)), &ctx),
            [Tier::Propose]
        );
        assert_eq!(
            tiers(
                account(),
                Some(env("us-east-1", Some("111122223333"))),
                &ctx
            ),
            [Tier::Fix]
        );
        assert_eq!(
            tiers(
                account(),
                Some(env("us-east-1", Some("444455556666"))),
                &ctx
            ),
            [Tier::Flag]
        );
    }

    #[test]
    fn a_flag_does_not_hold_back_a_fix_in_the_same_value() {
        let t = tiers(
            vec![
                lit(HazardKind::ArnPartition, "arn:aws:"),
                lit(HazardKind::RegionLiteral, "us-east-1"),
            ],
            Some(env("eu-central-1", None)),
            &Context::default(),
        );
        assert_eq!(t, [Tier::Fix, Tier::Flag]);
    }

    #[test]
    fn zones_need_the_target_zone_count() {
        let z = |v: &str| vec![lit(HazardKind::AvailabilityZone, v)];
        let live = Context {
            target_zones: Some(2),
            ..Context::default()
        };
        assert_eq!(
            tiers(z("eu-central-1b"), None, &Context::default()),
            [Tier::Flag]
        );
        assert_eq!(tiers(z("eu-central-1b"), None, &live), [Tier::Propose]);
        assert_eq!(tiers(z("eu-central-1c"), None, &live), [Tier::Flag]);
        assert_eq!(tiers(z("euc1-az1"), None, &live), [Tier::Flag]);
        assert_eq!(
            tiers(z("eu-central-1a"), Some(env("us-east-1", None)), &live),
            [Tier::Flag]
        );
        let c = hazard(
            &Hazard {
                logical_id: "R".into(),
                path: "Properties.AvailabilityZone".into(),
                literals: z("eu-central-1b"),
                env: None,
                value: "eu-central-1b".into(),
            },
            &live,
        );
        assert_eq!(
            c[0].edits[0].replace.terraform,
            "data.aws_availability_zones.available.names[1]"
        );
    }

    fn one(kind: HazardKind, lit_value: &str, whole: &str, ctx: &Context) -> Tier {
        hazard(
            &Hazard {
                logical_id: "R".into(),
                path: "Properties.X".into(),
                literals: vec![lit(kind, lit_value)],
                env: None,
                value: whole.into(),
            },
            ctx,
        )[0]
        .tier
    }

    #[test]
    fn a_zone_inside_a_longer_value_is_flagged() {
        let live = Context {
            target_zones: Some(2),
            ..Context::default()
        };
        let z = HazardKind::AvailabilityZone;
        assert_eq!(
            one(z, "eu-central-1a", "eu-central-1a", &live),
            Tier::Propose
        );
        assert_eq!(
            one(z, "eu-central-1a", "app-eu-central-1a", &live),
            Tier::Flag
        );
    }

    #[test]
    fn a_suffix_without_a_region_label_is_proposed() {
        let d = HazardKind::DnsSuffix;
        let ctx = Context::default();
        assert_eq!(
            one(
                d,
                "amazonaws.com",
                "sqs.eu-central-1.amazonaws.com/1/q",
                &ctx
            ),
            Tier::Fix
        );
        assert_eq!(
            one(d, "amazonaws.com", "s3.us-east-1.amazonaws.com", &ctx),
            Tier::Fix
        );
        assert_eq!(
            one(d, "amazonaws.com", "s3.amazonaws.com/bucket", &ctx),
            Tier::Propose
        );
        assert_eq!(
            one(d, "amazonaws.com", "sts.amazonaws.com", &ctx),
            Tier::Propose
        );
    }

    fn dev(remediation: bool) -> Deviation {
        Deviation {
            logical_id: "T".into(),
            resource_type: "AWS::DynamoDB::GlobalTable".into(),
            rule: "dynamodb-global-tables".into(),
            documented: "Global Tables and Cross-Region Restore".into(),
            source: "https://docs.aws.eu/esc/latest/userguide/dynamodb.html".into(),
            remediation: remediation.then(|| crate::deviation::RuleRemediation {
                change: "Use a table.".into(),
                consequence: "Replaced.".into(),
                doc: "https://docs.aws.amazon.com/x".into(),
            }),
        }
    }

    #[test]
    fn rule_remediations_need_a_single_region_partition() {
        let one = Context {
            single_region: true,
            ..Context::default()
        };
        assert_eq!(deviation(&dev(true), &one).tier, Tier::Propose);
        assert_eq!(
            deviation(&dev(true), &one).doc.as_deref(),
            Some("https://docs.aws.amazon.com/x")
        );
        assert_eq!(deviation(&dev(true), &Context::default()).tier, Tier::Flag);
        assert_eq!(deviation(&dev(false), &one).tier, Tier::Flag);
    }

    #[test]
    fn instance_candidates_keep_size_and_architecture() {
        let offered: BTreeSet<String> = [
            "m5.large",
            "m6i.large",
            "m7i.large",
            "m7g.large",
            "m6g.large",
            "m7i.xlarge",
            "c7i.large",
        ]
        .map(String::from)
        .into();
        assert_eq!(
            instance_candidates("m5a.large", &offered),
            ["m7i.large", "m6i.large", "m5.large"]
        );
        assert_eq!(
            instance_candidates("m8g.large", &offered),
            ["m7g.large", "m6g.large"]
        );
        assert!(instance_candidates("u-6tb1.metal", &offered).is_empty());
    }

    #[test]
    fn version_candidates_keep_the_major_version() {
        let offered: BTreeSet<String> = [
            "postgres 16.4",
            "postgres 16.10",
            "postgres 17.2",
            "mysql 16.1",
        ]
        .map(String::from)
        .into();
        assert_eq!(
            version_candidates("postgres 16.1", &offered),
            ["postgres 16.10", "postgres 16.4"]
        );
        assert!(version_candidates("postgres 15.2", &offered).is_empty());
    }
}
