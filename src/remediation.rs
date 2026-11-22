//! What to do about each required change, and how sure the tool is about it.
//!
//! `fix`: the change keeps the value the input has today, is valid in the target and
//! touches one property value. `propose`: one documented change exists, but it holds
//! only under a stated precondition or replaces a resource. `flag`: the owner decides.

use serde::{Deserialize, Serialize};

use crate::depth::{DepthCheck, DepthKind, Offered};
use crate::deviation::{Dependency, Deviation};
use crate::extractor::{Hazard, HazardKind, Impact, Literal};
use crate::model::{DecidedBy, DeployEnv};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    Fix,
    Propose,
    Flag,
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::Fix => "fix",
            Tier::Propose => "propose",
            Tier::Flag => "flag",
        }
    }
}

/// What a required change comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CauseType {
    /// The resource is not available in the target.
    Availability,
    /// The ESC User Guide or another AWS page documents the feature as not available.
    Deviation,
    /// Something the resource needs stays outside the target (a dependency rule).
    Dependency,
    /// A property value the target does not offer.
    Depth,
    /// A hardcoded literal.
    Hazard,
    /// More zones than the target offers.
    Zones,
    /// Values written for the input's own environment.
    Environment,
    /// The target account: Region opt-in, quotas, SCPs, public SSM parameters.
    Account,
}

/// `ids` names what fired: hazard kinds, the depth kind, or the guide rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct Cause {
    #[serde(rename = "type")]
    pub kind: CauseType,
    pub ids: Vec<String>,
}

impl Cause {
    pub fn new(kind: CauseType, ids: impl IntoIterator<Item = String>) -> Self {
        let mut ids: Vec<String> = ids.into_iter().collect();
        ids.sort();
        ids.dedup();
        Self { kind, ids }
    }
}

/// The JSON name of an enum value, for `Cause::ids`.
pub fn id(v: impl Serialize) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct RequiredChange {
    pub logical_id: String,
    pub cdk_path: Option<String>,
    pub tier: Tier,
    pub cause: Cause,
    /// For a hardcoded literal: `breaks` when any literal of the change does. Null for
    /// other causes.
    pub impact: Option<Impact>,
    pub decided_by: DecidedBy,
    pub reason: String,
    pub change: String,
    /// What must hold for a proposed change to be right.
    pub precondition: Option<String>,
    pub consequence: Option<String>,
    pub edits: Vec<Edit>,
    /// Values the target offers, for the owner to choose from.
    pub candidates: Vec<String>,
    pub doc: Option<String>,
    /// The change in a few words for the terminal summary. Built from the same
    /// structured data as the change, never parsed from its text.
    #[serde(skip)]
    pub brief: Brief,
}

/// One summary line: what is affected and what to do, both short.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Brief {
    pub what: String,
    pub action: String,
    /// The resource type the line is about, when lines of several types share
    /// `what` and `action` and the summary lists the types instead.
    pub subject: Option<String>,
}

pub fn brief(what: impl Into<String>, action: impl Into<String>) -> Brief {
    Brief {
        what: what.into(),
        action: action.into(),
        subject: None,
    }
}

impl Brief {
    pub fn about(mut self, resource_type: &str) -> Self {
        self.subject = Some(resource_type.into());
        self
    }
}

impl RequiredChange {
    pub fn new(
        logical_id: &str,
        tier: Tier,
        cause: Cause,
        reason: String,
        change: String,
        brief: Brief,
    ) -> Self {
        Self {
            logical_id: logical_id.into(),
            cdk_path: None,
            tier,
            cause,
            impact: None,
            decided_by: DecidedBy::Scanner,
            reason,
            change,
            precondition: None,
            consequence: None,
            edits: Vec::new(),
            candidates: Vec::new(),
            doc: None,
            brief,
        }
    }
}

/// Replace `find` in the string value at `path` with the expression for the source the
/// input was produced from. A CloudFormation expression in `${}` goes into `Fn::Sub`; a
/// zone replacement is the whole value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct Edit {
    pub path: String,
    pub find: String,
    pub replace: Replacement,
}

// Literal rules in `data/rules.json` deserialize into this and reject unknown keys; the
// report schema keeps the object open, as for every other output type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(!deny_unknown_fields)]
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
    /// The target's partition facts, which decide the rules that apply.
    pub facts: Option<&'a crate::extractor::PartitionFacts>,
    /// Live mode's account checks.
    pub account: Option<&'a crate::account::AccountChecks>,
}

struct Decision {
    tier: Tier,
    /// The change in a few words, for the terminal summary.
    action: &'static str,
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

fn region_expr() -> Option<Replacement> {
    rep(
        "${AWS::Region}",
        "${Aws.REGION}",
        "${data.aws_region.current.region}",
    )
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
            action: "build the ARN from the partition",
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
            tier: if all_regional(&h.value, v) {
                Tier::Fix
            } else {
                Tier::Propose
            },
            action: "use the partition DNS suffix",
            change: "Build the host name from the partition's DNS suffix instead of the literal."
                .into(),
            precondition: (!all_regional(&h.value, v)).then_some(
                "The target serves this host without a Region in its name. Most global host names exist only with a Region in other partitions; check the target's endpoints.",
            ),
            replace: rep(
                "${AWS::URLSuffix}",
                "${Aws.URL_SUFFIX}",
                "${data.aws_partition.current.dns_suffix}",
            ),
        },
        // No pseudo parameter gives the dual-stack suffix, and `AWS::URLSuffix` would
        // silently move the client to the IPv4-only endpoint.
        HazardKind::DualStackSuffix => Decision {
            tier: Tier::Flag,
            action: "pass the dual-stack suffix per partition",
            change: format!(
                "No pseudo parameter gives the dual-stack DNS suffix. Pass `{v}` as a parameter or map it per partition, or use the partition DNS suffix if the client does not need IPv6."
            ),
            precondition: None,
            replace: None,
        },
        HazardKind::ServicePrincipal => Decision {
            tier: Tier::Fix,
            action: "use the amazonaws.com principal",
            change: "Use the `amazonaws.com` form of the service principal.".into(),
            precondition: None,
            replace: rep("amazonaws.com", "amazonaws.com", "amazonaws.com"),
        },
        // A hand-written target Region means the Region the stack deploys to.
        HazardKind::RegionLiteral if env.is_none() && l.impact == Impact::Portability => Decision {
            tier: Tier::Fix,
            action: "use the deployment Region",
            change: format!("Use the deployment Region instead of `{v}`."),
            precondition: None,
            replace: region_expr(),
        },
        HazardKind::RegionLiteral => match own(env.and_then(|e| e.region.as_ref())) {
            Tier::Flag => Decision {
                tier: Tier::Flag,
                action: "set the target Region",
                change: format!(
                    "`{v}` is not the Region this resource deploys to, so it refers to something in another Region. Decide what replaces it in the target."
                ),
                precondition: None,
                replace: None,
            },
            tier => Decision {
                tier,
                action: "use the deployment Region",
                change: format!("Use the deployment Region instead of `{v}`."),
                precondition: (tier == Tier::Propose).then_some(
                    "The value means the Region the stack deploys to. The input does not say which Region it was written for.",
                ),
                replace: region_expr(),
            },
        },
        HazardKind::AccountId => match own(env.and_then(|e| e.account.as_ref())) {
            Tier::Flag => Decision {
                tier: Tier::Flag,
                action: "set the target account",
                change: format!(
                    "`{v}` is not the account this resource deploys to. Name the account that has this role in the target partition; for an AWS-owned account, look up its value for the target Region."
                ),
                precondition: None,
                replace: None,
            },
            tier => Decision {
                tier,
                action: "use the deployment account",
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
        HazardKind::AvailabilityZone => zone(l, &h.value, env, ctx),
        HazardKind::ResourceId => Decision {
            tier: Tier::Flag,
            action: "look the resource up in the target",
            change: format!(
                "`{v}` names a resource in one Region and account. Pass it as a parameter or look it up in the target: for an AMI, an SSM public parameter (`{{{{resolve:ssm:/aws/service/...}}}}` in CloudFormation, `data \"aws_ssm_parameter\"` in Terraform). For a CDK lookup, synthesize again for the target."
            ),
            precondition: None,
            replace: None,
        },
        HazardKind::LegacyEndpoint => {
            let rule = l
                .rule
                .as_deref()
                .and_then(|id| crate::rules::all().iter().find(|r| r.id == id));
            // The Region the endpoint names decides the tier, as for a Region literal.
            let region = v.split_once('-').map_or("", |(_, r)| r).to_string();
            let tier = if l.impact == Impact::Portability && env.is_none() {
                Tier::Fix
            } else {
                match env.and_then(|e| e.region.as_ref()) {
                    None => Tier::Propose,
                    Some(r) if *r == region => Tier::Fix,
                    Some(_) => Tier::Flag,
                }
            };
            match rule.and_then(|r| r.replace.as_ref()) {
                Some(r) if tier != Tier::Flag => Decision {
                    tier,
                    action: "use the standard endpoint of the deployment Region",
                    change: format!(
                        "Use the standard endpoint form of the deployment Region instead of `{v}`."
                    ),
                    precondition: (tier == Tier::Propose).then_some(
                        "The endpoint means the Region the stack deploys to. The input does not say which Region it was written for.",
                    ),
                    replace: Some(r.clone()),
                },
                _ => Decision {
                    tier: Tier::Flag,
                    action: "set the endpoint's Region",
                    change: format!(
                        "`{v}` is the legacy form of an endpoint in {region}, which is not the Region this resource deploys to. Decide what replaces it in the target; to keep {region}, use the standard form `s3.{region}`."
                    ),
                    precondition: None,
                    replace: None,
                },
            }
        }
    }
}

/// A zone name `<region><letter>` becomes the zone at the same index in the target,
/// when the target has that many zones and the region is the resource's own.
fn zone(l: &Literal, whole: &str, env: Option<&DeployEnv>, ctx: &Context) -> Decision {
    let v = l.value.as_str();
    let flag = |why: String| Decision {
        tier: Tier::Flag,
        action: "choose a zone in the target",
        change: format!("Choose the zone for `{v}` in the target. {why}"),
        precondition: None,
        replace: None,
    };
    let letter = v.chars().last().filter(char::is_ascii_lowercase);
    let region = &v[..v.len().saturating_sub(1)];
    let Some(letter) = letter.filter(|_| region.ends_with(|c: char| c.is_ascii_digit())) else {
        return flag("A zone ID names one physical zone, and no expression derives it.".into());
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
    // An environment-agnostic CDK stack sees two zones, so `availabilityZones[2]` and
    // later do not exist there.
    macro_rules! with_cdk {
        ($s:literal) => {
            [
                $s,
                concat!(
                    $s,
                    " In CDK, the stack needs an explicit account and Region: without them it lists only two zones."
                ),
            ]
        };
    }
    let by_index = |texts: [&'static str; 2]| Decision {
        tier: Tier::Propose,
        action: "use the target's zone by index",
        change: format!("Use the target's zone at index {i} instead of `{v}`."),
        precondition: Some(texts[usize::from(i >= 2)]),
        replace: rep(
            &format!(r#"{{"Fn::Select": [{i}, {{"Fn::GetAZs": ""}}]}}"#),
            &format!("Stack.of(this).availabilityZones[{i}]"),
            &format!("data.aws_availability_zones.available.names[{i}]"),
        ),
    };
    // A zone of the target itself: the index exists unless the target has fewer zones.
    if l.impact == Impact::Portability && ctx.target_zones.is_none_or(|n| i < n) {
        return by_index(with_cdk!(
            "Any zone of the target serves here. The target's zone list can differ by account, for example CloudFormation lists only zones with a default subnet when any has one, and can change when zones are added, so the index can name another zone than today."
        ));
    }
    match ctx.target_zones {
        None => flag("Run in live mode to compare with the target's zones.".into()),
        Some(n) if i >= n => flag(format!("The target offers {n} zones.")),
        Some(_) => by_index(with_cdk!(
            "Any zone of the target serves here. Zone names are per Region, so the index picks a different physical zone."
        )),
    }
}

/// An AWS principal of another partition in a policy. IAM trust does not cross
/// partitions, so rewriting its ARN would produce a principal that cannot exist.
fn foreign_principal(h: &Hazard) -> Option<RequiredChange> {
    let in_principal = h.path.contains("Principal.AWS") || h.path.ends_with("Principal");
    // With the account built from `AWS::AccountId` the principal is the deployment's
    // own account, and the partition fix is right. A literal account next to another
    // partition's ARN prefix is an account of that partition.
    let has = |k| {
        h.literals
            .iter()
            .any(|l| l.kind == k && l.impact == Impact::Breaks)
    };
    let foreign = has(HazardKind::ArnPartition) && has(HazardKind::AccountId);
    (in_principal && foreign).then(|| {
        let mut c = RequiredChange::new(
            &h.logical_id,
            Tier::Flag,
            Cause::new(CauseType::Hazard, h.literals.iter().map(|l| id(l.kind))),
            format!("principal of another partition at {}", h.path),
            "IAM trust does not cross partitions. Replace the principal with an identity in the target partition, for example a role there or an OIDC provider or IAM Roles Anywhere trust anchor for the caller.".into(),
            brief("principal of another partition", "use an identity in the target partition"),
        );
        c.consequence = Some(
            "Changing only the partition of the ARN produces a principal that does not exist in the target."
                .into(),
        );
        c.impact = Some(Impact::Breaks);
        c
    })
}

/// An Amazon ECR image host. Fixing its DNS suffix points to a registry in the target
/// partition, which holds the image only after the pipeline copies it there.
const ECR_IMAGE_CONSEQUENCE: &str = "The image must exist in an ECR repository in the target partition. ECR replication and pull-through cache do not cross partitions, so copy the image there, by digest, before deploying.";
/// The same for another Region or account of the partition.
const ECR_IMAGE_REGION_CONSEQUENCE: &str = "The image must exist in the ECR repository this resolves to: replicate the repository there (ECR replication works across Regions and accounts of a partition) or push the image there before deploying.";

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
            Cause::new(
                CauseType::Hazard,
                mine.iter()
                    .flat_map(|(l, _)| std::iter::once(id(l.kind)).chain(l.rule.clone())),
            ),
            format!("hardcoded {} at {}", values.join(", "), h.path),
            join_unique(mine.iter().map(|(_, d)| d.change.as_str())),
            brief(
                format!("hardcoded {}", values.join(", ")),
                merge_actions(mine.iter().map(|(_, d)| d.action)),
            ),
        );
        c.impact = mine.iter().map(|(l, _)| l.impact).min();
        let pre = join_unique(mine.iter().filter_map(|(_, d)| d.precondition));
        c.precondition = (!pre.is_empty()).then_some(pre);
        if h.value.contains(".dkr.ecr.") {
            let has = |k| {
                mine.iter()
                    .any(|(l, _)| l.kind == k && l.impact == Impact::Breaks)
            };
            if has(HazardKind::DnsSuffix) {
                c.consequence = Some(ECR_IMAGE_CONSEQUENCE.into());
            } else if has(HazardKind::RegionLiteral) || has(HazardKind::AccountId) {
                c.consequence = Some(ECR_IMAGE_REGION_CONSEQUENCE.into());
            }
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

/// Short actions joined; a shared leading phrase is said once: "use the deployment
/// Region" and "use the deployment account" become "use the deployment Region and
/// account".
fn merge_actions<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    let seen = crate::report::unique(parts);
    if seen.len() < 2 {
        return seen.join("");
    }
    let words: Vec<Vec<&str>> = seen.iter().map(|s| s.split(' ').collect()).collect();
    let mut common = 0;
    while words
        .iter()
        .all(|w| w.len() > common + 1 && w[common] == words[0][common])
    {
        common += 1;
    }
    if common == 0 {
        return seen.join("; ");
    }
    let rests: Vec<String> = words.iter().map(|w| w[common..].join(" ")).collect();
    format!("{} {}", words[0][..common].join(" "), rests.join(" and "))
}

fn join_unique<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    let seen = crate::report::unique(parts);
    seen.join(" ")
}

pub fn deviation(d: &Deviation, ctx: &Context) -> RequiredChange {
    let by = match d.decided_by {
        DecidedBy::Guide => "the ESC User Guide",
        _ => "AWS",
    };
    let reason = format!(
        "{} uses a feature {by} documents as different: \"{}\" ({})",
        d.resource_type, d.documented, d.source
    );
    let what = d.rule.replace('-', " ");
    let cause = Cause::new(CauseType::Deviation, [d.rule.clone()]);
    // ESC substitutes hold where the target has a single Region; other rules state
    // their own scope.
    let usable = ctx.single_region || d.decided_by != DecidedBy::Guide;
    match d.remediation.as_ref().filter(|_| usable) {
        Some(m) => {
            let mut c = RequiredChange::new(
                &d.logical_id,
                Tier::Propose,
                cause,
                reason,
                m.change.clone(),
                brief(what, m.action.clone()).about(&d.resource_type),
            );
            c.consequence = Some(m.consequence.clone());
            c.doc = Some(m.doc.clone());
            c
        }
        None => {
            let mut c = RequiredChange::new(
                &d.logical_id,
                Tier::Flag,
                cause,
                reason,
                "Decide how to remove or replace the feature in the target.".into(),
                brief(what, "remove or replace the feature").about(&d.resource_type),
            );
            c.doc = Some(d.source.clone());
            c
        }
    }
}

pub fn dependency(d: &Dependency) -> RequiredChange {
    let reason = format!(
        "{} has a dependency AWS documents: \"{}\" ({})",
        d.resource_type, d.documented, d.source
    );
    let what = d.rule.replace('-', " ");
    let cause = Cause::new(CauseType::Dependency, [d.rule.clone()]);
    let m = d
        .remediation
        .as_ref()
        .expect("dependency rules state the change");
    let mut c = RequiredChange::new(
        &d.logical_id,
        Tier::Flag,
        cause,
        reason,
        m.change.clone(),
        brief(what, m.action.clone()).about(&d.resource_type),
    );
    c.consequence = Some(m.consequence.clone());
    c.doc = Some(m.doc.clone());
    c
}

/// Required changes from the account checks that fail.
pub fn account(a: &crate::account::AccountChecks, target_region: &str) -> Vec<RequiredChange> {
    let mut out = Vec::new();
    let flag = |id: &str, cause: &str, reason: String, change: String, short| {
        let mut c = RequiredChange::new(
            id,
            Tier::Flag,
            Cause::new(CauseType::Account, [cause.to_string()]),
            reason,
            change,
            short,
        );
        c.decided_by = DecidedBy::Live;
        c
    };
    if a.region_opt_in.as_deref() == Some("not-opted-in") {
        out.push(flag(
            "*",
            "region-opt-in",
            format!("{target_region} is an opt-in Region that is not enabled for the account"),
            "Enable the Region for the account before deploying.".into(),
            brief("Region not enabled", "enable the Region"),
        ));
    }
    for q in a.quotas.iter().filter(|q| q.exceeded) {
        let mut c = flag(
            "*",
            &q.rule,
            format!(
                "the input alone needs {} of {} ({} {}), the account's {} quota in {target_region} is {}",
                q.needed,
                q.name,
                q.service_code,
                q.quota_code,
                id(q.value_source),
                q.quota
            ),
            "Request a quota increase in the target account before deploying, or reduce what the input needs.".into(),
            brief(format!("{} quota too low", q.name), "request a quota increase"),
        );
        c.doc = Some(q.doc.clone());
        out.push(c);
    }
    for p in a
        .scp
        .iter()
        .flat_map(|s| &s.policies)
        .filter(|p| p.verdict == crate::account::ScpVerdict::DeniesTarget)
    {
        out.push(flag(
            "*",
            "scp",
            format!(
                "the service control policy {} ({}) denies requests to {target_region}{}",
                p.name,
                p.id,
                if p.conditional {
                    " unless its further conditions exempt the request"
                } else {
                    ""
                }
            ),
            "Ask the organization's administrators to allow the target Region for the account."
                .into(),
            brief("SCP denies the Region", "have the SCP allow the Region"),
        ));
    }
    for p in a.ssm_parameters.iter().filter(|p| !p.exists) {
        for id in &p.used_by {
            out.push(flag(
                id,
                "ssm-parameter",
                format!(
                    "the public parameter {} does not exist in {target_region}",
                    p.name
                ),
                "Choose a public parameter the target offers, or pass the value as a parameter."
                    .into(),
                brief("SSM parameter missing", "choose a parameter the Region has"),
            ));
        }
    }
    out
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
    let what = format!("{} `{}` not offered", kind_label(d.kind), d.value);
    let cause = Cause::new(CauseType::Depth, [id(d.kind)]);
    if d.kind == DepthKind::Property {
        let mut c = RequiredChange::new(
            logical_id,
            Tier::Flag,
            cause,
            format!(
                "property `{}` is not in the CloudFormation schema of the resource type in {target_region}",
                d.value
            ),
            "Remove the property, or keep the resource out of the target until its CloudFormation schema there has it.".into(),
            brief(what, "remove the property"),
        );
        c.consequence =
            Some("The feature the property configures is not set in the target.".into());
        return c;
    }
    let set = ctx.offered.and_then(|o| o.get(&d.kind));
    let (candidates, consequence) = match (d.kind, set) {
        (DepthKind::InstanceType, Some(s)) => (
            instance_candidates(&d.value, s),
            "Price and performance differ between instance families.",
        ),
        (k, Some(s)) if k.is_engine() => (
            version_candidates(&d.value, s),
            "Versions differ in features and fixes; test the application against the chosen one.",
        ),
        _ => (Vec::new(), ""),
    };
    if candidates.is_empty() {
        return RequiredChange::new(
            logical_id,
            Tier::Flag,
            cause,
            reason,
            "Choose a value the target region offers.".into(),
            brief(what, "choose a value the region offers"),
        );
    }
    let mut c = RequiredChange::new(
        logical_id,
        Tier::Propose,
        cause,
        reason,
        "Choose one of the candidates the target offers.".into(),
        brief(what, format!("choose one of {} offered", candidates.len())),
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
        DepthKind::CacheNodeType => "ElastiCache node type",
        DepthKind::NeptuneEngineVersion => "Neptune engine version",
        DepthKind::DocumentDbEngineVersion => "DocumentDB engine version",
        DepthKind::RedshiftNodeType => "Redshift node type",
        DepthKind::Property => "property",
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

/// Every host in `value` that ends in `suffix` has a Region label. One edit replaces
/// the suffix in all of them, so a single global host makes the change a proposal.
fn all_regional(value: &str, suffix: &str) -> bool {
    let hosts: Vec<&str> = value
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        // A fully qualified name such as a Route 53 record value ends in a dot.
        .map(|t| t.trim_end_matches('.'))
        .filter(|t| t.ends_with(suffix))
        .collect();
    !hosts.is_empty() && hosts.iter().all(|h| has_region_label(h))
}

/// A DNS label shaped like a Region id, such as `eu-central-1`.
fn has_region_label(host: &str) -> bool {
    // The legacy S3 form `s3-us-west-2` carries its Region after the service name.
    let labels = host
        .split(['.', '/', ':'])
        .flat_map(|l| std::iter::once(l).chain(l.strip_prefix("s3-")));
    labels.into_iter().any(|label| {
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

    #[test]
    fn merged_actions_say_the_shared_phrase_once() {
        let m = |p: &[&str]| merge_actions(p.iter().copied());
        assert_eq!(
            m(&["use the deployment Region", "use the deployment account"]),
            "use the deployment Region and account"
        );
        assert_eq!(m(&["use a x", "use a y", "use a z"]), "use a x and y and z");
        assert_eq!(m(&["a b", "c d"]), "a b; c d");
    }

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

    #[test]
    fn ecr_image_in_another_region_says_the_image_must_be_replicated() {
        let mut portable = lit(HazardKind::DnsSuffix, "amazonaws.com");
        portable.impact = Impact::Portability;
        let c = at(
            "Properties.ContainerDefinitions[0].Image",
            "111122223333.dkr.ecr.eu-central-1.amazonaws.com/app:1",
            vec![portable, lit(HazardKind::RegionLiteral, "eu-central-1")],
        );
        let consequence = |t| {
            c.iter()
                .find(|c| c.tier == t)
                .and_then(|c| c.consequence.clone())
        };
        assert_eq!(
            consequence(Tier::Fix),
            None,
            "the suffix is right for the target"
        );
        assert!(
            consequence(Tier::Propose)
                .unwrap()
                .contains("replicate the repository")
        );
    }

    /// A literal of another Region or partition, as in an ESC scan of global input.
    fn lit(kind: HazardKind, value: &str) -> Literal {
        Literal {
            kind,
            value: value.into(),
            impact: Impact::Breaks,
            rule: None,
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
    fn the_target_region_typed_by_hand_is_a_fix() {
        let own = Literal {
            impact: Impact::Portability,
            ..lit(HazardKind::RegionLiteral, "eu-west-1")
        };
        assert_eq!(tiers(vec![own], None, &Context::default()), [Tier::Fix]);
    }

    #[test]
    fn a_principal_of_the_target_partition_keeps_the_partition_fix() {
        let c = at(
            "Properties.AssumeRolePolicyDocument.Statement[0].Principal.AWS",
            "arn:aws:iam::111122223333:root",
            [HazardKind::ArnPartition, HazardKind::AccountId]
                .into_iter()
                .zip(["arn:aws:", "111122223333"])
                .map(|(k, v)| Literal {
                    impact: Impact::Portability,
                    ..lit(k, v)
                })
                .collect(),
        );
        assert!(c.iter().any(|c| c.tier == Tier::Fix), "{c:?}");
        assert!(c.iter().all(|c| c.cause.kind == CauseType::Hazard));
        assert!(c.iter().all(|c| c.impact == Some(Impact::Portability)));
    }

    #[test]
    fn a_zone_of_the_target_is_proposed_by_index_without_live_mode() {
        let own = Literal {
            impact: Impact::Portability,
            ..lit(HazardKind::AvailabilityZone, "eu-west-1b")
        };
        let c = tiers(vec![own], None, &Context::default());
        assert_eq!(c, [Tier::Propose]);
        let past = Literal {
            impact: Impact::Portability,
            ..lit(HazardKind::AvailabilityZone, "eu-west-1d")
        };
        let three = Context {
            target_zones: Some(3),
            ..Context::default()
        };
        assert_eq!(tiers(vec![past], None, &three), [Tier::Flag]);
        let pre = |zone: &str| {
            let own = Literal {
                impact: Impact::Portability,
                ..lit(HazardKind::AvailabilityZone, zone)
            };
            at("Properties.AvailabilityZone", zone, vec![own])[0]
                .precondition
                .clone()
                .unwrap()
        };
        assert!(!pre("eu-west-1b").contains("CDK"));
        assert!(pre("eu-west-1c").contains("only two zones"));
        let id = Literal {
            impact: Impact::Breaks,
            ..lit(HazardKind::AvailabilityZone, "euw1-az1")
        };
        assert_eq!(tiers(vec![id], None, &Context::default()), [Tier::Flag]);
    }

    #[test]
    fn a_global_host_next_to_a_regional_one_makes_the_suffix_a_proposal() {
        let d = || vec![lit(HazardKind::DnsSuffix, "amazonaws.com")];
        let tier = |value: &str| at("Properties.X", value, d())[0].tier;
        assert_eq!(tier("sqs.eu-west-1.amazonaws.com/q"), Tier::Fix);
        assert_eq!(tier("sqs.eu-west-1.amazonaws.com."), Tier::Fix);
        assert_eq!(tier("s3.us-east-1.amazonaws.com"), Tier::Fix);
        assert_eq!(
            tier("s3.amazonaws.com/x sqs.eu-west-1.amazonaws.com/y"),
            Tier::Propose
        );
        assert_eq!(tier("sts.amazonaws.com"), Tier::Propose);
    }

    #[test]
    fn resource_ids_and_legacy_endpoints_get_their_tier() {
        let c = at(
            "Properties.ImageId",
            "ami-0123456789abcdef0",
            vec![lit(HazardKind::ResourceId, "ami-0123456789abcdef0")],
        );
        assert_eq!(c[0].tier, Tier::Flag);
        assert!(c[0].change.contains("{{resolve:ssm:/aws/service/"));
        let dash = Literal {
            rule: Some("s3-dash-region-endpoint".into()),
            ..lit(HazardKind::LegacyEndpoint, "s3-us-west-2")
        };
        let c = at(
            "Properties.U",
            "b.s3-us-west-2.amazonaws.com",
            vec![dash.clone()],
        );
        assert_eq!(
            c[0].tier,
            Tier::Propose,
            "the input does not say its Region"
        );
        assert_eq!(c[0].edits[0].replace.cloudformation, "s3.${AWS::Region}");
        assert!(
            c[0].cause
                .ids
                .contains(&"s3-dash-region-endpoint".to_string())
        );
        let elsewhere = tiers(
            vec![dash.clone()],
            Some(env("eu-west-1", None)),
            &Context::default(),
        );
        assert_eq!(
            elsewhere,
            [Tier::Flag],
            "a bucket in another Region is a decision"
        );
        let own = Literal {
            impact: Impact::Portability,
            ..dash
        };
        assert_eq!(tiers(vec![own], None, &Context::default()), [Tier::Fix]);
        // The suffix of a dash-Region host is regional, so its edit stays a fix.
        let suffix = || vec![lit(HazardKind::DnsSuffix, "amazonaws.com")];
        let c = at("Properties.U", "b.s3-us-west-2.amazonaws.com", suffix());
        assert_eq!(c[0].tier, Tier::Fix);
        let c = at("Properties.U", "s3-logs.s3.amazonaws.com", suffix());
        assert_eq!(c[0].tier, Tier::Propose, "a bucket name is no Region label");
    }

    #[test]
    fn a_dual_stack_suffix_is_flagged_not_rewritten_to_ipv4() {
        let c = at(
            "Properties.Url",
            "sqs.eu-west-1.api.aws",
            vec![lit(HazardKind::DualStackSuffix, "api.aws")],
        );
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].tier, Tier::Flag);
        assert!(c[0].edits.is_empty());
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

    fn dev(remediation: bool) -> Deviation {
        Deviation {
            logical_id: "T".into(),
            resource_type: "AWS::DynamoDB::GlobalTable".into(),
            rule: "dynamodb-global-tables".into(),
            documented: "Global Tables and Cross-Region Restore".into(),
            source: "https://docs.aws.eu/esc/latest/userguide/dynamodb.html".into(),
            decided_by: crate::model::DecidedBy::Guide,
            severity: crate::deviation::Severity::Blocker,
            feature: None,
            conflict: None,
            remediation: remediation.then(|| crate::deviation::RuleRemediation {
                action: "use a table".into(),
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
