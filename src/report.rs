//! The JSON report and its human-readable summary.

use serde::Serialize;

use crate::depth::DepthSource;
use crate::deviation::{
    Dependency, Deviation, Documented, GuideFindings, GuideProvenance, Severity,
};
use crate::extractor::{EnvLiterals, Scan};
use crate::matcher::{Finding, Verdict};
use crate::model::{DecidedBy, DeployEnv, OutOfScope, SourceFormat};
use crate::provider::knowledge::State;
use crate::provider::live::LiveProvenance;
use crate::remediation::{self, Cause, CauseType, Context, RequiredChange, Tier};

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct TerraformProvenance {
    pub aws_provider_version: String,
    pub awscc_provider_version: String,
}

#[derive(Debug, Clone)]
pub struct KnowledgeProvenance {
    /// Where products, services and APIs came from: the AWS Knowledge MCP server, or the
    /// AWS SDK endpoint data for China.
    pub url: String,
    /// Where the CloudFormation types and config values came from: the Builder Center
    /// capabilities API, the Knowledge MCP server when the API failed, or the Region's
    /// schema bundle for China.
    pub cloudformation_url: String,
    /// Where the product and roadmap states came from: the capabilities API, with the
    /// Knowledge MCP server for the not-expanding state, or the Knowledge MCP server
    /// alone when the API failed. Null for China, which publishes none.
    pub products_url: Option<String>,
    /// Types, services or operations the sources do not know.
    pub unknown: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Provenance {
    pub tool_version: String,
    /// The input as named on the command line, `.` or `stdin`.
    pub input: String,
    /// Stacks of a CDK assembly or template, by the stack prefixes of the ids.
    pub stacks: usize,
    pub source_format: SourceFormat,
    pub input_kind: crate::model::InputKind,
    pub target_region: String,
    /// The account the input moves to, when `--account` is given.
    pub target_account: Option<String>,
    /// Where the input was synthesized (CDK cloud assembly) or planned (Terraform).
    pub input_environments: Vec<DeployEnv>,
    /// botocore release of the bundled partition data.
    pub partitions_version: String,
    /// The public availability data; null when no public source covers the target, so
    /// live mode decides alone.
    pub knowledge: Option<KnowledgeProvenance>,
    /// ESC User Guide service pages, when the target is in its partition.
    pub user_guide: Option<GuideProvenance>,
    /// When the public data was fetched; `live.fetched_at` is when the account was read.
    pub fetched_at: String,
    pub terraform: Option<TerraformProvenance>,
    pub live: Option<LiveProvenance>,
    /// The target's CloudFormation resource schemas the property checks read. Null when
    /// none were read: the input has no CloudFormation resource types, or the target
    /// publishes no schema bundle and live mode is off.
    pub schemas: Option<crate::provider::schema::SchemaProvenance>,
    /// CloudFormation resource types in the input, for the unchecked-properties warning.
    pub schema_types: usize,
    /// Live mode was refused `cloudformation:DescribeType`.
    pub schema_denied: bool,
    /// Macros in the template's `Transform`, which skip the property checks.
    pub macros: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, schemars::JsonSchema)]
pub struct Summary {
    pub resources: usize,
    pub available: usize,
    pub not_available: usize,
    pub disputed: usize,
    pub cannot_assess: usize,
    /// Findings whose product has a planned launch quarter.
    pub planned: usize,
    /// Property values with a hardcoded hazard; each is one place to fix.
    pub hazards: usize,
    /// Hazards with a literal that breaks in the target, and hazards whose literals
    /// only tie the input to one Region or account; together `hazards`.
    pub hazards_breaking: usize,
    pub hazards_portability: usize,
    /// Property values written for the input's own environment (see
    /// `run.input_environments`).
    pub environment_literal_places: usize,
    pub divergences: usize,
    /// Depth checks whose value the target region does not offer, plus a zone
    /// shortfall.
    pub depth_blockers: usize,
    /// Account checks that block deployment (see `account`).
    pub account_blockers: usize,
    /// Resources that use a feature the ESC User Guide or another AWS page documents as
    /// not available.
    pub deviation_blockers: usize,
    /// Guide restrictions the public availability data contradicts; warnings, not blockers.
    pub guide_conflicts: usize,
    /// Features that work with a documented difference.
    pub caveats: usize,
    /// Documented dependencies outside the target, one per resource and rule.
    pub dependencies: usize,
    /// Required changes by tier: applied as stated, applied after a yes, owner decides.
    pub fixes: usize,
    pub proposals: usize,
    pub flags: usize,
}

/// The input spreads over more zones of its own environment than the target offers.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ZoneCheck {
    pub used: Vec<String>,
    pub target_offers: usize,
}

/// What `--fail-on` decides, per category, from the summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct Outcome {
    /// Not available, a depth value the target does not offer, a feature the ESC
    /// User Guide or another AWS page documents as not available, or an account check
    /// that fails.
    pub blocker: bool,
    /// A hardcoded literal, an environment literal or a documented dependency.
    pub hazard: bool,
    /// A disputed or cannot-assess finding, or a guide conflict.
    pub disputed: bool,
}

impl Outcome {
    pub fn of(s: &Summary) -> Self {
        Self {
            blocker: s.depth_blockers + s.deviation_blockers + s.not_available + s.account_blockers
                > 0,
            hazard: s.hazards + s.environment_literal_places + s.dependencies > 0,
            disputed: s.disputed + s.cannot_assess + s.guide_conflicts > 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum WarningCode {
    /// The input was produced for another Region than the target.
    InputRegionMismatch,
    /// The public availability data does not know some types, services or operations.
    PublicDataUnknown,
    /// No public availability data covers the target; live mode decides alone.
    PublicDataRegionUnlisted,
    /// No source answered for instance types, engine versions or node types the input
    /// sets (AWS China publishes none), so they were not checked.
    ValuesUnchecked,
    /// The ESC User Guide and the public availability data disagree.
    GuideConflict,
    /// Rules matched, but the guide no longer contains their sentence.
    StaleRules,
    /// No schema of the target was read, so properties were not checked.
    PropertiesUnchecked,
    /// Live mode could not run some account checks.
    AccountChecksSkipped,
}

/// A run-level condition. `code` is stable and `message` is prose for people;
/// `items` names what the condition is about (types, values, rule ids, Regions).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct Warning<C> {
    pub code: C,
    pub message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<String>,
}

impl<C> Warning<C> {
    pub fn new(code: C, message: String, items: Vec<String>) -> Self {
        Self {
            code,
            message,
            items,
        }
    }
}

/// The scan in memory. The terminal summary reads it as it is; `output::scan` shapes
/// the JSON from it.
#[derive(Debug, Clone)]
pub struct Report {
    pub data_provenance: Provenance,
    pub summary: Summary,
    pub outcome: Outcome,
    pub findings: Vec<Finding>,
    /// The hazards and dependencies behind the required changes; the tests read them.
    #[cfg_attr(not(test), allow(dead_code))]
    pub hazards: Vec<crate::extractor::Hazard>,
    pub deviations: Vec<Deviation>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub dependencies: Vec<Dependency>,
    /// Differences the ESC User Guide documents for the services in the input.
    pub documented_differences: Vec<Documented>,
    pub environment_literals: Vec<EnvLiterals>,
    pub required_changes: Vec<RequiredChange>,
    /// Terraform resources of providers other than aws and awscc.
    pub out_of_scope: Vec<OutOfScope>,
    /// Live mode's checks of the target account; null in public mode.
    pub account: Option<crate::account::AccountChecks>,
    pub warnings: Vec<Warning<WarningCode>>,
    /// For a warning that carries a command: its index, the prose without the
    /// command, and the command, so the terminal shows the command on its own line.
    /// The JSON warning has both in one message.
    pub warning_commands: Vec<(usize, String, String)>,
}

pub fn build(
    provenance: Provenance,
    mut findings: Vec<Finding>,
    scan: Scan,
    guide: GuideFindings,
    out_of_scope: Vec<OutOfScope>,
    ctx: &Context,
) -> Report {
    let target = provenance.target_region.clone();
    findings.sort_by(|a, b| a.logical_id.cmp(&b.logical_id));
    let Scan {
        mut hazards,
        env_literals,
    } = scan;
    // A resource that is not available at all is removed or rebuilt, not edited.
    let gone: std::collections::BTreeSet<&str> = findings
        .iter()
        .filter(|f| f.verdict == Verdict::NotAvailable)
        .map(|f| f.logical_id.as_str())
        .collect();
    hazards.retain(|h| !gone.contains(h.logical_id.as_str()));
    let mut s = Summary {
        resources: findings.len(),
        hazards: hazards.len(),
        hazards_breaking: hazards.iter().filter(|h| breaks(h)).count(),
        hazards_portability: hazards.iter().filter(|h| !breaks(h)).count(),
        environment_literal_places: env_literals.iter().map(|e| e.places).sum(),
        deviation_blockers: guide.deviations.iter().filter(|d| d.blocks()).count(),
        guide_conflicts: guide
            .deviations
            .iter()
            .filter(|d| d.conflict.is_some())
            .count(),
        caveats: guide
            .deviations
            .iter()
            .filter(|d| d.severity == Severity::Caveat)
            .count(),
        dependencies: guide.dependencies.len(),
        ..Summary::default()
    };
    let mut changes = Vec::new();
    for f in &findings {
        if f.roadmap
            .as_ref()
            .is_some_and(|r| r.status == State::Planned)
        {
            s.planned += 1;
        }
        match &f.verdict {
            Verdict::Available => s.available += 1,
            Verdict::NotAvailable => s.not_available += 1,
            Verdict::Disputed => s.disputed += 1,
            Verdict::CannotAssess => s.cannot_assess += 1,
        }
        if f.divergence {
            s.divergences += 1;
        }
        for d in f
            .depth
            .iter()
            .filter(|d| d.offered == Some(false) && !gone.contains(f.logical_id.as_str()))
        {
            s.depth_blockers += 1;
            changes.push(remediation::depth(&f.logical_id, d, &target, ctx));
        }
        if f.verdict == Verdict::NotAvailable {
            changes.push(availability_change(f, &target, ctx));
        }
    }
    changes.extend(
        guide
            .deviations
            .iter()
            .filter(|d| d.blocks())
            .map(|d| remediation::deviation(d, ctx)),
    );
    changes.extend(guide.dependencies.iter().map(remediation::dependency));
    changes.extend(hazards.iter().flat_map(|h| remediation::hazard(h, ctx)));
    let used: Vec<String> = env_literals
        .iter()
        .flat_map(|e| e.zones.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let zones = ctx
        .target_zones
        .filter(|n| used.len() > *n)
        .map(|n| ZoneCheck {
            used,
            target_offers: n,
        });
    if let Some(z) = &zones {
        s.depth_blockers += 1;
        changes.push(RequiredChange::new(
            "*",
            Tier::Flag,
            Cause::new(CauseType::Zones, []),
            format!(
                "the input uses {} zones ({}); {target} offers {}",
                z.used.len(),
                z.used.join(", "),
                z.target_offers
            ),
            "Size the zone count from the target region (for example a slice over the available zones bounded by their number) instead of a fixed count.".into(),
            remediation::brief(
                format!("{} zones used, {} offered", z.used.len(), z.target_offers),
                "size the zone count from the region",
            ),
        ));
    }
    let (resynth, produced, produce, retarget) = match provenance.source_format {
        SourceFormat::Cloudformation => (
            "synthesize again for",
            "synthesized",
            "Synthesize",
            "Set the CDK stack environment to the target account and Region, or remove it to make the stack environment-agnostic, and synthesize again. These values then change together.",
        ),
        SourceFormat::TerraformPlan => (
            "plan again for",
            "planned",
            "Plan",
            "Set the provider Region to the target Region and plan again with credentials for the target account. These values then change together.",
        ),
    };
    if let Some(a) = ctx.account {
        s.account_blockers = a.blockers();
        changes.extend(remediation::account(a, &target));
    }
    for e in &env_literals {
        let mut c = RequiredChange::new(
            "*",
            Tier::Propose,
            Cause::new(CauseType::Environment, []),
            format!(
                "{} property values were written for {} by synthesis or planning, not by hand",
                e.places,
                env_label(&e.env)
            ),
            retarget.into(),
            remediation::brief(
                format!(
                    "{} values {produced} for {}",
                    e.places,
                    e.env.region.as_deref().unwrap_or("its environment")
                ),
                format!("{resynth} {}", provenance.target_region),
            ),
        );
        c.precondition = Some("The account the input deploys to in the target is known.".into());
        changes.push(c);
    }
    for c in &mut changes {
        let finding = findings.iter().find(|f| f.logical_id == c.logical_id);
        c.cdk_path = finding.and_then(|f| f.cdk_path.clone());
        c.decided_by = decided_by(c, finding, &guide);
        if c.cause.kind != CauseType::Hazard && c.resource_type.is_none() {
            c.resource_type = finding.map(|f| f.resource_type.clone());
        }
        if c.cause.kind == CauseType::Availability {
            c.roadmap = finding.and_then(|f| f.roadmap.clone());
        }
        if matches!(c.cause.kind, CauseType::Availability | CauseType::Deviation)
            && let Some(f) = finding
        {
            let partition = ctx
                .facts
                .map(|p| p.target_partition.as_str())
                .unwrap_or_default();
            // A whole-service substitute answers an unavailable type; a feature gap is
            // answered only by mitigations for its rule.
            let t = crate::sam::base_type(&f.resource_type).unwrap_or(&f.resource_type);
            let t = (c.cause.kind == CauseType::Availability).then_some(t);
            c.mitigations = crate::mitigations::find(t, &c.cause.ids, partition);
        }
        match c.tier {
            Tier::Fix => s.fixes += 1,
            Tier::Propose => s.proposals += 1,
            Tier::Flag => s.flags += 1,
        }
    }
    let open: Vec<(&Finding, &crate::depth::DepthCheck)> = findings
        .iter()
        .flat_map(|f| f.depth.iter().map(move |d| (f, d)))
        .filter(|(_, d)| d.offered.is_none() && crate::depth::is_public(d.kind))
        .collect();
    let label = |f: &Finding, d: &crate::depth::DepthCheck| {
        format!(
            "{} {}",
            crate::output::property_path(&f.resource_type, &d.path),
            d.value
        )
    };
    let unchecked: Vec<String> = unique(open.iter().map(|(f, d)| label(f, d)));
    // The values live mode can check; it probes only some kinds.
    let probed: Vec<String> = unique(
        open.iter()
            .filter(|(_, d)| crate::depth::live_probes(d.kind))
            .map(|(f, d)| label(f, d)),
    );
    let (warnings, warning_commands) =
        warnings(&provenance, &guide, ctx, produce, &unchecked, &probed);
    Report {
        data_provenance: provenance,
        outcome: Outcome::of(&s),
        summary: s,
        findings,
        hazards,
        deviations: guide.deviations,
        dependencies: guide.dependencies,
        documented_differences: guide.documented,
        environment_literals: env_literals,
        required_changes: changes,
        out_of_scope,
        account: ctx.account.cloned(),
        warnings,
        warning_commands,
    }
}

fn breaks(h: &crate::extractor::Hazard) -> bool {
    h.literals
        .iter()
        .any(|l| l.impact == crate::extractor::Impact::Breaks)
}

fn availability_change(f: &Finding, target: &str, ctx: &Context) -> RequiredChange {
    // Without a known service (a type only the live registry knows), the line names the
    // type instead.
    let svc = f
        .service
        .as_deref()
        .unwrap_or("the resource type's service");
    let custom = f.resource_type.starts_with("Custom::");
    let type_gap = f.type_gap && !custom;
    let short = if custom {
        remediation::brief(
            format!("custom resource calls {svc}"),
            format!("remove or replace {svc}"),
        )
    } else if type_gap || f.service.is_none() {
        let what = match f.resource_type.split("::").nth(1) {
            Some(ns) => format!("{ns} type missing in CloudFormation"),
            None => "resource type missing in CloudFormation".into(),
        };
        let substitute = ctx
            .facts
            .filter(|_| ctx.single_region)
            .and_then(|facts| crate::deviation::substitute_for(&f.resource_type, facts))
            .map(|m| m.action);
        remediation::brief(
            what,
            substitute
                .unwrap_or_else(|| "use another type or deploy it without CloudFormation".into()),
        )
    } else if let Some(rm) = &f.roadmap {
        // The product's own name reads better than the service key.
        let name = rm.product.as_str();
        remediation::brief(
            format!("{name} {}", rm.short()),
            match (&rm.status, &rm.launch) {
                (State::Planned, Some(q)) => format!("replace {name} or wait for {q}"),
                _ => format!("remove or replace {name}"),
            },
        )
    } else {
        let name = f.resource_type.split("::").nth(1).unwrap_or(svc);
        remediation::brief(
            format!("{name} not available"),
            format!("remove or replace {name}"),
        )
    }
    .about(&f.resource_type);
    RequiredChange::new(
        &f.logical_id,
        Tier::Flag,
        Cause::new(CauseType::Availability, []),
        match (&f.service, custom) {
            (Some(svc), true) => format!(
                "{} calls {svc}, which is not available in {target}",
                f.resource_type
            ),
            _ => format!("{} is not available in {target}", f.resource_type),
        },
        f.note.clone().unwrap_or_default(),
        short,
    )
}

fn decided_by(c: &RequiredChange, finding: Option<&Finding>, guide: &GuideFindings) -> DecidedBy {
    match c.cause.kind {
        CauseType::Availability => finding.map_or(DecidedBy::Scanner, |f| f.decided_by),
        CauseType::Deviation => guide
            .deviations
            .iter()
            .find(|d| d.logical_id == c.logical_id && c.cause.ids.contains(&d.rule))
            .map_or(DecidedBy::Rule, |d| d.decided_by),
        CauseType::Depth => finding
            .and_then(|f| {
                f.depth
                    .iter()
                    .filter(|d| d.offered == Some(false))
                    .find(|d| c.cause.ids.contains(&remediation::id(d.kind)))
            })
            .and_then(|d| d.source)
            .map_or(DecidedBy::Public, |s| match s {
                DepthSource::Public => DecidedBy::Public,
                DepthSource::Live => DecidedBy::Live,
                DepthSource::Schema => DecidedBy::Schema,
            }),
        CauseType::Dependency => DecidedBy::Rule,
        CauseType::Zones | CauseType::Account => DecidedBy::Live,
        CauseType::Hazard | CauseType::Environment => DecidedBy::Scanner,
    }
}

/// For a warning that carries a command: its index, the prose and the command.
type WarningCommands = Vec<(usize, String, String)>;

/// The report's warnings, and the commands split from them for the terminal.
fn warnings(
    prov: &Provenance,
    guide: &GuideFindings,
    ctx: &Context,
    produce: &str,
    unchecked: &[String],
    probed: &[String],
) -> (Vec<Warning<WarningCode>>, WarningCommands) {
    let target = &prov.target_region;
    let mut warnings: Vec<Warning<WarningCode>> = Vec::new();
    let mut warn = |code, message: String, items: Vec<String>| {
        let w = Warning::new(code, message, items);
        let new = !warnings.contains(&w);
        if new {
            warnings.push(w);
        }
        new.then(|| warnings.len() - 1)
    };
    if prov.knowledge.is_none() {
        warn(
            WarningCode::PublicDataRegionUnlisted,
            format!(
                "No public availability data covers {target}, so the verdicts come from live mode alone, without roadmap states."
            ),
            vec![target.clone()],
        );
    }
    if !unchecked.is_empty() {
        warn(
            WarningCode::ValuesUnchecked,
            format!(
                "No source says whether {target} offers {}, so these values were not checked.{}",
                unchecked.join(", "),
                if prov.live.is_some() || probed.is_empty() {
                    " Check them in the target before you deploy.".to_string()
                } else if probed.len() == unchecked.len() {
                    " Run in live mode to check them in the account.".to_string()
                } else {
                    format!(
                        " Run in live mode to check {} in the account, and check the others in the target before you deploy.",
                        probed.join(", ")
                    )
                }
            ),
            unchecked.to_vec(),
        );
    }
    let mut warning_commands = Vec::new();
    for region in prov
        .input_environments
        .iter()
        .filter_map(|e| e.region.as_ref())
        .filter(|r| **r != prov.target_region)
    {
        // Only a CDK cloud assembly states an environment for CloudFormation input.
        let cmd = (prov.source_format == SourceFormat::Cloudformation)
            .then(|| format!("AWS_REGION={target} cdk synth"));
        let how = cmd
            .as_ref()
            .map(|c| format!(" {CDK_HINT} {c}"))
            .unwrap_or_default();
        let prose = format!(
            "The input was produced for {region}, not {target}. {produce} it for the target region so region-specific values resolve as they will be deployed."
        );
        if let (Some(i), Some(c)) = (
            warn(
                WarningCode::InputRegionMismatch,
                format!("{prose}{how}"),
                vec![region.clone()],
            ),
            cmd,
        ) {
            warning_commands.push((i, prose, c));
        }
    }
    if let Some(k) = prov.knowledge.as_ref().filter(|k| !k.unknown.is_empty()) {
        warn(
            WarningCode::PublicDataUnknown,
            format!(
                "The public availability data does not know {}; only live mode can assess these resources.",
                k.unknown.join(", ")
            ),
            k.unknown.clone(),
        );
    }
    let conflicts = unique(
        guide
            .deviations
            .iter()
            .filter(|d| d.conflict.is_some())
            .map(|d| format!("{} ({})", d.conflict.as_deref().unwrap_or_default(), d.rule)),
    );
    if !conflicts.is_empty() {
        warn(
            WarningCode::GuideConflict,
            format!(
                "The ESC User Guide says these features are not available, while the public availability data lists them as available: {}. The guide is likely outdated. Ask your AWS team to confirm and to have the guide corrected.",
                conflicts.join(", ")
            ),
            conflicts.clone(),
        );
    }
    if let Some(a) = ctx.account {
        let skipped: Vec<String> = a
            .skipped
            .iter()
            .map(|s| format!("{} ({})", s.check, s.reason.trim_end_matches('.')))
            .collect();
        if !skipped.is_empty() {
            warn(
                WarningCode::AccountChecksSkipped,
                format!("These account checks were skipped: {}.", skipped.join("; ")),
                a.skipped.iter().map(|s| s.check.clone()).collect(),
            );
        }
    }
    if !prov.macros.is_empty() {
        warn(
            WarningCode::PropertiesUnchecked,
            format!(
                "The template uses the transform {}, which rewrites resources when it is deployed, so resource properties were not checked against the target's schemas. Check the processed template instead.",
                prov.macros.join(", ")
            ),
            prov.macros.clone(),
        );
    } else if prov.schemas.is_none() && prov.schema_types > 0 {
        warn(
            WarningCode::PropertiesUnchecked,
            if prov.schema_denied {
                "The live role may not call cloudformation:DescribeType, so resource properties were not checked against the target's schemas. Add the action from iam/esc-preflight-readonly.json.".to_string()
            } else {
                format!(
                    "{target} publishes no CloudFormation schema bundle, so resource properties were not checked against it. Run in live mode to check them with cloudformation:DescribeType."
                )
            },
            if prov.schema_denied {
                vec!["cloudformation:DescribeType".to_string()]
            } else {
                vec![target.clone()]
            },
        );
    }
    if let Some(g) = prov
        .user_guide
        .as_ref()
        .filter(|g| !g.stale_rules.is_empty())
    {
        warn(
            WarningCode::StaleRules,
            format!(
                "These rules match the input, but the ESC User Guide no longer contains the sentence they quote, so they were skipped: {}. Check the guide: the restriction may have been lifted or reworded.",
                g.stale_rules.join(", ")
            ),
            g.stale_rules.clone(),
        );
    }
    (warnings, warning_commands)
}

fn env_label(e: &DeployEnv) -> String {
    match (&e.account, &e.region) {
        (Some(a), Some(r)) => format!("account {a} in {r}"),
        (Some(a), None) => format!("account {a}"),
        (None, Some(r)) => r.clone(),
        (None, None) => "its environment".into(),
    }
}

/// Gaps-only view: drops findings that are cleanly available, keeps everything
/// that needs action or verification. Summary and provenance stay complete.
pub fn gaps_only(r: &mut Report) {
    r.documented_differences.clear();
    r.findings.retain(|f| {
        f.divergence
            || f.depth.iter().any(|d| d.offered != Some(true))
            || f.verdict != Verdict::Available
    });
}

pub use crate::summary::text_summary;
#[cfg(test)]
use crate::tui::Style;

/// Introduces the synth command in a region warning.
pub(crate) const CDK_HINT: &str = "For a CDK app without a hardcoded env:";

/// Text from the input with control characters replaced, so a template cannot send
/// terminal escape sequences and every character takes one column.
pub(crate) fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

pub(crate) fn list(items: &[String], max: usize) -> String {
    match items.len() {
        n if n <= max => items.join(", "),
        n => format!("{}, +{} more", items[..max].join(", "), n - max),
    }
}

/// The items in first-seen order, without repeats.
pub(crate) fn unique<T: PartialEq>(it: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut out = Vec::new();
    for x in it {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

/// RFC 3339 UTC timestamp from the system clock, without a date-time dependency.
pub fn now_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
pub(crate) mod tests {
    /// The scan summary of `r` without a run's time or JSON destination.
    fn text_summary(r: &Report, st: Style) -> String {
        crate::summary::text_summary(r, st, &crate::tui::Run::default())
    }

    /// The rows inside the frame, without its borders.
    fn rows(text: &str) -> Vec<String> {
        text.lines()
            .map(|l| {
                let c: Vec<char> = l.chars().collect();
                if c.len() > 4 {
                    c[2..c.len() - 2]
                        .iter()
                        .collect::<String>()
                        .trim_end()
                        .to_string()
                } else {
                    String::new()
                }
            })
            .collect()
    }

    use super::*;
    use crate::extractor::{HazardKind, Impact};
    use crate::provider::{PublicData, guide, knowledge, partition, terraform};
    use crate::{depth, deviation, extractor, matcher, reader};

    /// Marks every property of every object in a JSON schema as required: the reports
    /// always write every key, null where a value is absent.
    /// The JSON Schema of what `T` serializes to: keys it skips are not required.
    pub(crate) fn output_schema<T: schemars::JsonSchema>() -> serde_json::Value {
        let g = schemars::generate::SchemaSettings::default()
            .for_serialize()
            .into_generator();
        serde_json::to_value(g.into_root_schema_for::<T>()).unwrap()
    }

    /// The committed `schema/<file>` is the JSON Schema of `T`. Set `UPDATE_GOLDEN=1`
    /// to rewrite it.
    pub(crate) fn assert_committed_schema<T: schemars::JsonSchema>(file: &str) {
        let v = output_schema::<T>();
        let text = format!("{}\n", serde_json::to_string_pretty(&v).unwrap());
        let path = format!("{}/schema/{file}", env!("CARGO_MANIFEST_DIR"));
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::write(&path, &text).unwrap();
        }
        assert!(
            std::fs::read_to_string(&path).unwrap_or_default() == text,
            "schema/{file} is out of date: run UPDATE_GOLDEN=1 cargo test schema, and decide whether output::SCHEMA_VERSION changes"
        );
    }

    fn data() -> PublicData {
        PublicData {
            partition: partition::facts("eusc-de-east-1").unwrap(),
            knowledge: knowledge::tests::fixture(),
            urls: Some((
                knowledge::URL.into(),
                crate::provider::capabilities::URL.into(),
                Some(crate::provider::capabilities::URL.into()),
            )),
            bundle: None,
            guide: Some(guide::tests::fixture()),
            tf: Some(terraform::tests::fixture()),
        }
    }

    /// A report without findings, for tests of what reads one.
    pub(crate) fn empty_report(target: &str) -> Report {
        build(
            Provenance {
                target_region: target.into(),
                ..prov(SourceFormat::Cloudformation, vec![])
            },
            vec![],
            extractor::Scan::default(),
            Default::default(),
            vec![],
            &Context::default(),
        )
    }

    #[test]
    fn unanswered_values_are_a_warning() {
        let (w, _) = warnings(
            &prov(SourceFormat::Cloudformation, vec![]),
            &GuideFindings::default(),
            &Context::default(),
            "Synthesize",
            &["InstanceType m7i.large".to_string()],
            &["InstanceType m7i.large".to_string()],
        );
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].code, WarningCode::ValuesUnchecked);
        assert!(
            w[0].message.contains("InstanceType m7i.large") && w[0].message.contains("live mode")
        );
        let (none, _) = warnings(
            &prov(SourceFormat::Cloudformation, vec![]),
            &GuideFindings::default(),
            &Context::default(),
            "Synthesize",
            &[],
            &[],
        );
        assert!(none.is_empty());
        // Live mode probes no Lambda architectures, so it is not offered for them.
        let (arch, _) = warnings(
            &prov(SourceFormat::Cloudformation, vec![]),
            &GuideFindings::default(),
            &Context::default(),
            "Synthesize",
            &["Properties.Architectures[] arm64".to_string()],
            &[],
        );
        assert!(
            arch[0]
                .message
                .ends_with("Check them in the target before you deploy.")
        );
        assert_eq!(arch[0].items, ["Properties.Architectures[] arm64"]);
        let both = [
            "Properties.Architectures[] arm64".to_string(),
            "Properties.InstanceType m7i.large".to_string(),
        ];
        let (mixed, _) = warnings(
            &prov(SourceFormat::Cloudformation, vec![]),
            &GuideFindings::default(),
            &Context::default(),
            "Synthesize",
            &both,
            &both[1..],
        );
        assert!(
            mixed[0].message.contains(
                "live mode to check Properties.InstanceType m7i.large in the account, and check the others"
            ),
            "{}",
            mixed[0].message
        );
        // Unchecked properties name the target, or the call that was refused.
        let (props, _) = warnings(
            &Provenance {
                schema_types: 1,
                ..prov(SourceFormat::Cloudformation, vec![])
            },
            &GuideFindings::default(),
            &Context::default(),
            "Synthesize",
            &[],
            &[],
        );
        assert_eq!(
            (props[0].code, props[0].items.as_slice()),
            (
                WarningCode::PropertiesUnchecked,
                ["eusc-de-east-1".to_string()].as_slice()
            )
        );
        let (denied, _) = warnings(
            &Provenance {
                schema_types: 1,
                schema_denied: true,
                ..prov(SourceFormat::Cloudformation, vec![])
            },
            &GuideFindings::default(),
            &Context::default(),
            "Synthesize",
            &[],
            &[],
        );
        assert_eq!(denied[0].items, ["cloudformation:DescribeType"]);
    }

    fn prov(format: SourceFormat, envs: Vec<DeployEnv>) -> Provenance {
        Provenance {
            tool_version: "test".into(),
            input: "template.yaml".into(),
            stacks: 1,
            source_format: format,
            input_kind: match format {
                SourceFormat::Cloudformation => crate::model::InputKind::Cloudformation,
                SourceFormat::TerraformPlan => crate::model::InputKind::TerraformPlan,
            },
            target_region: "eusc-de-east-1".into(),
            target_account: None,
            input_environments: envs,
            partitions_version: "test".into(),
            knowledge: Some(KnowledgeProvenance {
                url: knowledge::URL.into(),
                cloudformation_url: crate::provider::capabilities::URL.into(),
                products_url: Some(crate::provider::capabilities::URL.into()),
                unknown: vec![],
            }),
            user_guide: None,
            fetched_at: "1970-01-01T00:00:00Z".into(),
            terraform: None,
            live: None,
            schemas: None,
            schema_types: 0,
            schema_denied: false,
            macros: vec![],
        }
    }

    fn fixed_report(input: &str) -> String {
        crate::output::to_json(&crate::output::scan(&fixed(input)), true)
    }

    pub(crate) fn fixed(input: &str) -> Report {
        fixed_t(reader::parse_text(input).unwrap())
    }

    fn fixed_t(t: crate::model::Template) -> Report {
        scanned(t, data())
    }

    /// A report for a target, without the guide outside ESC, and with `--account`.
    fn fixed_for(input: &str, target: &str, account: Option<&str>) -> Report {
        let mut data = data();
        data.partition = partition::facts(target).unwrap();
        data.partition.target_account = account.map(String::from);
        if data.partition.target_partition != "aws-eusc" {
            data.guide = None;
        }
        scanned(reader::parse_text(input).unwrap(), data)
    }

    fn scanned(t: crate::model::Template, data: PublicData) -> Report {
        let prov = Provenance {
            terraform: data
                .tf
                .as_ref()
                .filter(|_| t.format == SourceFormat::TerraformPlan)
                .map(|tf| TerraformProvenance {
                    aws_provider_version: tf.aws_version.clone(),
                    awscc_provider_version: tf.awscc_version.clone(),
                }),
            target_region: data.partition.target_region.clone(),
            ..prov(t.format, t.envs())
        };
        let mut depth = depth::checks(&t, &data.partition.target_region);
        let offered = depth::public_offered(&data.knowledge);
        depth::resolve(&mut depth, &offered, depth::DepthSource::Public);
        let findings = matcher::assess(&t, &data.knowledge, data.tf.as_ref(), None, &depth);
        let scan = extractor::hazards(&t, &data.partition);
        let (g, gp) = deviation::assess(
            &t,
            &findings,
            data.guide.as_ref(),
            &data.knowledge,
            &data.partition,
        );
        let prov = Provenance {
            user_guide: gp,
            schema_types: crate::provider::schema::types(&t, data.tf.as_ref()).len(),
            macros: t.macros.clone(),
            ..prov
        };
        build(
            prov,
            findings,
            scan,
            g,
            t.out_of_scope.clone(),
            &Context {
                single_region: data.partition.target_regions == 1,
                offered: Some(&offered),
                facts: Some(&data.partition),
                ..Context::default()
            },
        )
    }

    fn fixture_reports() -> Vec<(Report, &'static str)> {
        let cdk = format!("{}/tests/fixtures/cdk.out", env!("CARGO_MANIFEST_DIR"));
        vec![
            (fixed(crate::test_inputs::SAMPLE_TEMPLATE), "sample"),
            (
                fixed(include_str!("../tests/fixtures/tf-plan.json")),
                "tf-plan",
            ),
            (
                fixed(crate::test_inputs::CUSTOM_RESOURCES_TEMPLATE),
                "custom-resources",
            ),
            (
                fixed_t(reader::read(&cdk, "eusc-de-east-1").unwrap()),
                "cdk",
            ),
        ]
    }

    /// The terminal summary of each fixture, in Unicode and in ASCII. Set
    /// `UPDATE_GOLDEN=1` to rewrite them after an intended change.
    #[test]
    fn golden_summaries() {
        for (r, name) in fixture_reports() {
            for (st, suffix) in [
                (
                    Style {
                        color: false,
                        unicode: true,
                        ..Style::default()
                    },
                    "unicode",
                ),
                (
                    Style {
                        color: false,
                        unicode: false,
                        ..Style::default()
                    },
                    "ascii",
                ),
            ] {
                let path = format!(
                    "{}/tests/fixtures/{name}-summary.{suffix}.golden.txt",
                    env!("CARGO_MANIFEST_DIR")
                );
                let actual = text_summary(&r, st);
                if std::env::var_os("UPDATE_GOLDEN").is_some() {
                    std::fs::write(&path, &actual).unwrap();
                }
                let expected = std::fs::read_to_string(&path)
                    .expect("golden file exists; run with UPDATE_GOLDEN=1");
                assert_eq!(actual, expected, "{path}");
            }
        }
    }

    /// Every required change has a short form, the arrow sits in one column, the
    /// lines shown account for every change, and ASCII mode is ASCII only.
    #[test]
    fn summary_is_complete_and_aligned() {
        for (r, name) in fixture_reports() {
            for c in &r.required_changes {
                assert!(
                    !c.brief.what.is_empty() && !c.brief.action.is_empty(),
                    "{name}: change without a brief: {}",
                    c.reason
                );
            }
            let ascii = text_summary(
                &r,
                Style {
                    color: false,
                    unicode: false,
                    ..Style::default()
                },
            );
            assert!(ascii.is_ascii(), "{name}: non-ASCII in ASCII mode");
            let text = text_summary(
                &r,
                Style {
                    color: false,
                    unicode: true,
                    ..Style::default()
                },
            );
            let block = section_rows(&text, "Required changes");
            // One-line rows share the arrow column; a long action has its own row.
            let arrows: std::collections::BTreeSet<usize> = block
                .iter()
                .filter(|l| !l.trim_start().starts_with('→'))
                .filter_map(|l| l.chars().position(|ch| ch == '→'))
                .collect();
            assert!(arrows.len() <= 1, "{name}: arrows at {arrows:?}");
            // Every change is in a group, and the lines shown plus the rest add up.
            let groups = crate::summary::change_groups(&r);
            assert_eq!(
                groups.iter().map(|g| g.n).sum::<usize>(),
                r.required_changes.len(),
                "{name}"
            );
            let shown = crate::summary::pick(&groups, crate::summary::MAX_CHANGE_LINES);
            assert_eq!(
                block.iter().filter(|l| l.contains('→')).count(),
                shown.len(),
                "{name}"
            );
        }
    }

    /// The rows of the section titled `title`, up to the next blank row.
    fn section_rows(text: &str, title: &str) -> Vec<String> {
        rows(text)
            .into_iter()
            .skip_while(|l| !l.contains(&format!(" {title} ")))
            .skip(1)
            .take_while(|l| !l.trim().is_empty())
            .collect()
    }

    /// At the narrowest and the widest width every row fits the frame, and every code
    /// replacement shown is whole.
    #[test]
    fn frames_fit_and_keep_replacements_whole() {
        for (r, name) in fixture_reports() {
            let groups = crate::summary::change_groups(&r);
            let shown = crate::summary::pick(&groups, crate::summary::MAX_CHANGE_LINES);
            for width in [crate::tui::MIN_WIDTH, crate::tui::MAX_WIDTH] {
                for unicode in [true, false] {
                    let st = Style {
                        unicode,
                        width,
                        ..Style::default()
                    };
                    let text = text_summary(&r, st);
                    for l in text.lines() {
                        assert_eq!(crate::tui::width(l), width, "{name}: {l}");
                    }
                    for g in shown.iter().filter(|g| g.code) {
                        assert!(
                            text.contains(&format!("`{}`", g.action)),
                            "{name} at {width}:\n{text}"
                        );
                    }
                }
            }
        }
    }

    /// The JSON warning carries the synth command; the terminal shows it on its own
    /// line after the prose.
    #[test]
    fn region_warning_carries_the_synth_command() {
        let (r, _) = fixture_reports().pop().unwrap();
        let cmd = "AWS_REGION=eusc-de-east-1 cdk synth";
        assert!(
            r.warnings
                .iter()
                .any(|w| w.code == WarningCode::InputRegionMismatch && w.message.ends_with(cmd)),
            "{:?}",
            r.warnings
        );
        let text = text_summary(
            &r,
            Style {
                color: false,
                unicode: true,
                ..Style::default()
            },
        );
        assert!(
            text.lines()
                .any(|l| l.contains(CDK_HINT) && l.contains(cmd)),
            "{text}"
        );
        assert!(!text.contains(&format!("deployed. {CDK_HINT}")), "{text}");
    }

    #[test]
    fn colored_replacements_are_accented_without_backticks() {
        let (r, _) = fixture_reports().remove(0);
        let text = text_summary(
            &r,
            Style {
                color: true,
                unicode: true,
                ..Style::default()
            },
        );
        assert!(
            text.contains("\x1b[38;5;79marn:${AWS::Partition}:\x1b[0m"),
            "{text}"
        );
        let plain = text_summary(
            &r,
            Style {
                color: false,
                unicode: true,
                ..Style::default()
            },
        );
        assert!(plain.contains("`arn:${AWS::Partition}:`"), "{plain}");
    }

    /// More distinct changes than the cap: the rest is counted, not dropped.
    #[test]
    fn long_change_lists_are_capped_and_counted() {
        let mut r = fixed(crate::test_inputs::SAMPLE_TEMPLATE);
        for i in 0..12 {
            r.required_changes.push(RequiredChange::new(
                &format!("R{i}"),
                Tier::Flag,
                Cause::new(CauseType::Availability, []),
                "x".into(),
                "x".into(),
                remediation::brief(format!("svc{i} not available"), "remove it"),
            ));
        }
        let text = text_summary(
            &r,
            Style {
                color: false,
                unicode: true,
                ..Style::default()
            },
        );
        let block = section_rows(&text, "Required changes");
        let max = crate::summary::MAX_CHANGE_LINES;
        assert_eq!(block.iter().filter(|l| l.contains('→')).count(), max);
        let groups = crate::summary::change_groups(&r);
        let shown: usize = crate::summary::pick(&groups, max).iter().map(|g| g.n).sum();
        let rest = r.required_changes.len() - shown;
        assert!(
            block.last().unwrap().contains(&format!("{rest} more")),
            "{text}"
        );
        // The fixes are not hidden behind the flags.
        assert!(block.iter().any(|l| l.contains(" fix ")), "{text}");
    }

    #[test]
    fn control_characters_from_the_input_are_not_printed() {
        assert_eq!(clean("AWS::Fo\u{1b}]0;x\u{7}o::Bar"), "AWS::Fo?]0;x?o::Bar");
    }

    #[test]
    fn wrap_keeps_long_words_whole() {
        assert_eq!(
            crate::tui::wrap("a verylongword b", 4),
            vec!["a", "verylongword", "b"]
        );
    }

    /// Set `UPDATE_GOLDEN=1` to rewrite the golden files after an intended change.
    #[test]
    fn golden_reports() {
        for (input, golden) in [
            (
                crate::test_inputs::SAMPLE_TEMPLATE,
                "sample-report.golden.json",
            ),
            (
                include_str!("../tests/fixtures/tf-plan.json"),
                "tf-plan-report.golden.json",
            ),
            (
                crate::test_inputs::CUSTOM_RESOURCES_TEMPLATE,
                "custom-resources-report.golden.json",
            ),
        ] {
            let path = format!("{}/tests/fixtures/{golden}", env!("CARGO_MANIFEST_DIR"));
            let actual = fixed_report(input);
            if std::env::var_os("UPDATE_GOLDEN").is_some() {
                std::fs::write(&path, &actual).unwrap();
            }
            let expected = std::fs::read_to_string(&path)
                .expect("golden file exists; run with UPDATE_GOLDEN=1");
            assert_eq!(actual, expected, "{golden}");
        }
    }

    #[test]
    fn gaps_view_drops_clean_findings_only() {
        let t = reader::parse_text(crate::test_inputs::SAMPLE_TEMPLATE).unwrap();
        let d = data();
        let findings = matcher::assess(
            &t,
            &d.knowledge,
            None,
            None,
            &std::collections::BTreeMap::new(),
        );
        let clean = findings
            .iter()
            .filter(|f| f.verdict == Verdict::Available)
            .count();
        assert!(
            clean > 0,
            "fixture must contain a cleanly available resource"
        );
        let total = findings.len();
        let prov = prov(SourceFormat::Cloudformation, vec![]);
        let mut g = build(
            prov,
            findings,
            Scan::default(),
            GuideFindings::default(),
            vec![],
            &Context::default(),
        );
        gaps_only(&mut g);
        assert_eq!(g.findings.len(), total - clean);
        assert_eq!(g.summary.resources, total);
    }

    #[test]
    fn zone_shortfall_is_a_blocker() {
        let t = reader::read(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cdk.out"),
            "eusc-de-east-1",
        )
        .unwrap();
        let data = data();
        let mut scan = extractor::hazards(&t, &data.partition);
        scan.env_literals[0].zones = vec![
            "eu-central-1a".into(),
            "eu-central-1b".into(),
            "eu-central-1c".into(),
        ];
        let prov = prov(t.format, t.envs());
        let r = build(
            prov.clone(),
            vec![],
            scan.clone(),
            GuideFindings::default(),
            vec![],
            &Context {
                target_zones: Some(2),
                ..Context::default()
            },
        );
        assert_eq!(r.summary.depth_blockers, 1);
        let zones = |r: &Report| {
            r.required_changes
                .iter()
                .filter(|c| c.cause.kind == CauseType::Zones)
                .count()
        };
        assert_eq!(zones(&r), 1);
        assert!(
            r.required_changes
                .iter()
                .any(|c| c.reason.contains("3 zones"))
        );
        assert_eq!(
            zones(&build(
                prov,
                vec![],
                scan,
                GuideFindings::default(),
                vec![],
                &Context {
                    target_zones: Some(3),
                    ..Context::default()
                }
            )),
            0
        );
    }

    #[test]
    fn timestamp_shape() {
        let t = now_utc();
        assert_eq!(t.len(), 20);
        assert!(t.ends_with('Z') && t.as_bytes()[10] == b'T');
    }

    /// Where `v` breaks `schema`: a key the schema does not declare, a required key
    /// that is missing, or a null or empty list, which the output leaves out.
    pub(crate) fn schema_errors(
        v: &serde_json::Value,
        schema: &serde_json::Value,
        root: &serde_json::Value,
        at: &str,
        out: &mut Vec<String>,
    ) {
        use serde_json::Value;
        if let Some(r) = schema["$ref"].as_str() {
            let name = r.trim_start_matches("#/$defs/");
            return schema_errors(v, &root["$defs"][name], root, at, out);
        }
        match v {
            Value::Null => return out.push(format!("{at}: null")),
            Value::Array(a) if a.is_empty() => return out.push(format!("{at}: []")),
            _ => {}
        }
        if let Some(branches) = schema["anyOf"].as_array().or(schema["oneOf"].as_array()) {
            let fits = branches.iter().any(|b| {
                let mut e = Vec::new();
                schema_errors(v, b, root, at, &mut e);
                e.is_empty() && type_fits(v, b, root)
            });
            if !fits {
                out.push(format!("{at}: no branch fits"));
            }
            return;
        }
        if let (Some(m), Some(props)) = (v.as_object(), schema["properties"].as_object()) {
            for k in schema["required"].as_array().into_iter().flatten() {
                if !m.contains_key(k.as_str().unwrap_or_default()) {
                    out.push(format!("{at}.{k}: missing"));
                }
            }
            for (k, x) in m {
                match props.get(k) {
                    Some(s) => schema_errors(x, s, root, &format!("{at}.{k}"), out),
                    None => out.push(format!("{at}.{k}: undeclared")),
                }
            }
        } else if let (Some(m), Some(s)) = (v.as_object(), schema.get("additionalProperties")) {
            for (k, x) in m {
                schema_errors(x, s, root, &format!("{at}.{k}"), out);
            }
        }
        if let (Some(items), Some(a)) = (schema.get("items"), v.as_array()) {
            for (i, x) in a.iter().enumerate() {
                schema_errors(x, items, root, &format!("{at}[{i}]"), out);
            }
        }
    }

    fn type_fits(
        v: &serde_json::Value,
        schema: &serde_json::Value,
        root: &serde_json::Value,
    ) -> bool {
        if let Some(r) = schema["$ref"].as_str() {
            return type_fits(v, &root["$defs"][r.trim_start_matches("#/$defs/")], root);
        }
        let name = match v {
            serde_json::Value::Object(_) => "object",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Number(_) => "integer",
            serde_json::Value::Null => "null",
        };
        match &schema["type"] {
            serde_json::Value::String(t) => t == name || (t == "number" && name == "integer"),
            serde_json::Value::Array(ts) => ts.iter().any(|t| t == name),
            _ => true,
        }
    }

    #[test]
    fn reports_follow_their_schema_and_leave_out_empty_keys() {
        let schema = output_schema::<crate::output::Scan>();
        for input in [
            crate::test_inputs::SAMPLE_TEMPLATE,
            include_str!("../tests/fixtures/tf-plan.json"),
            crate::test_inputs::CUSTOM_RESOURCES_TEMPLATE,
        ] {
            let v: serde_json::Value = serde_json::from_str(&fixed_report(input)).unwrap();
            let mut errors = Vec::new();
            schema_errors(&v, &schema, &schema, "", &mut errors);
            assert!(errors.is_empty(), "{errors:?}");
        }
    }

    #[test]
    fn a_target_without_knowledge_data_says_live_mode_decides_alone() {
        let r = build(
            Provenance {
                knowledge: None,
                ..prov(SourceFormat::Cloudformation, vec![])
            },
            vec![],
            extractor::Scan::default(),
            Default::default(),
            vec![],
            &Context::default(),
        );
        assert_eq!(
            r.warnings.iter().map(|w| w.code).collect::<Vec<_>>(),
            [WarningCode::PublicDataRegionUnlisted]
        );
        let text = text_summary(&r, Style::default());
        let target = text
            .lines()
            .find(|l| l.contains("-> eusc-de-east-1"))
            .unwrap_or_default();
        assert!(
            target.contains("public mode") && !target.contains("Knowledge"),
            "{text}"
        );
    }

    /// A dependency and a doc-rule deviation: their lists, counts, outcome, required
    /// changes and summary rows.
    #[test]
    fn dependencies_and_doc_rules_reach_the_report() {
        let r = fixed(
            r#"{"Resources":{"P":{"Type":"AWS::IAM::ManagedPolicy","Properties":{"PolicyDocument":
                {"Statement":[{"Effect":"Deny","Condition":{"StringNotEquals":{"aws:RequestedRegion":{"Ref":"Regions"}}}}]}}},
            "F":{"Type":"AWS::Lambda::Function","Properties":{"Runtime":"python3.7"}}}}"#,
        );
        assert_eq!(r.summary.dependencies, 1);
        assert_eq!(r.dependencies[0].rule, "iam-requested-region-condition");
        assert_eq!(r.summary.hazards, 0);
        assert!(r.outcome.hazard, "a dependency is a hazard for --fail-on");
        assert!(r.outcome.blocker, "the runtime cannot be created");
        let of = |t: CauseType| {
            r.required_changes
                .iter()
                .filter(|c| c.cause.kind == t)
                .map(|c| (c.logical_id.as_str(), c.tier, c.decided_by, c.doc.is_some()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            of(CauseType::Dependency),
            [("P", Tier::Flag, DecidedBy::Rule, true)]
        );
        assert_eq!(
            of(CauseType::Deviation),
            [("F", Tier::Propose, DecidedBy::Rule, true)],
            "doc rules bring their remediation"
        );
        let text = text_summary(&r, Style::default());
        assert!(text.contains("lambda runtime create blocked"), "{text}");
        assert!(text.contains("iam requested region condition"), "{text}");
    }

    /// A property the target schema lacks is a depth blocker decided by the schema, and
    /// without a schema the report says properties were not checked.
    #[test]
    fn missing_properties_block_and_unchecked_ones_warn() {
        let t = reader::parse_text(
            r#"{"Resources":{"F":{"Type":"AWS::Lambda::Function","Properties":{"AcceleratorConfig":{}}}}}"#,
        )
        .unwrap();
        let unchecked = fixed_t(t.clone());
        assert!(
            unchecked
                .warnings
                .iter()
                .any(|w| w.code == WarningCode::PropertiesUnchecked)
        );
        let denied = build(
            Provenance {
                schema_types: 1,
                schema_denied: true,
                ..prov(SourceFormat::Cloudformation, vec![])
            },
            vec![],
            extractor::Scan::default(),
            Default::default(),
            vec![],
            &Context::default(),
        );
        assert!(
            denied
                .warnings
                .iter()
                .any(|w| w.code == WarningCode::PropertiesUnchecked
                    && w.message.contains("cloudformation:DescribeType"))
        );
        let schemas = crate::provider::schema::Schemas::from([(
            "AWS::Lambda::Function".to_string(),
            ["Runtime".to_string()].into(),
        )]);
        let mut depth = crate::provider::schema::checks(&t, &schemas, None);
        let data = data();
        let findings = matcher::assess(&t, &data.knowledge, None, None, &depth);
        depth.clear();
        let r = build(
            Provenance {
                schemas: Some(crate::provider::schema::SchemaProvenance::new(
                    crate::provider::schema::SchemaSource::Live,
                    None,
                    &schemas,
                )),
                schema_types: 1,
                ..prov(SourceFormat::Cloudformation, vec![])
            },
            findings,
            extractor::hazards(&t, &data.partition),
            Default::default(),
            vec![],
            &Context::default(),
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert_eq!(r.summary.depth_blockers, 1);
        assert!(r.outcome.blocker);
        let c = &r.required_changes[0];
        assert_eq!(
            (c.cause.kind, c.tier, c.decided_by, c.cause.ids.clone()),
            (
                CauseType::Depth,
                Tier::Flag,
                DecidedBy::Schema,
                vec!["property".to_string()]
            )
        );
        let text = text_summary(&r, Style::default());
        assert!(text.contains("not offered"), "{text}");
    }

    /// Failing account checks are blockers decided by live mode; skipped ones warn.
    #[test]
    fn account_checks_reach_the_report() {
        use crate::account::*;
        let a = AccountChecks {
            region_opt_in: Some("opted-in".into()),
            quotas: vec![QuotaCheck {
                rule: "quota-vpcs-per-region".into(),
                service_code: "vpc".into(),
                quota_code: "L-F678F1CE".into(),
                name: "VPCs per Region".into(),
                needed: 6,
                used: None,
                uncounted: 0,
                quota: 5.0,
                value_source: QuotaSource::Default,
                exceeded: true,
                doc: "https://docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html"
                    .into(),
            }],
            scp: Some(ScpCheck {
                status: ScpStatus::Evaluated,
                policies: vec![ScpPolicy {
                    id: "p-1".into(),
                    name: "RegionDeny".into(),
                    verdict: ScpVerdict::DeniesTarget,
                    conditional: true,
                }],
                services_denied: vec![],
            }),
            ssm_parameters: vec![SsmParameterCheck {
                name: "/aws/service/x".into(),
                used_by: vec!["Parameters/Ami".into()],
                exists: false,
            }],
            skipped: vec![Skipped {
                check: "region-opt-in".into(),
                reason: "ec2:DescribeRegions was denied for the role.".into(),
            }],
        };
        let r = build(
            prov(SourceFormat::Cloudformation, vec![]),
            vec![],
            extractor::Scan::default(),
            Default::default(),
            vec![],
            &Context {
                account: Some(&a),
                ..Context::default()
            },
        );
        assert_eq!(r.summary.account_blockers, 3);
        assert!(r.outcome.blocker);
        let changes: Vec<(&str, &str, DecidedBy)> = r
            .required_changes
            .iter()
            .filter(|c| c.cause.kind == CauseType::Account)
            .map(|c| (c.logical_id.as_str(), c.cause.ids[0].as_str(), c.decided_by))
            .collect();
        assert_eq!(
            changes,
            [
                ("*", "quota-vpcs-per-region", DecidedBy::Live),
                ("*", "scp", DecidedBy::Live),
                ("Parameters/Ami", "ssm-parameter", DecidedBy::Live)
            ]
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.code == WarningCode::AccountChecksSkipped
                    && w.message.contains("region-opt-in"))
        );
        let text = text_summary(&r, Style::default());
        assert!(text.contains("blockers") && text.contains("SCP"), "{text}");
    }

    /// A Terraform policy set from a policy document read at apply time is checked
    /// through the document's statements.
    #[test]
    fn terraform_policy_documents_are_checked() {
        let plan = r#"{"format_version":"1.2",
          "planned_values":{"root_module":{"resources":[
            {"address":"aws_iam_policy.p","mode":"managed","type":"aws_iam_policy","name":"p",
             "provider_name":"registry.terraform.io/hashicorp/aws","values":{"name":"p"}}]}},
          "resource_changes":[
            {"address":"data.aws_iam_policy_document.d","mode":"data","type":"aws_iam_policy_document","name":"d",
             "change":{"actions":["read"],"after":{"statement":[{"effect":"Deny","actions":["*"],
               "condition":[{"test":"StringNotEquals","variable":"aws:RequestedRegion","values":["eu-central-1"]}]}]}}}],
          "configuration":{"root_module":{"resources":[
            {"address":"aws_iam_policy.p","mode":"managed","type":"aws_iam_policy","name":"p",
             "expressions":{"policy":{"references":["data.aws_iam_policy_document.d.json","data.aws_iam_policy_document.d"]}}}]}}}"#;
        let r = fixed_for(plan, "eusc-de-east-1", None);
        assert!(
            r.dependencies
                .iter()
                .any(|d| d.rule == "iam-requested-region-condition"
                    && d.logical_id == "aws_iam_policy.p"),
            "{:?}",
            r.dependencies
        );
    }

    /// A SAM function is assessed as the Lambda function it deploys as, with Globals.
    #[test]
    fn sam_resources_are_assessed_as_their_base_type() {
        let input = r#"{"Transform":"AWS::Serverless-2016-10-31",
            "Globals":{"Function":{"Runtime":"python3.7","Environment":{"Variables":{"R":"eu-central-1"}}}},
            "Resources":{
              "F":{"Type":"AWS::Serverless::Function","Properties":{"Handler":"a.h","CodeUri":"src/","AcceleratorConfig":{}}},
              "C":{"Type":"AWS::Serverless::Connector","Properties":{}}}}"#;
        let r = fixed_for(input, "eu-west-1", None);
        let f = r.findings.iter().find(|f| f.logical_id == "F").unwrap();
        assert_eq!(f.resource_type, "AWS::Serverless::Function");
        assert_eq!(f.verdict, crate::matcher::Verdict::Available);
        assert!(
            r.deviations
                .iter()
                .any(|d| d.rule == "lambda-runtime-create-blocked" && d.logical_id == "F"),
            "{:?}",
            r.deviations
        );
        // A literal in Globals is reported where it is written, not on the function.
        assert!(
            r.hazards.iter().all(|h| h.logical_id != "F"),
            "{:?}",
            r.hazards
        );
        assert!(
            r.hazards
                .iter()
                .any(|h| h.logical_id == "Globals/Function"
                    && h.path.starts_with("Globals.Function.")),
            "{:?}",
            r.hazards
        );
        let t = reader::parse_text(input).unwrap();
        assert_eq!(
            crate::provider::schema::types(&t, None),
            ["AWS::Lambda::Function".to_string()].into()
        );
        let schemas = crate::provider::schema::Schemas::from([(
            "AWS::Lambda::Function".to_string(),
            ["Runtime", "Handler", "Environment"]
                .map(String::from)
                .into(),
        )]);
        let checks = crate::provider::schema::checks(&t, &schemas, None);
        let props: Vec<&str> = checks["F"].iter().map(|c| c.value.as_str()).collect();
        assert_eq!(props, ["AcceleratorConfig"]);
    }

    /// Each scan addition fires on an input that has it and not on one that does not,
    /// for ESC and for a global-partition target. Property checks (`schema::tests`)
    /// and account checks (`account::tests`) are tested where they are computed.
    #[test]
    fn scan_additions_fire_for_esc_and_the_global_partition() {
        let res = |ty: &str, props: &str| {
            format!(r#"{{"Resources":{{"R":{{"Type":"{ty}","Properties":{props}}}}}}}"#)
        };
        let deviation = |r: &Report| {
            r.deviations
                .iter()
                .map(|d| d.rule.clone())
                .collect::<Vec<_>>()
        };
        let dependency = |r: &Report| {
            r.dependencies
                .iter()
                .map(|d| d.rule.clone())
                .collect::<Vec<_>>()
        };
        let kinds = |r: &Report| {
            r.hazards
                .iter()
                .flat_map(|h| &h.literals)
                .map(|l| (l.kind, l.impact))
                .collect::<Vec<_>>()
        };
        let lambda = "AWS::Lambda::Function";
        for target in ["eusc-de-east-1", "eu-west-1"] {
            let r = |input: &str| fixed_for(input, target, None);
            // Lambda runtimes
            assert_eq!(
                deviation(&r(&res(lambda, r#"{"Runtime":"python3.7"}"#))),
                ["lambda-runtime-create-blocked"],
                "{target}"
            );
            assert!(deviation(&r(&res(lambda, r#"{"Runtime":"python3.13"}"#))).is_empty());
            // Resource IDs
            let ami = r(&res(
                "AWS::EC2::Instance",
                r#"{"ImageId":"ami-0123456789abcdef0"}"#,
            ));
            assert_eq!(
                kinds(&ami),
                [(HazardKind::ResourceId, Impact::Breaks)],
                "{target}"
            );
            let ssm = res(
                "AWS::EC2::Instance",
                r#"{"ImageId":"{{resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64}}"}"#,
            );
            assert!(kinds(&r(&ssm)).is_empty(), "{target}");
            // Legacy S3 endpoints
            let dash = r(&res(
                lambda,
                r#"{"Environment":{"Variables":{"U":"b.s3-us-west-2.amazonaws.com"}}}"#,
            ));
            assert!(kinds(&dash).contains(&(HazardKind::LegacyEndpoint, Impact::Breaks)));
            let dot = r(&res(
                lambda,
                r#"{"Environment":{"Variables":{"U":"b.s3.us-west-2.amazonaws.com"}}}"#,
            ));
            assert!(
                !kinds(&dot)
                    .iter()
                    .any(|(k, _)| *k == HazardKind::LegacyEndpoint)
            );
            // Dependencies
            let policy = res(
                "AWS::IAM::ManagedPolicy",
                r#"{"PolicyDocument":{"Statement":[{"Condition":{"StringEquals":{"aws:RequestedRegion":{"Ref":"R"}}}}]}}"#,
            );
            assert_eq!(dependency(&r(&policy)), ["iam-requested-region-condition"]);
            assert!(
                dependency(&r(&res(
                    "AWS::IAM::ManagedPolicy",
                    r#"{"PolicyDocument":{}}"#
                )))
                .is_empty()
            );
            // Accounts
            let arn = res(
                lambda,
                r#"{"Role":"arn:${AWS::Partition}:iam::444455556666:role/r"}"#,
            );
            let impact = |account| kinds(&fixed_for(&arn, target, account))[0].1;
            assert_eq!(impact(Some("111122223333")), Impact::Breaks, "{target}");
            assert_eq!(impact(Some("444455556666")), Impact::Portability);
            assert_eq!(impact(None), Impact::Portability);
            // Provenance
            assert_eq!(
                r(&res(lambda, r#"{"Runtime":"python3.7"}"#)).deviations[0].decided_by,
                DecidedBy::Rule
            );
        }
        // Global partition only: the CloudFront certificate stays in us-east-1.
        let cdn = res(
            "AWS::CloudFront::Distribution",
            r#"{"DistributionConfig":{"ViewerCertificate":{"AcmCertificateArn":{"Ref":"C"}}}}"#,
        );
        assert_eq!(
            dependency(&fixed_for(&cdn, "eu-west-1", None)),
            ["cloudfront-certificate-stays-in-us-east-1"]
        );
        assert!(dependency(&fixed_for(&cdn, "eusc-de-east-1", None)).is_empty());
        assert!(dependency(&fixed_for(&cdn, "us-east-1", None)).is_empty());
    }

    /// Every required change names the source that decided it.
    #[test]
    fn required_changes_name_their_source() {
        let r = fixed(
            r#"{"Resources":{"S":{"Type":"AWS::SecretsManager::Secret","Properties":{"ReplicaRegions":[{"Region":"x"}]}},
            "Q":{"Type":"AWS::QBusiness::Application"},
            "F":{"Type":"AWS::Lambda::Function","Properties":{"Role":"arn:aws:iam::111122223333:role/r"}}}}"#,
        );
        let by = |t: CauseType| {
            r.required_changes
                .iter()
                .filter(|c| c.cause.kind == t)
                .map(|c| c.decided_by)
                .collect::<Vec<_>>()
        };
        assert_eq!(by(CauseType::Deviation), [DecidedBy::Guide]);
        assert_eq!(by(CauseType::Availability), [DecidedBy::Public]);
        assert!(
            by(CauseType::Hazard)
                .iter()
                .all(|d| *d == DecidedBy::Scanner)
        );
        assert!(
            r.deviations
                .iter()
                .all(|d| d.decided_by == DecidedBy::Guide)
        );
    }

    #[test]
    fn committed_schema_matches_the_report_types() {
        assert_committed_schema::<crate::output::Scan>("report.schema.json");
    }
}
