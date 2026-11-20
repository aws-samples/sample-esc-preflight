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

/// Version of the JSON report's shape. Adding a field or an enum value keeps it;
/// removing or renaming a field, or changing what one means, increments it.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct TerraformProvenance {
    pub aws_provider_version: String,
    pub awscc_provider_version: String,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct KnowledgeProvenance {
    pub url: String,
    /// Types, services or operations the server does not know.
    pub unknown: Vec<String>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct Provenance {
    pub tool_version: String,
    pub source_format: SourceFormat,
    pub target_region: String,
    /// The account the input moves to, when `--account` is given.
    pub target_account: Option<String>,
    /// Where the input was synthesized (CDK cloud assembly) or planned (Terraform).
    pub input_environments: Vec<DeployEnv>,
    /// botocore release of the bundled partition data.
    pub partitions_version: String,
    /// Null when the server has no data for the target, so live mode decides alone.
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
    #[serde(skip)]
    pub schema_types: usize,
    /// Live mode was refused `cloudformation:DescribeType`.
    #[serde(skip)]
    pub schema_denied: bool,
    /// Macros in the template's `Transform`, which skip the property checks.
    #[serde(skip)]
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
    /// Property values written for the input's own environment (see `environment_literals`).
    pub environment_literals: usize,
    pub divergences: usize,
    /// Depth checks whose value the target region does not offer, plus a zone
    /// shortfall (see `zones`).
    pub depth_blockers: usize,
    /// Account checks that block deployment (see `account`).
    pub account_blockers: usize,
    /// Resources that use a feature the ESC User Guide or another AWS page documents as
    /// not available.
    pub deviations: usize,
    /// Guide restrictions the Knowledge MCP data contradicts; warnings, not blockers.
    pub guide_conflicts: usize,
    /// Features that work with a documented difference.
    pub caveats: usize,
    /// Documented dependencies outside the target, one per resource and rule (see
    /// `dependencies`).
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
            blocker: s.depth_blockers + s.deviations + s.not_available + s.account_blockers > 0,
            hazard: s.hazards + s.environment_literals + s.dependencies > 0,
            disputed: s.disputed + s.cannot_assess + s.guide_conflicts > 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum WarningCode {
    /// The input was produced for another Region than the target.
    InputRegionMismatch,
    /// The Knowledge MCP server does not know some types, services or operations.
    KnowledgeUnknown,
    /// The Knowledge MCP server has no data for the target; live mode decides alone.
    KnowledgeRegionUnlisted,
    /// The ESC User Guide and the Knowledge MCP data disagree.
    GuideConflict,
    /// Rules matched, but the guide no longer contains their sentence.
    StaleRules,
    /// No schema of the target was read, so properties were not checked.
    PropertiesUnchecked,
    /// Live mode could not run some account checks.
    AccountChecksSkipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct Warning {
    pub code: WarningCode,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct Report {
    #[schemars(extend("const" = 1))]
    pub schema_version: u32,
    pub data_provenance: Provenance,
    pub summary: Summary,
    pub outcome: Outcome,
    pub findings: Vec<Finding>,
    pub hazards: Vec<crate::extractor::Hazard>,
    pub deviations: Vec<Deviation>,
    pub dependencies: Vec<Dependency>,
    /// Differences the ESC User Guide documents for the services in the input.
    pub documented_differences: Vec<Documented>,
    pub environment_literals: Vec<EnvLiterals>,
    pub zones: Option<ZoneCheck>,
    pub required_changes: Vec<RequiredChange>,
    /// Terraform resources of providers other than aws and awscc.
    pub out_of_scope: Vec<OutOfScope>,
    /// Live mode's checks of the target account; null in public mode.
    pub account: Option<crate::account::AccountChecks>,
    pub warnings: Vec<Warning>,
    /// For a warning that carries a command: its index, the prose without the
    /// command, and the command, so the terminal shows the command on its own line.
    /// The JSON warning has both in one message.
    #[serde(skip)]
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
        environment_literals: env_literals.iter().map(|e| e.places).sum(),
        deviations: guide.deviations.iter().filter(|d| d.blocks()).count(),
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
        match c.tier {
            Tier::Fix => s.fixes += 1,
            Tier::Propose => s.proposals += 1,
            Tier::Flag => s.flags += 1,
        }
    }
    let (warnings, warning_commands) = warnings(&provenance, &guide, ctx, produce);
    Report {
        schema_version: SCHEMA_VERSION,
        data_provenance: provenance,
        outcome: Outcome::of(&s),
        summary: s,
        findings,
        hazards,
        deviations: guide.deviations,
        dependencies: guide.dependencies,
        documented_differences: guide.documented,
        environment_literals: env_literals,
        zones,
        required_changes: changes,
        out_of_scope,
        account: ctx.account.cloned(),
        warnings,
        warning_commands,
    }
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
        let what = match &f.service {
            Some(s) => format!("{s} type not registered"),
            None => "resource type not registered".into(),
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
        remediation::brief(
            format!("{svc} {}", rm.short()),
            match (&rm.status, &rm.launch) {
                (State::Planned, Some(q)) => format!("replace {svc} or wait for {q}"),
                _ => format!("remove or replace {svc}"),
            },
        )
    } else {
        remediation::brief(
            format!("{svc} not available"),
            format!("remove or replace {svc}"),
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
            .map_or(DecidedBy::Knowledge, |s| match s {
                DepthSource::Knowledge => DecidedBy::Knowledge,
                DepthSource::Live => DecidedBy::Live,
                DepthSource::Schema => DecidedBy::Schema,
            }),
        CauseType::Dependency => DecidedBy::Rule,
        CauseType::Zones | CauseType::Account => DecidedBy::Live,
        CauseType::Hazard | CauseType::Environment => DecidedBy::Scanner,
    }
}

/// The report's warnings, and the commands split from them for the terminal.
fn warnings(
    prov: &Provenance,
    guide: &GuideFindings,
    ctx: &Context,
    produce: &str,
) -> (Vec<Warning>, Vec<(usize, String, String)>) {
    let target = &prov.target_region;
    let mut warnings: Vec<Warning> = Vec::new();
    let mut warn = |code, message: String| {
        let w = Warning { code, message };
        let new = !warnings.contains(&w);
        if new {
            warnings.push(w);
        }
        new.then(|| warnings.len() - 1)
    };
    if prov.knowledge.is_none() {
        warn(
            WarningCode::KnowledgeRegionUnlisted,
            format!(
                "The AWS Knowledge MCP server has no data for {target}, so the verdicts come from live mode alone, without roadmap states."
            ),
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
            warn(WarningCode::InputRegionMismatch, format!("{prose}{how}")),
            cmd,
        ) {
            warning_commands.push((i, prose, c));
        }
    }
    if let Some(k) = prov.knowledge.as_ref().filter(|k| !k.unknown.is_empty()) {
        warn(
            WarningCode::KnowledgeUnknown,
            format!(
                "The Knowledge MCP data does not know {}; only live mode can assess these resources.",
                k.unknown.join(", ")
            ),
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
                "The ESC User Guide says these features are not available, while the Knowledge MCP data lists them as available: {}. The guide is likely outdated. Ask your AWS team to confirm and to have the guide corrected.",
                conflicts.join(", ")
            ),
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
    r.findings.retain(|f| {
        f.divergence
            || f.depth.iter().any(|d| d.offered != Some(true))
            || f.verdict != Verdict::Available
    });
}

pub fn to_json(v: &impl Serialize) -> String {
    let mut s = serde_json::to_string_pretty(v).expect("serializes");
    s.push('\n');
    s
}

/// How the terminal summary may draw. Glyphs need a terminal; color additionally
/// honours `NO_COLOR`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Style {
    pub color: bool,
    pub unicode: bool,
}

/// Introduces the synth command in a region warning.
const CDK_HINT: &str = "For a CDK app without a hardcoded env:";

/// Required-change lines shown before the rest is left to the JSON report.
const MAX_CHANGE_LINES: usize = 8;
/// Warning prose wraps at this width.
const WRAP: usize = 100;
/// Longest "what" column before it is cut with an ellipsis.
const MAX_WHAT: usize = 42;
/// Longest action and detail text before it is cut.
const MAX_ACTION: usize = 54;
const MAX_DETAIL: usize = 76;

/// The human-readable summary on stderr. Every line is built from structured fields
/// of the report, never by parsing its prose, so the same report gives the same text.
pub fn text_summary(r: &Report, st: Style) -> String {
    let s = &r.summary;
    let p = &r.data_provenance;
    let pen = Pen::new(st);
    let Pen {
        ok,
        bad,
        warn,
        unk,
        dot,
        ..
    } = pen;

    let mut out = vec![
        pen.paint(
            BOLD,
            &format!(
                "{}esc-preflight{dot}{} resources{dot}{}",
                pen.g("◆ ", ""),
                s.resources,
                p.target_region
            ),
        ),
        format!(
            "  {}",
            pen.paint(
                DIM,
                &[
                    p.knowledge.as_ref().map(|_| "Knowledge MCP".to_string()),
                    p.user_guide
                        .as_ref()
                        .map(|g| format!("ESC User Guide {} pages", g.pages)),
                    Some(
                        if p.live.is_some() {
                            "live mode"
                        } else {
                            "public mode"
                        }
                        .into()
                    ),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(dot)
            )
        ),
        String::new(),
    ];

    out.push(pen.paint(BOLD, "  AVAILABILITY"));
    pen.row(&mut out, ok, GREEN, "available", s.available, String::new());
    let na = types_of(r, |f| f.verdict == Verdict::NotAvailable);
    pen.row(
        &mut out,
        if s.not_available > 0 { bad } else { ok },
        if s.not_available > 0 { RED } else { GREEN },
        "not available",
        s.not_available,
        na,
    );
    if s.cannot_assess > 0 {
        let custom = r
            .findings
            .iter()
            .filter(|f| f.verdict == Verdict::CannotAssess)
            .all(|f| {
                f.resource_type.starts_with("Custom::")
                    || f.resource_type.ends_with("CustomResource")
            });
        let detail = if custom {
            "custom resources, backed by their own code".to_string()
        } else {
            types_of(r, |f| f.verdict == Verdict::CannotAssess)
        };
        pen.row(
            &mut out,
            unk,
            YELLOW,
            "cannot assess",
            s.cannot_assess,
            detail,
        );
    }
    if s.disputed > 0 {
        let d = types_of(r, |f| f.verdict == Verdict::Disputed);
        pen.row(&mut out, warn, YELLOW, "disputed", s.disputed, d);
    }
    if s.divergences > 0 {
        let d = types_of(r, |f| f.divergence);
        pen.row(&mut out, warn, YELLOW, "live vs public", s.divergences, d);
    }

    out.push(String::new());
    out.push(pen.paint(BOLD, "  PORTABILITY"));
    out.extend(portability_rows(r, &pen));
    out.push(String::new());
    out.extend(change_lines(r, &pen));
    out.extend(warning_lines(r, &pen));
    out.join("\n") + "\n"
}

/// The PORTABILITY rows; one line when there is nothing to report.
fn portability_rows(r: &Report, pen: &Pen) -> Vec<String> {
    let (s, p) = (&r.summary, &r.data_provenance);
    let Pen {
        ok, bad, warn, dot, ..
    } = *pen;
    let mut out = Vec::new();
    if s.hazards > 0 {
        let mut lits: Vec<&crate::extractor::Literal> =
            r.hazards.iter().flat_map(|h| &h.literals).collect();
        // Literals that break the deployment first.
        lits.sort_by_key(|l| l.impact);
        let values = unique(lits.iter().map(|l| l.value.as_str()));
        let resources = unique(r.hazards.iter().map(|h| h.logical_id.as_str())).len();
        let breaking = r
            .hazards
            .iter()
            .filter(|h| {
                h.literals
                    .iter()
                    .any(|l| l.impact == crate::extractor::Impact::Breaks)
            })
            .count();
        // Room for the breaking count, when not all of them break.
        let room = if breaking < s.hazards { 1 } else { 3 };
        let shown = list(
            &values
                .iter()
                .map(|v| format!("`{}`", clean(v)))
                .collect::<Vec<_>>(),
            room,
        );
        // The count is property values (fields) that contain a literal; the detail
        // names the distinct literals, so the two do not have to match.
        pen.row(
            &mut out,
            warn,
            YELLOW,
            "hardcoded fields",
            s.hazards,
            format!(
                "{}{resources} {}: {shown}",
                if breaking < s.hazards {
                    format!("{breaking} breaking{dot}")
                } else {
                    String::new()
                },
                plural(resources, "resource")
            ),
        );
    }
    if s.environment_literals > 0 {
        let envs: Vec<String> = r
            .environment_literals
            .iter()
            .map(|e| clean(&env_label(&e.env)))
            .collect();
        let verb = match p.source_format {
            SourceFormat::Cloudformation => "synthesized",
            SourceFormat::TerraformPlan => "planned",
        };
        pen.row(
            &mut out,
            warn,
            YELLOW,
            "env literals",
            s.environment_literals,
            format!("{verb} for {}", list(&envs, 2)),
        );
    }
    let rules_of = |keep: &dyn Fn(&Deviation) -> bool| {
        unique(
            r.deviations
                .iter()
                .filter(|d| keep(d))
                .map(|d| d.rule.replace('-', " ")),
        )
    };
    // Where the rules come from: the ESC User Guide, other AWS pages, or both.
    let sources_of = |keep: &dyn Fn(&Deviation) -> bool| {
        let by = |b: DecidedBy| r.deviations.iter().any(|d| keep(d) && d.decided_by == b);
        match (by(DecidedBy::Guide), by(DecidedBy::Rule)) {
            (true, true) => "ESC User Guide, AWS docs",
            (false, true) => "AWS docs",
            _ => "ESC User Guide",
        }
    };
    if s.deviations > 0 {
        let rules = rules_of(&|d| d.blocks());
        // A documented deviation means the feature does not work in the target.
        pen.row(
            &mut out,
            bad,
            RED,
            "deviations",
            s.deviations,
            format!("{} ({})", list(&rules, 2), sources_of(&|d| d.blocks())),
        );
    }
    if s.guide_conflicts > 0 {
        let rules = rules_of(&|d| d.conflict.is_some());
        pen.row(
            &mut out,
            warn,
            YELLOW,
            "guide conflicts",
            s.guide_conflicts,
            format!("{} (guide likely outdated)", list(&rules, 2)),
        );
    }
    if s.caveats > 0 {
        let rules = rules_of(&|d| d.severity == Severity::Caveat);
        pen.row(
            &mut out,
            warn,
            YELLOW,
            "caveats",
            s.caveats,
            format!(
                "{} ({})",
                list(&rules, 2),
                sources_of(&|d| d.severity == Severity::Caveat)
            ),
        );
    }
    if s.dependencies > 0 {
        let rules = unique(r.dependencies.iter().map(|d| d.rule.replace('-', " ")));
        pen.row(
            &mut out,
            warn,
            YELLOW,
            "dependencies",
            s.dependencies,
            format!("{} (AWS docs)", list(&rules, 2)),
        );
    }
    if s.account_blockers > 0 {
        pen.row(
            &mut out,
            bad,
            RED,
            "account blockers",
            s.account_blockers,
            "the target account blocks the deployment (live)".into(),
        );
    }
    if s.depth_blockers > 0 {
        pen.row(
            &mut out,
            bad,
            RED,
            "depth blockers",
            s.depth_blockers,
            if r.findings
                .iter()
                .flat_map(|f| &f.depth)
                .any(|d| d.kind == crate::depth::DepthKind::Property && d.offered == Some(false))
            {
                "values or properties the region does not offer".into()
            } else {
                "values the region does not offer".into()
            },
        );
    }
    if out.is_empty() {
        out.push(format!(
            "  {} nothing hardcoded or region-specific",
            pen.paint(GREEN, ok)
        ));
    }
    out
}

/// The REQUIRED CHANGES heading and the changes, grouped by what they say in short,
/// worst tier first.
fn change_lines(r: &Report, pen: &Pen) -> Vec<String> {
    let (s, st) = (&r.summary, pen.st);
    let Pen {
        ok,
        bad,
        dot,
        arrow,
        ..
    } = *pen;
    let mut out = Vec::new();
    let tiers = [
        (Tier::Flag, s.flags),
        (Tier::Propose, s.proposals),
        (Tier::Fix, s.fixes),
    ];
    let counts: Vec<String> = tiers
        .iter()
        .filter(|(_, n)| *n > 0)
        .map(|(t, n)| format!("{n} {}", t.label()))
        .collect();
    out.push(format!(
        "{}  {}",
        pen.paint(BOLD, "  REQUIRED CHANGES"),
        if counts.is_empty() {
            "none".to_string()
        } else {
            counts.join(dot)
        }
    ));
    let groups = change_groups(r);
    if groups.is_empty() {
        out.push(format!("  {} no changes needed", pen.paint(GREEN, ok)));
    }
    let shown = &groups[..groups.len().min(MAX_CHANGE_LINES)];
    let tier_label = |grp: &Group| match grp.n {
        1 => grp.tier.label().to_string(),
        n if st.unicode => format!("{} ×{n}", grp.tier.label()),
        n => format!("{} ({n})", grp.tier.label()),
    };
    let tier_w = shown
        .iter()
        .map(|x| tier_label(x).chars().count())
        .max()
        .unwrap_or(0);
    let ell = pen.g("…", "~");
    let what_w = shown
        .iter()
        .map(|x| x.shown_what(ell).chars().count())
        .max()
        .unwrap_or(0);
    for grp in shown {
        // Colors mean one thing each: red blocks deployment, yellow warns, green is
        // fine, cyan is code to type, dim is metadata. Only a flag blocks, so only
        // its glyph is colored; the tier word stays plain.
        let glyph = match grp.tier {
            Tier::Flag => pen.paint(RED, bad),
            Tier::Propose | Tier::Fix => pen.g("●", "*").to_string(),
        };
        let action = clip(&grp.action, MAX_ACTION, ell);
        // A replacement is code to type: cyan instead of backticks when colored.
        let action = match action.strip_prefix('`').and_then(|a| a.strip_suffix('`')) {
            Some(code) if grp.code && st.color => pen.paint(CYAN, code),
            _ => action,
        };
        let what = grp.shown_what(ell);
        let pad = what_w - what.chars().count();
        let tier = tier_label(grp);
        out.push(format!(
            "  {glyph} {tier:<tier_w$}  {what}{}  {} {action}",
            " ".repeat(pad),
            pen.paint(DIM, arrow),
        ));
        // The resource types behind a service-level line, under the "what" column.
        if !grp.subjects.is_empty() {
            let res = if grp.resources > 1 {
                format!("{} resources: ", grp.resources)
            } else {
                String::new()
            };
            let types = clip(
                &format!("{res}{}", list(&grp.subjects, 2)),
                MAX_WHAT + 4 + MAX_ACTION,
                ell,
            );
            out.push(format!(
                "  {}  {}",
                " ".repeat(tier_w + 2),
                pen.paint(DIM, &types)
            ));
        }
    }
    if groups.len() > MAX_CHANGE_LINES {
        let rest: usize = groups[MAX_CHANGE_LINES..].iter().map(|x| x.n).sum();
        out.push(pen.paint(
            DIM,
            &format!("  {} {rest} more in the JSON report", pen.g("…", "...")),
        ));
    }
    out
}

/// The warnings, each command on its own line after its prose.
fn warning_lines(r: &Report, pen: &Pen) -> Vec<String> {
    let warn = pen.warn;
    let mut out = Vec::new();
    if !r.warnings.is_empty() {
        out.push(String::new());
    }
    for (i, w) in r.warnings.iter().enumerate() {
        if i > 0 {
            out.push(String::new());
        }
        let split = r.warning_commands.iter().find(|(k, _, _)| *k == i);
        let text = clean(split.map_or(w.message.as_str(), |(_, prose, _)| prose.as_str()));
        let cmd = split.map(|(_, _, c)| clean(c));
        for (k, l) in wrap(&text, WRAP - 2).iter().enumerate() {
            let lead = if k == 0 {
                pen.paint(YELLOW, warn)
            } else {
                " ".repeat(warn.chars().count())
            };
            out.push(format!("{lead} {l}"));
        }
        if let Some(c) = cmd {
            out.push(format!("  {}", pen.paint(DIM, CDK_HINT)));
            out.push(format!(
                "    {} {}",
                pen.paint(DIM, "$"),
                pen.paint(CYAN, &c)
            ));
        }
    }
    out
}

/// The glyphs and colors of the terminal summary in one style.
#[derive(Clone, Copy)]
struct Pen {
    st: Style,
    ok: &'static str,
    bad: &'static str,
    warn: &'static str,
    unk: &'static str,
    dot: &'static str,
    arrow: &'static str,
}

const RED: &str = "31";
const YELLOW: &str = "33";
const GREEN: &str = "32";
const CYAN: &str = "36";
const BOLD: &str = "1";
const DIM: &str = "2;3";

impl Pen {
    fn new(st: Style) -> Self {
        let g = |uni, ascii| if st.unicode { uni } else { ascii };
        Self {
            st,
            ok: g("✔", "ok"),
            bad: g("✘", "x"),
            warn: g("⚠", "!"),
            unk: "?",
            dot: g(" · ", ", "),
            arrow: g("→", "->"),
        }
    }

    fn g(&self, uni: &'static str, ascii: &'static str) -> &'static str {
        if self.st.unicode { uni } else { ascii }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.st.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    /// Rows: glyph, color, label, count, detail. Zero rows are hidden, except
    /// "available" and "not available", which always answer the main question.
    fn row(
        &self,
        out: &mut Vec<String>,
        glyph: &str,
        code: &str,
        label: &str,
        n: usize,
        detail: String,
    ) {
        let count = self.paint(BOLD, &format!("{n:>4}"));
        let detail = if detail.is_empty() {
            String::new()
        } else {
            format!("   {}", clip(&detail, MAX_DETAIL, self.g("…", "~")))
        };
        // ASCII glyphs differ in width ("ok", "x"); pad them so labels line up.
        let w = if self.st.unicode { 1 } else { 2 };
        out.push(format!(
            "  {} {label:<18}{count}{detail}",
            self.paint(code, &format!("{glyph:<w$}"))
        ));
    }
}

struct Group {
    tier: Tier,
    what: String,
    action: String,
    /// `action` is a replacement to type, not prose.
    code: bool,
    n: usize,
    /// Distinct resource types, for lines that name a service or feature.
    subjects: Vec<String>,
    resources: usize,
    /// " in N resources", kept apart so clipping `what` never cuts the count.
    count: String,
}

impl Group {
    fn shown_what(&self, ellipsis: &str) -> String {
        let max = MAX_WHAT.saturating_sub(self.count.chars().count());
        format!("{}{}", clip(&self.what, max, ellipsis), self.count)
    }
}

/// Required changes that read the same in short, worst tier first, then the most
/// frequent. A group of several resources says how many.
fn change_groups(r: &Report) -> Vec<Group> {
    let format_of = |c: &RequiredChange| match r.data_provenance.source_format {
        SourceFormat::TerraformPlan => 2,
        SourceFormat::Cloudformation if c.cdk_path.is_some() => 1,
        SourceFormat::Cloudformation => 0,
    };
    let mut groups: Vec<(Group, Vec<&str>)> = Vec::new();
    for c in &r.required_changes {
        // A single, uniform replacement is the most precise action there is.
        let reps: Vec<&str> = c
            .edits
            .iter()
            .map(|e| match format_of(c) {
                1 => e.replace.cdk.as_str(),
                2 => e.replace.terraform.as_str(),
                _ => e.replace.cloudformation.as_str(),
            })
            .collect();
        let (action, code) = match reps.first() {
            Some(first) if reps.iter().all(|x| x == first) => (format!("`{first}`"), true),
            _ => (c.brief.action.clone(), false),
        };
        let (what, action) = (clean(&c.brief.what), clean(&action));
        let i = match groups
            .iter()
            .position(|(x, _)| x.tier == c.tier && x.what == what && x.action == action)
        {
            Some(i) => {
                groups[i].0.n += 1;
                i
            }
            None => {
                groups.push((
                    Group {
                        tier: c.tier,
                        what,
                        action,
                        code,
                        n: 1,
                        subjects: Vec::new(),
                        resources: 0,
                        count: String::new(),
                    },
                    Vec::new(),
                ));
                groups.len() - 1
            }
        };
        let (x, ids) = &mut groups[i];
        if !ids.contains(&c.logical_id.as_str()) {
            ids.push(&c.logical_id);
        }
        if let Some(t) = &c.brief.subject
            && !x.subjects.contains(&clean(t))
        {
            x.subjects.push(clean(t));
        }
    }
    let mut out: Vec<Group> = groups
        .into_iter()
        .map(|(mut x, ids)| {
            x.resources = ids.len();
            // Without a subject line, say how many resources share the line.
            if x.subjects.is_empty() && ids.len() > 1 {
                x.count = format!(" in {} resources", ids.len());
            }
            x
        })
        .collect();
    out.sort_by(|a, b| {
        b.tier
            .cmp(&a.tier)
            .then(b.n.cmp(&a.n))
            .then(a.what.cmp(&b.what))
    });
    out
}

/// The distinct resource types of the findings that match, at most two, each with its
/// product's roadmap state.
fn types_of(r: &Report, keep: impl Fn(&Finding) -> bool) -> String {
    let types = unique(
        r.findings
            .iter()
            .filter(|f| keep(f))
            .map(|f| match &f.roadmap {
                Some(rm) => format!("{} ({})", clean(&f.resource_type), rm.short()),
                None => clean(&f.resource_type),
            }),
    );
    list(&types, 2)
}

/// Text from the input with control characters replaced, so a template cannot send
/// terminal escape sequences and every character takes one column.
pub(crate) fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn list(items: &[String], max: usize) -> String {
    match items.len() {
        n if n <= max => items.join(", "),
        n => format!("{}, +{} more", items[..max].join(", "), n - max),
    }
}

/// Greedy word wrap; a word longer than the width stays whole on its own line.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for w in text.split_whitespace() {
        if !cur.is_empty() && cur.chars().count() + 1 + w.chars().count() > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(w);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
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

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        word.into()
    } else {
        format!("{word}s")
    }
}

fn clip(s: &str, max: usize, ellipsis: &str) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max - 1).collect();
        t.push_str(ellipsis);
        t
    }
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
    use super::*;
    use crate::extractor::{HazardKind, Impact};
    use crate::provider::{PublicData, guide, knowledge, partition, terraform};
    use crate::{depth, deviation, extractor, matcher, reader};

    /// Marks every property of every object in a JSON schema as required: the reports
    /// always write every key, null where a value is absent.
    fn require_all(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(m) => {
                if let Some(serde_json::Value::Object(props)) = m.get("properties") {
                    let keys: Vec<_> = props.keys().cloned().map(serde_json::Value::from).collect();
                    m.insert("required".into(), keys.into());
                }
                m.values_mut().for_each(require_all);
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(require_all),
            _ => {}
        }
    }

    /// The committed `schema/<file>` is the JSON Schema of `T`. Set `UPDATE_GOLDEN=1`
    /// to rewrite it.
    pub(crate) fn assert_committed_schema<T: schemars::JsonSchema>(file: &str) {
        let mut v = serde_json::to_value(schemars::schema_for!(T)).unwrap();
        require_all(&mut v);
        let text = format!("{}\n", serde_json::to_string_pretty(&v).unwrap());
        let path = format!("{}/schema/{file}", env!("CARGO_MANIFEST_DIR"));
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::write(&path, &text).unwrap();
        }
        assert!(
            std::fs::read_to_string(&path).unwrap_or_default() == text,
            "schema/{file} is out of date: run UPDATE_GOLDEN=1 cargo test schema, and decide whether SCHEMA_VERSION changes"
        );
    }

    fn data() -> PublicData {
        PublicData {
            partition: partition::facts("eusc-de-east-1").unwrap(),
            knowledge: knowledge::tests::fixture(),
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

    fn prov(format: SourceFormat, envs: Vec<DeployEnv>) -> Provenance {
        Provenance {
            tool_version: "test".into(),
            source_format: format,
            target_region: "eusc-de-east-1".into(),
            target_account: None,
            input_environments: envs,
            partitions_version: "test".into(),
            knowledge: Some(KnowledgeProvenance {
                url: knowledge::URL.into(),
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
        to_json(&fixed(input))
    }

    fn fixed(input: &str) -> Report {
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
        depth::resolve(&mut depth, &offered, depth::DepthSource::Knowledge);
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
            schema_types: crate::provider::schema::types(&t).len(),
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
                    },
                    "unicode",
                ),
                (
                    Style {
                        color: false,
                        unicode: false,
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
                },
            );
            assert!(ascii.is_ascii(), "{name}: non-ASCII in ASCII mode");
            let text = text_summary(
                &r,
                Style {
                    color: false,
                    unicode: true,
                },
            );
            let lines: Vec<&str> = text.lines().collect();
            let start = lines
                .iter()
                .position(|l| l.starts_with("  REQUIRED CHANGES"))
                .unwrap();
            let block: Vec<&str> = lines[start + 1..]
                .iter()
                .take_while(|l| !l.is_empty())
                .copied()
                .collect();
            let arrows: std::collections::BTreeSet<usize> = block
                .iter()
                .filter_map(|l| l.char_indices().position(|(_, ch)| ch == '→'))
                .collect();
            assert!(arrows.len() <= 1, "{name}: arrows at {arrows:?}");
            let shown: usize = block
                .iter()
                .filter(|l| l.contains('→'))
                .map(|l| {
                    l.split_once('×')
                        .and_then(|(_, rest)| rest.split_whitespace().next())
                        .and_then(|n| n.parse().ok())
                        .unwrap_or(1)
                })
                .sum::<usize>()
                + block
                    .iter()
                    .filter_map(|l| l.trim().strip_prefix("… "))
                    .filter_map(|l| l.split_whitespace().next()?.parse::<usize>().ok())
                    .sum::<usize>();
            assert_eq!(shown, r.required_changes.len(), "{name}");
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
            },
        );
        assert!(text.contains(&format!("    $ {cmd}\n")), "{text}");
        assert!(!text.contains(&format!("deployed. {CDK_HINT}")), "{text}");
    }

    #[test]
    fn colored_replacements_are_cyan_without_backticks() {
        let (r, _) = fixture_reports().remove(0);
        let text = text_summary(
            &r,
            Style {
                color: true,
                unicode: true,
            },
        );
        assert!(
            text.contains("\x1b[36marn:${AWS::Partition}:\x1b[0m"),
            "{text}"
        );
        let plain = text_summary(
            &r,
            Style {
                color: false,
                unicode: true,
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
            },
        );
        let block: Vec<&str> = text
            .lines()
            .skip_while(|l| !l.starts_with("  REQUIRED CHANGES"))
            .skip(1)
            .take_while(|l| !l.is_empty())
            .collect();
        assert_eq!(
            block.iter().filter(|l| l.contains('→')).count(),
            MAX_CHANGE_LINES
        );
        let rest = r.required_changes.len() - MAX_CHANGE_LINES;
        assert!(
            block.last().unwrap().contains(&format!("{rest} more")),
            "{text}"
        );
    }

    #[test]
    fn control_characters_from_the_input_are_not_printed() {
        assert_eq!(clean("AWS::Fo\u{1b}]0;x\u{7}o::Bar"), "AWS::Fo?]0;x?o::Bar");
    }

    #[test]
    fn wrap_keeps_long_words_whole() {
        assert_eq!(wrap("a verylongword b", 4), vec!["a", "verylongword", "b"]);
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
        assert_eq!(r.zones.unwrap().used.len(), 3);
        assert!(
            build(
                prov,
                vec![],
                scan,
                GuideFindings::default(),
                vec![],
                &Context {
                    target_zones: Some(3),
                    ..Context::default()
                }
            )
            .zones
            .is_none()
        );
    }

    #[test]
    fn timestamp_shape() {
        let t = now_utc();
        assert_eq!(t.len(), 20);
        assert!(t.ends_with('Z') && t.as_bytes()[10] == b'T');
    }

    /// The JSON Schema of the report. Every key is always emitted, so every property
    /// is required.
    fn schema() -> serde_json::Value {
        let mut v = serde_json::to_value(schemars::schema_for!(Report)).unwrap();
        require_all(&mut v);
        v
    }

    /// Every key the schema declares is in the JSON, also where the value is absent.
    fn missing_keys(
        v: &serde_json::Value,
        schema: &serde_json::Value,
        root: &serde_json::Value,
        at: &str,
        out: &mut Vec<String>,
    ) {
        if let Some(r) = schema["$ref"].as_str() {
            let name = r.trim_start_matches("#/$defs/");
            return missing_keys(v, &root["$defs"][name], root, at, out);
        }
        if v.is_null() {
            return;
        }
        if let Some(branches) = schema["anyOf"].as_array().or(schema["oneOf"].as_array()) {
            for b in branches.iter().filter(|b| b["type"] != "null") {
                missing_keys(v, b, root, at, out);
            }
        }
        if let Some(props) = schema["properties"].as_object() {
            for (k, s) in props {
                match v.get(k) {
                    Some(x) => missing_keys(x, s, root, &format!("{at}.{k}"), out),
                    None => out.push(format!("{at}.{k}")),
                }
            }
        }
        if let (Some(items), Some(a)) = (schema.get("items"), v.as_array()) {
            for (i, x) in a.iter().enumerate() {
                missing_keys(x, items, root, &format!("{at}[{i}]"), out);
            }
        }
    }

    #[test]
    fn every_key_is_always_present() {
        let schema = schema();
        for input in [
            crate::test_inputs::SAMPLE_TEMPLATE,
            include_str!("../tests/fixtures/tf-plan.json"),
            crate::test_inputs::CUSTOM_RESOURCES_TEMPLATE,
        ] {
            let v: serde_json::Value = serde_json::from_str(&fixed_report(input)).unwrap();
            let mut missing = Vec::new();
            missing_keys(&v, &schema, &schema, "", &mut missing);
            assert!(missing.is_empty(), "{missing:?}");
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
            [WarningCode::KnowledgeRegionUnlisted]
        );
        let text = text_summary(&r, Style::default());
        let sources = text.lines().nth(1).unwrap_or_default();
        assert_eq!(sources.trim(), "public mode", "{text}");
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
        assert!(
            text.contains("lambda runtime create blocked (AWS docs)"),
            "{text}"
        );
        assert!(
            text.lines()
                .any(|l| l.contains("dependencies") && l.contains("(AWS docs)")),
            "{text}"
        );
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
        let mut depth = crate::provider::schema::checks(&t, &schemas);
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
        assert!(
            text.contains("values or properties the region does not offer"),
            "{text}"
        );
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
        assert!(text.contains("account blockers"), "{text}");
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
        assert_eq!(by(CauseType::Availability), [DecidedBy::Knowledge]);
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
        assert_committed_schema::<Report>("report.schema.json");
    }
}
