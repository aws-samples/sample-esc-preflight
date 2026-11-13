//! The JSON report and its human-readable summary.

use serde::Serialize;

use crate::deviation::{Deviation, Documented, GuideFindings, GuideProvenance, Severity};
use crate::extractor::{EnvLiterals, Scan};
use crate::matcher::{Finding, Verdict};
use crate::model::{DeployEnv, OutOfScope, SourceFormat};
use crate::provider::knowledge::State;
use crate::provider::live::LiveProvenance;
use crate::remediation::{self, Context, RequiredChange, Tier};

#[derive(Debug, Clone, Serialize)]
pub struct TerraformProvenance {
    pub aws_provider_version: String,
    pub awscc_provider_version: String,
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KnowledgeProvenance {
    pub url: String,
    pub calls: usize,
    /// Types, services or operations the server does not know.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unknown: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Provenance {
    pub tool_version: String,
    pub source_format: SourceFormat,
    pub mode: String,
    pub target_region: String,
    /// Where the input was synthesized (CDK cloud assembly) or planned (Terraform).
    pub input_environments: Vec<DeployEnv>,
    /// botocore release of the bundled partition data.
    pub partitions_version: String,
    pub knowledge: KnowledgeProvenance,
    /// ESC User Guide service pages, when the target is in its partition.
    pub user_guide: Option<GuideProvenance>,
    pub fetched_at: String,
    pub terraform: Option<TerraformProvenance>,
    pub live: Option<LiveProvenance>,
}

#[derive(Debug, Clone, Default, Serialize)]
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
    /// Resources that use a feature the ESC User Guide documents as not available.
    pub deviations: usize,
    /// Guide restrictions the Knowledge MCP data contradicts; warnings, not blockers.
    pub guide_conflicts: usize,
    /// Features that work with an ESC difference the guide documents.
    pub caveats: usize,
    /// Required changes by tier: applied as stated, applied after a yes, owner decides.
    pub fixes: usize,
    pub proposals: usize,
    pub flags: usize,
}

/// The input spreads over more zones of its own environment than the target offers.
#[derive(Debug, Clone, Serialize)]
pub struct ZoneCheck {
    pub used: Vec<String>,
    pub target_offers: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub data_provenance: Provenance,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub hazards: Vec<crate::extractor::Hazard>,
    pub deviations: Vec<Deviation>,
    /// Differences the ESC User Guide documents for the services in the input.
    pub documented_differences: Vec<Documented>,
    pub environment_literals: Vec<EnvLiterals>,
    pub zones: Option<ZoneCheck>,
    pub required_changes: Vec<RequiredChange>,
    /// Terraform resources of providers other than aws and awscc.
    pub out_of_scope: Vec<OutOfScope>,
    pub warnings: Vec<String>,
    /// For a warning that carries a command: its index, the prose without the
    /// command, and the command, so the terminal shows the command on its own line.
    /// The JSON warning has both in one sentence.
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
    let target_zones = ctx.target_zones;
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
            // Without a known service (a type only the live registry knows), the line
            // names the type instead.
            let svc = f
                .service
                .as_deref()
                .unwrap_or("the resource type's service");
            let type_gap = f.type_gap && !f.resource_type.starts_with("Custom::");
            let short = if f.resource_type.starts_with("Custom::") {
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
                    .single_region
                    .then(|| crate::deviation::substitute_for(&f.resource_type))
                    .flatten()
                    .map(|m| m.action);
                remediation::brief(
                    what,
                    substitute.unwrap_or_else(|| {
                        "use another type or deploy it without CloudFormation".into()
                    }),
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
            changes.push(RequiredChange::new(
                &f.logical_id,
                Tier::Flag,
                match (&f.service, f.resource_type.starts_with("Custom::")) {
                    (Some(svc), true) => format!(
                        "{} calls {svc}, which is not available in {target}",
                        f.resource_type
                    ),
                    _ => format!("{} is not available in {target}", f.resource_type),
                },
                f.note.clone().unwrap_or_default(),
                short,
            ));
        }
    }
    changes.extend(
        guide
            .deviations
            .iter()
            .filter(|d| d.blocks())
            .map(|d| remediation::deviation(d, ctx)),
    );
    changes.extend(hazards.iter().flat_map(|h| remediation::hazard(h, ctx)));
    let used: Vec<String> = env_literals
        .iter()
        .flat_map(|e| e.zones.iter().cloned())
        .collect();
    let zones = target_zones.filter(|n| used.len() > *n).map(|n| ZoneCheck {
        used,
        target_offers: n,
    });
    if let Some(z) = &zones {
        s.depth_blockers += 1;
        changes.push(RequiredChange::new(
            "*",
            Tier::Flag,
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
    let (resynth, produced) = match provenance.source_format {
        SourceFormat::Cloudformation => ("synthesize again for", "synthesized"),
        SourceFormat::TerraformPlan => ("plan again for", "planned"),
    };
    let (produce, retarget) = match provenance.source_format {
        SourceFormat::Cloudformation => (
            "Synthesize",
            "Set the CDK stack environment to the target account and Region, or remove it to make the stack environment-agnostic, and synthesize again. These values then change together.",
        ),
        SourceFormat::TerraformPlan => (
            "Plan",
            "Set the provider Region to the target Region and plan again with credentials for the target account. These values then change together.",
        ),
    };
    for e in &env_literals {
        let mut c = RequiredChange::new(
            "*",
            Tier::Propose,
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
        c.cdk_path = findings
            .iter()
            .find(|f| f.logical_id == c.logical_id)
            .and_then(|f| f.cdk_path.clone());
        match c.tier {
            Tier::Fix => s.fixes += 1,
            Tier::Propose => s.proposals += 1,
            Tier::Flag => s.flags += 1,
        }
    }
    let mut warnings: Vec<String> = Vec::new();
    let mut warning_commands = Vec::new();
    for region in provenance
        .input_environments
        .iter()
        .filter_map(|e| e.region.as_ref())
        .filter(|r| **r != provenance.target_region)
    {
        let target = &provenance.target_region;
        // Only a CDK cloud assembly states an environment for CloudFormation input.
        let cmd = (provenance.source_format == SourceFormat::Cloudformation)
            .then(|| format!("AWS_REGION={target} cdk synth"));
        let how = cmd
            .as_ref()
            .map(|c| format!(" {CDK_HINT} {c}"))
            .unwrap_or_default();
        let prose = format!(
            "The input was produced for {region}, not {target}. {produce} it for the target region so region-specific values resolve as they will be deployed."
        );
        let w = format!("{prose}{how}");
        if warnings.contains(&w) {
            continue;
        }
        if let Some(c) = cmd {
            warning_commands.push((warnings.len(), prose, c));
        }
        warnings.push(w);
    }
    if !provenance.knowledge.unknown.is_empty() {
        warnings.push(format!(
            "The Knowledge MCP data does not know {}; only live mode can assess these resources.",
            provenance.knowledge.unknown.join(", ")
        ));
    }
    let mut conflicts: Vec<String> = Vec::new();
    for d in guide.deviations.iter().filter(|d| d.conflict.is_some()) {
        let c = format!("{} ({})", d.conflict.as_deref().unwrap_or_default(), d.rule);
        if !conflicts.contains(&c) {
            conflicts.push(c);
        }
    }
    if !conflicts.is_empty() {
        warnings.push(format!(
            "The ESC User Guide says these features are not available, while the Knowledge MCP data lists them as available: {}. The guide is likely outdated. Ask your AWS team to confirm and to have the guide corrected.",
            conflicts.join(", ")
        ));
    }
    if let Some(g) = &provenance.user_guide {
        if !g.stale_rules.is_empty() {
            warnings.push(format!(
                "These rules match the input, but the ESC User Guide no longer contains the sentence they quote, so they were skipped: {}. Check the guide: the restriction may have been lifted or reworded.",
                g.stale_rules.join(", ")
            ));
        }
        if !g.unmapped_pages.is_empty() {
            warnings.push(format!(
                "ESC User Guide pages not mapped to a service, so their differences are not attached: {}.",
                g.unmapped_pages.join(", ")
            ));
        }
    }
    Report {
        data_provenance: provenance,
        summary: s,
        findings,
        hazards,
        deviations: guide.deviations,
        documented_differences: guide.documented,
        environment_literals: env_literals,
        zones,
        required_changes: changes,
        out_of_scope,
        warnings,
        warning_commands,
    }
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

pub fn to_json(report: &Report) -> String {
    let mut s = serde_json::to_string_pretty(report).expect("report serializes");
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
    let paint = |code: &str, text: &str| {
        if st.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    };
    let g = |uni: &'static str, ascii: &'static str| if st.unicode { uni } else { ascii };
    let (ok, bad, warn, unk) = (g("✔", "ok"), g("✘", "x"), g("⚠", "!"), "?");
    let dot = g(" · ", ", ");
    let arrow = g("→", "->");
    let (red, yellow, green, cyan, bold, dim) = ("31", "33", "32", "36", "1", "2;3");

    let mut out = vec![
        paint(
            bold,
            &format!(
                "{}esc-preflight{dot}{} resources{dot}{}",
                g("◆ ", ""),
                s.resources,
                p.target_region
            ),
        ),
        format!(
            "  {}",
            paint(
                dim,
                &format!(
                    "Knowledge MCP{}{dot}{} mode",
                    p.user_guide
                        .as_ref()
                        .map(|g| format!("{dot}ESC User Guide {} pages", g.pages))
                        .unwrap_or_default(),
                    p.mode
                )
            )
        ),
        String::new(),
    ];

    // Rows: glyph, color, label, count, detail. Zero rows are hidden, except
    // "available" and "not available", which always answer the main question.
    let row =
        |out: &mut Vec<String>, glyph: &str, code: &str, label: &str, n: usize, detail: String| {
            let count = paint(bold, &format!("{n:>4}"));
            let detail = if detail.is_empty() {
                String::new()
            } else {
                format!("   {}", clip(&detail, MAX_DETAIL, g("…", "~")))
            };
            // ASCII glyphs differ in width ("ok", "x"); pad them so labels line up.
            let w = if st.unicode { 1 } else { 2 };
            out.push(format!(
                "  {} {label:<18}{count}{detail}",
                paint(code, &format!("{glyph:<w$}"))
            ));
        };

    out.push(paint(bold, "  AVAILABILITY"));
    row(&mut out, ok, green, "available", s.available, String::new());
    let na = types_of(r, |f| f.verdict == Verdict::NotAvailable);
    row(
        &mut out,
        if s.not_available > 0 { bad } else { ok },
        if s.not_available > 0 { red } else { green },
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
        row(
            &mut out,
            unk,
            yellow,
            "cannot assess",
            s.cannot_assess,
            detail,
        );
    }
    if s.disputed > 0 {
        let d = types_of(r, |f| f.verdict == Verdict::Disputed);
        row(&mut out, warn, yellow, "disputed", s.disputed, d);
    }
    if s.divergences > 0 {
        let d = types_of(r, |f| f.divergence);
        row(&mut out, warn, yellow, "live vs public", s.divergences, d);
    }

    out.push(String::new());
    out.push(paint(bold, "  PORTABILITY"));
    let before = out.len();
    if s.hazards > 0 {
        let mut values: Vec<&str> = Vec::new();
        for l in r.hazards.iter().flat_map(|h| &h.literals) {
            if !values.contains(&l.value.as_str()) {
                values.push(&l.value);
            }
        }
        let resources = distinct(r.hazards.iter().map(|h| h.logical_id.as_str()));
        let shown = list(
            &values
                .iter()
                .map(|v| format!("`{}`", clean(v)))
                .collect::<Vec<_>>(),
            3,
        );
        // The count is property values (fields) that contain a literal; the detail
        // names the distinct literals, so the two do not have to match.
        row(
            &mut out,
            warn,
            yellow,
            "hardcoded fields",
            s.hazards,
            format!("{resources} {}: {shown}", plural(resources, "resource")),
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
        row(
            &mut out,
            warn,
            yellow,
            "env literals",
            s.environment_literals,
            format!("{verb} for {}", list(&envs, 2)),
        );
    }
    let rules_of = |keep: &dyn Fn(&Deviation) -> bool| {
        let mut rules: Vec<String> = Vec::new();
        for d in r.deviations.iter().filter(|d| keep(d)) {
            let l = d.rule.replace('-', " ");
            if !rules.contains(&l) {
                rules.push(l);
            }
        }
        rules
    };
    if s.deviations > 0 {
        let rules = rules_of(&|d| d.blocks());
        // A documented deviation means the feature does not work in the target.
        row(
            &mut out,
            bad,
            red,
            "deviations",
            s.deviations,
            format!("{} (ESC User Guide)", list(&rules, 2)),
        );
    }
    if s.guide_conflicts > 0 {
        let rules = rules_of(&|d| d.conflict.is_some());
        row(
            &mut out,
            warn,
            yellow,
            "guide conflicts",
            s.guide_conflicts,
            format!("{} (guide likely outdated)", list(&rules, 2)),
        );
    }
    if s.caveats > 0 {
        let rules = rules_of(&|d| d.severity == Severity::Caveat);
        row(
            &mut out,
            warn,
            yellow,
            "caveats",
            s.caveats,
            format!("{} (ESC User Guide)", list(&rules, 2)),
        );
    }
    if s.depth_blockers > 0 {
        row(
            &mut out,
            bad,
            red,
            "depth blockers",
            s.depth_blockers,
            "values the region does not offer".into(),
        );
    }
    if out.len() == before {
        out.push(format!(
            "  {} nothing hardcoded or region-specific",
            paint(green, ok)
        ));
    }

    // Required changes, grouped by what they say in short, worst tier first.
    out.push(String::new());
    let tiers = [
        (Tier::Flag, s.flags, "flag"),
        (Tier::Propose, s.proposals, "propose"),
        (Tier::Fix, s.fixes, "fix"),
    ];
    let counts: Vec<String> = tiers
        .iter()
        .filter(|(_, n, _)| *n > 0)
        .map(|(_, n, l)| format!("{n} {l}"))
        .collect();
    out.push(format!(
        "{}  {}",
        paint(bold, "  REQUIRED CHANGES"),
        if counts.is_empty() {
            "none".to_string()
        } else {
            counts.join(dot)
        }
    ));
    let groups = change_groups(r);
    if groups.is_empty() {
        out.push(format!("  {} no changes needed", paint(green, ok)));
    }
    let shown = &groups[..groups.len().min(MAX_CHANGE_LINES)];
    let tier_label = |grp: &Group| match grp.n {
        1 => grp.tier_name.to_string(),
        n if st.unicode => format!("{} ×{n}", grp.tier_name),
        n => format!("{} ({n})", grp.tier_name),
    };
    let tier_w = shown
        .iter()
        .map(|x| tier_label(x).chars().count())
        .max()
        .unwrap_or(0);
    let ell = g("…", "~");
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
            Tier::Flag => paint(red, bad),
            Tier::Propose | Tier::Fix => g("●", "*").to_string(),
        };
        let action = clip(&grp.action, MAX_ACTION, ell);
        // A replacement is code to type: cyan instead of backticks when colored.
        let action = match action.strip_prefix('`').and_then(|a| a.strip_suffix('`')) {
            Some(code) if grp.code && st.color => paint(cyan, code),
            _ => action,
        };
        let what = grp.shown_what(ell);
        let pad = what_w - what.chars().count();
        let tier = tier_label(grp);
        out.push(format!(
            "  {glyph} {tier:<tier_w$}  {what}{}  {} {action}",
            " ".repeat(pad),
            paint(dim, arrow),
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
                paint(dim, &types)
            ));
        }
    }
    if groups.len() > MAX_CHANGE_LINES {
        let rest: usize = groups[MAX_CHANGE_LINES..].iter().map(|x| x.n).sum();
        out.push(paint(
            dim,
            &format!("  {} {rest} more in the JSON report", g("…", "...")),
        ));
    }

    if !r.warnings.is_empty() {
        out.push(String::new());
    }
    for (i, w) in r.warnings.iter().enumerate() {
        if i > 0 {
            out.push(String::new());
        }
        let split = r.warning_commands.iter().find(|(k, _, _)| *k == i);
        let text = clean(split.map_or(w.as_str(), |(_, prose, _)| prose.as_str()));
        let cmd = split.map(|(_, _, c)| clean(c));
        for (k, l) in wrap(&text, WRAP - 2).iter().enumerate() {
            let lead = if k == 0 {
                paint(yellow, warn)
            } else {
                " ".repeat(warn.chars().count())
            };
            out.push(format!("{lead} {l}"));
        }
        if let Some(c) = cmd {
            out.push(format!("  {}", paint(dim, CDK_HINT)));
            out.push(format!("    {} {}", paint(dim, "$"), paint(cyan, &c)));
        }
    }
    out.join("\n") + "\n"
}

struct Group {
    tier: Tier,
    tier_name: &'static str,
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
        let tier_name = match c.tier {
            Tier::Flag => "flag",
            Tier::Propose => "propose",
            Tier::Fix => "fix",
        };
        let i = match groups.iter().position(|(x, _)| {
            x.tier == c.tier && x.what == clean(&c.brief.what) && x.action == clean(&action)
        }) {
            Some(i) => {
                groups[i].0.n += 1;
                i
            }
            None => {
                groups.push((
                    Group {
                        tier: c.tier,
                        tier_name,
                        what: clean(&c.brief.what),
                        action: clean(&action),
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
    let mut types: Vec<String> = Vec::new();
    for f in r.findings.iter().filter(|f| keep(f)) {
        let t = match &f.roadmap {
            Some(rm) => format!("{} ({})", clean(&f.resource_type), rm.short()),
            None => clean(&f.resource_type),
        };
        if !types.contains(&t) {
            types.push(t);
        }
    }
    list(&types, 2)
}

/// Text from the input with control characters replaced, so a template cannot send
/// terminal escape sequences and every character takes one column.
fn clean(s: &str) -> String {
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

fn distinct<'a>(it: impl Iterator<Item = &'a str>) -> usize {
    let mut seen: Vec<&str> = Vec::new();
    for x in it {
        if !seen.contains(&x) {
            seen.push(x);
        }
    }
    seen.len()
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
mod tests {
    use super::*;
    use crate::provider::{PublicData, guide, knowledge, partition, terraform};
    use crate::{depth, deviation, extractor, matcher, reader};

    fn data() -> PublicData {
        PublicData {
            partition: partition::facts("eusc-de-east-1").unwrap(),
            knowledge: knowledge::tests::fixture(),
            guide: Some(guide::tests::fixture()),
            tf: Some(terraform::tests::fixture()),
        }
    }

    fn prov(format: SourceFormat, envs: Vec<DeployEnv>) -> Provenance {
        Provenance {
            tool_version: "test".into(),
            source_format: format,
            mode: "public".into(),
            target_region: "eusc-de-east-1".into(),
            input_environments: envs,
            partitions_version: "test".into(),
            knowledge: KnowledgeProvenance {
                url: knowledge::URL.into(),
                calls: 0,
                unknown: vec![],
            },
            user_guide: None,
            fetched_at: "1970-01-01T00:00:00Z".into(),
            terraform: None,
            live: None,
        }
    }

    fn fixed_report(input: &str) -> String {
        to_json(&fixed(input))
    }

    fn fixed(input: &str) -> Report {
        fixed_t(reader::parse_text(input).unwrap())
    }

    fn fixed_t(t: crate::model::Template) -> Report {
        let data = data();
        let prov = Provenance {
            terraform: data
                .tf
                .as_ref()
                .filter(|_| t.format == SourceFormat::TerraformPlan)
                .map(|tf| TerraformProvenance {
                    aws_provider_version: tf.aws_version.clone(),
                    awscc_provider_version: tf.awscc_version.clone(),
                    urls: vec![],
                }),
            ..prov(t.format, t.envs())
        };
        let mut depth = depth::checks(&t, "eusc-de-east-1");
        let offered = depth::public_offered(&data.knowledge);
        depth::resolve(&mut depth, &offered, depth::DepthSource::Knowledge);
        let findings = matcher::assess(&t, &data.knowledge, data.tf.as_ref(), None, &depth);
        let scan = extractor::hazards(&t, &data.partition);
        let (g, gp) =
            deviation::assess(&t, &findings, data.guide.as_ref().unwrap(), &data.knowledge);
        let prov = Provenance {
            user_guide: Some(gp),
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
            r.warnings.iter().any(|w| w.ends_with(cmd)),
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
    fn deterministic_across_runs() {
        let input = include_str!("../tests/fixtures/tf-plan.json");
        assert_eq!(fixed_report(input), fixed_report(input));
    }

    #[test]
    fn timestamp_shape() {
        let t = now_utc();
        assert_eq!(t.len(), 20);
        assert!(t.ends_with('Z') && t.as_bytes()[10] == b'T');
    }
}
