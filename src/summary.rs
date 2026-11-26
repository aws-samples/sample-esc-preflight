//! The scan's human-readable summary on stderr, drawn with [`crate::tui`]. Every line
//! is built from structured fields of the report, never by parsing its prose, so the
//! same report gives the same text.

use crate::deviation::{Deviation, Severity};
use crate::matcher::{Finding, Verdict};
use crate::model::{DecidedBy, InputKind, SourceFormat};
use crate::remediation::{CauseType, RequiredChange, Tier};
use crate::report::{CDK_HINT, Provenance, Report, Warning, WarningCode, clean, list, unique};
use crate::tui::{Frame, Run, Style, elapsed, fit, pad};

mod moves;
pub use moves::{compare_summary, plan_summary};

/// Required changes shown before the rest is left to the JSON report.
pub(crate) const MAX_CHANGE_LINES: usize = 8;
/// Availability lines shown before the rest is counted.
const MAX_AVAILABILITY_LINES: usize = 8;

pub fn text_summary(r: &Report, st: Style, run: &Run) -> String {
    let s = &r.summary;
    let p = &r.data_provenance;
    let mut f = Frame::new(st);
    let pen = f.pen;
    let dot = pen.dot();
    let target = clean(&p.target_region);

    // What ran: the input, and the target with the sources.
    let mut what = vec![input_kind_label(p.input_kind).to_string()];
    if p.stacks > 1 {
        what.push(format!("{} stacks", p.stacks));
    }
    what.push(plural_n(s.resources, "resource"));
    let mut how = vec![match &p.live {
        Some(l) => format!("live mode, account {}", clean(&l.account_id)),
        None => "public mode".into(),
    }];
    // Live mode decided what it could check; the public sources fill in the rest.
    how.extend(if p.live.is_some() {
        p.knowledge.as_ref().map(|_| {
            if p.user_guide.is_some() {
                "public data, ESC User Guide".to_string()
            } else {
                "public data".to_string()
            }
        })
    } else {
        sources_label(p)
    });
    if let Some(e) = run.elapsed {
        how.push(elapsed(e));
    }
    f.blank();
    f.boxed(vec![
        format!(
            "{}  {}",
            pen.bold(&clean(&p.input)),
            pen.dim(&what.join(dot))
        ),
        format!(
            "{} {}  {}",
            pen.arrow(),
            pen.bold(&target),
            pen.dim(&how.join(dot))
        ),
    ]);
    f.blank();

    // The verdict, then the counts it rests on.
    let blockers = s.not_available + s.depth_blockers + s.deviation_blockers + s.account_blockers;
    let verify =
        s.disputed + s.cannot_assess + s.guide_conflicts + s.caveats + r.out_of_scope.len();
    let mut counts = Vec::new();
    if blockers > 0 {
        counts.push(pen.red(&plural_n(blockers, "blocker")));
    }
    if s.fixes > 0 {
        counts.push(pen.acc(&format!("{} ready", plural_n(s.fixes, "fix"))));
    }
    if s.proposals > 0 {
        counts.push(format!("{} to review", s.proposals));
    }
    // Flags that do not block deployment are the owner's decisions.
    let decide = r
        .required_changes
        .iter()
        .filter(|c| {
            c.tier == Tier::Flag
                && matches!(
                    c.cause.kind,
                    CauseType::Hazard | CauseType::Dependency | CauseType::Environment
                )
        })
        .count();
    if decide > 0 {
        counts.push(format!("{decide} to decide"));
    }
    if verify > 0 {
        counts.push(format!("{verify} to verify"));
    }
    let (glyph, verdict) = if blockers > 0 {
        (pen.block(), format!("Not ready for {target}"))
    } else if s.flags + s.proposals + s.fixes > 0 {
        (
            pen.act(),
            format!("Ready for {target} after the changes below"),
        )
    } else {
        (pen.ok(), format!("Ready for {target}"))
    };
    let count_parts = counts.clone();
    let counts = counts.join(&pen.dim(dot));
    let head = format!("{glyph} {}", pen.bold(&verdict));
    // The counts follow the verdict, or go on the next line when both do not fit.
    if counts.is_empty() {
        f.line(head);
    } else if crate::tui::width(&head) + 3 + crate::tui::width(&counts) <= f.inner() {
        f.line(format!("{head}   {counts}"));
    } else {
        // Below the verdict, wrapped between counts, never inside one.
        f.line(head);
        let mut line = String::new();
        for c in &count_parts {
            let next = if line.is_empty() {
                c.clone()
            } else {
                format!("{line}{}{c}", pen.dim(dot))
            };
            if crate::tui::width(&next) + 2 > f.inner() && !line.is_empty() {
                f.line(format!("  {line}"));
                line = c.clone();
            } else {
                line = next;
            }
        }
        f.line(format!("  {line}"));
    }
    f.blank();

    availability(&mut f, r);
    f.blank();
    required_changes(&mut f, r);
    f.blank();
    if to_verify(&mut f, r) {
        f.blank();
    }
    if notes(&mut f, r) {
        f.blank();
    }
    let hint =
        (s.fixes + s.proposals > 0).then_some("apply the fixes with the esc-preflight agent skill");
    f.fitted("", &crate::tui::json_line(&pen, run, hint));
    f.render(&format!("esc-preflight {}", clean(&p.tool_version)))
}

pub(crate) fn input_kind_label(k: InputKind) -> &'static str {
    match k {
        InputKind::CdkAssembly => "CDK assembly",
        InputKind::Cloudformation => "CloudFormation template",
        InputKind::Sam => "AWS SAM template",
        InputKind::TerraformPlan => "Terraform plan",
    }
}

/// The public sources that answered, in a few words.
pub(crate) fn sources_label(p: &Provenance) -> Option<String> {
    let mut out = Vec::new();
    if let Some(k) = &p.knowledge {
        out.push(if k.url == crate::provider::china::ENDPOINTS_URL {
            "China schema bundle, SDK endpoints"
        } else if k.cloudformation_url == crate::provider::capabilities::URL {
            "capabilities API, Knowledge MCP"
        } else {
            "Knowledge MCP"
        });
    }
    if p.user_guide.is_some() {
        out.push("ESC User Guide");
    }
    (!out.is_empty()).then(|| out.join(", "))
}

pub(crate) fn plural_n(n: usize, word: &str) -> String {
    let w = match (n, word) {
        (1, w) => w.to_string(),
        (_, "fix") => "fixes".into(),
        (_, w) => format!("{w}s"),
    };
    format!("{n} {w}")
}

fn is_custom(f: &Finding) -> bool {
    f.resource_type.starts_with("Custom::") || f.resource_type.ends_with("::CustomResource")
}

/// What is not available, disputed or not assessable, one line per resource type.
fn availability(f: &mut Frame, r: &Report) {
    let (s, pen) = (&r.summary, f.pen);
    f.section(
        "Availability",
        format!("{} of {} available", s.available, s.resources),
    );
    // (glyph, type, state, detail) and how often it occurs.
    type Line = (String, String, String, String);
    let mut lines: Vec<(Line, usize)> = Vec::new();
    let mut add = |key: Line| match lines.iter_mut().find(|(k, _)| *k == key) {
        Some((_, n)) => *n += 1,
        None => lines.push((key, 1)),
    };
    let mut customs = 0;
    let p_live = r.data_provenance.live.is_some();
    for x in &r.findings {
        let t = clean(&x.resource_type);
        match x.verdict {
            Verdict::NotAvailable => {
                // The service is there, but CloudFormation does not offer the type.
                let missing_type = || {
                    let svc = x
                        .resource_type
                        .split("::")
                        .nth(1)
                        .map(clean)
                        .unwrap_or_default();
                    (
                        if p_live {
                            "not in the registry".to_string()
                        } else {
                            "no CloudFormation type".to_string()
                        },
                        if svc.is_empty() {
                            String::new()
                        } else {
                            format!("({svc} is available)")
                        },
                    )
                };
                let (state, detail) = match (&x.roadmap, x.type_gap) {
                    // The state is a feature's while the service is there.
                    (Some(rm), true) => (rm.short(), format!("({})", clean(&rm.product))),
                    (Some(rm), false) => (rm.short(), String::new()),
                    (None, true) => missing_type(),
                    (None, false) => ("not available".into(), String::new()),
                };
                let detail = match (&x.service, is_custom(x)) {
                    (Some(svc), true) => format!("(calls {})", clean(svc)),
                    _ => detail,
                };
                add((pen.block(), t, state, detail));
            }
            Verdict::Disputed => add((
                pen.verify(),
                t,
                x.roadmap
                    .as_ref()
                    .map_or_else(|| "sources disagree".into(), |rm| rm.short()),
                "(type listed, test it before relying on it)".into(),
            )),
            Verdict::CannotAssess if is_custom(x) => customs += 1,
            Verdict::CannotAssess => {
                // Why no source answers, by the kind of type.
                let (state, detail) = match x.resource_type.as_str() {
                    "AWS::Serverless::Application" => (
                        "not assessed".to_string(),
                        "(nested AWS SAM application)".to_string(),
                    ),
                    "AWS::CloudFormation::Stack" => (
                        "not assessed".into(),
                        "(nested stack: scan its template too)".into(),
                    ),
                    t if t.starts_with("AWS::Serverless::") => (
                        "not assessed".into(),
                        "(scan the processed template)".into(),
                    ),
                    t if !t.starts_with("AWS::") && t.contains("::") => (
                        "registry extension".into(),
                        "(check it is activated in the target)".into(),
                    ),
                    _ if p_live => ("unknown to every source".into(), String::new()),
                    _ => (
                        "unknown to the public data".into(),
                        "(live mode checks it)".into(),
                    ),
                };
                add((pen.verify(), t, state, detail))
            }
            Verdict::Available if x.divergence => add((
                pen.verify(),
                t,
                "live mode and public data disagree".into(),
                String::new(),
            )),
            Verdict::Available => {}
        }
    }
    if lines.is_empty() && customs == 0 {
        f.line(format!("  {} every resource is available", pen.ok()));
        return;
    }
    let shown = lines.len().min(MAX_AVAILABILITY_LINES);
    let custom_label = plural_n(customs, "custom resource");
    let tw = lines[..shown]
        .iter()
        .map(|((_, t, ..), n)| t.chars().count() + if *n > 1 { 4 } else { 0 })
        .chain((customs > 0).then(|| custom_label.chars().count()))
        .max()
        .unwrap_or(0)
        .clamp(18, 40);
    let ell = pen.ellipsis();
    for ((glyph, t, state, detail), n) in &lines[..shown] {
        let t = if *n > 1 {
            format!("{t} {}", pen.times(*n))
        } else {
            t.clone()
        };
        let detail = if detail.is_empty() {
            String::new()
        } else {
            format!(" {}", pen.dim(detail))
        };
        f.line(format!(
            "  {glyph} {}  {state}{detail}",
            pad(&fit(&t, tw, ell), tw)
        ));
    }
    if lines.len() > shown {
        let rest: usize = lines[shown..].iter().map(|(_, n)| n).sum();
        f.line(format!(
            "    {}",
            pen.dim(&format!("{ell} {rest} more in the JSON report"))
        ));
    }
    if customs > 0 {
        f.line(format!(
            "  {} {}  your own code, check what it calls",
            pen.verify(),
            pad(&custom_label, tw)
        ));
    }
}

/// The required changes, grouped by what they say in short, worst tier first: what
/// is wrong and what to do, then where.
fn required_changes(f: &mut Frame, r: &Report) {
    let (s, pen) = (&r.summary, f.pen);
    let counts: Vec<String> = [
        (Tier::Flag, s.flags),
        (Tier::Propose, s.proposals),
        (Tier::Fix, s.fixes),
    ]
    .iter()
    .filter(|(_, n)| *n > 0)
    .map(|(t, n)| format!("{n} {}", t.label()))
    .collect();
    f.section("Required changes", counts.join(pen.dot()));
    let groups = change_groups(r);
    if groups.is_empty() {
        f.line(format!("  {} no changes needed", pen.ok()));
        return;
    }
    let shown = pick(&groups, MAX_CHANGE_LINES);
    let ell = pen.ellipsis();
    let tier_w = shown
        .iter()
        .map(|g| g.tier.label().len())
        .max()
        .unwrap_or(0);
    let shown_action = |g: &Group| {
        if g.code {
            pen.code(&g.action)
        } else {
            g.action.clone()
        }
    };
    // What and action share what glyph, tier and arrow leave, measured as printed.
    let room = f.inner() - (tier_w + 6) - (crate::tui::width(pen.arrow()) + 2);
    // Actions up to half the room stay on the row; the widest of them sets the column.
    let action_w = shown
        .iter()
        .map(|g| crate::tui::width(&shown_action(g)))
        .filter(|w| *w <= room / 2)
        .max()
        .unwrap_or(0);
    // Nothing is cut: a row whose what or action does not fit puts the action on
    // its own line below, so a replacement, which is exact code, stays whole.
    let what_w = shown
        .iter()
        .map(|g| g.what.chars().count())
        .max()
        .unwrap_or(0)
        .min(room - action_w);
    for g in &shown {
        // Red marks what blocks deployment, whatever the tier.
        let glyph = if g.blocks { pen.block() } else { pen.act() };
        let action = shown_action(g);
        let tier = pen.bold(&format!("{:<tier_w$}", g.tier.label()));
        // Under the start of "what".
        let indent = " ".repeat(tier_w + 6);
        // A row that would cut what or action puts the action on its own line.
        if crate::tui::width(&action) <= room - what_w && g.what.chars().count() <= what_w {
            f.line(format!(
                "  {glyph} {tier}  {} {} {action}",
                pad(&fit(&g.what, what_w, ell), what_w),
                pen.arrow(),
            ));
        } else {
            f.fitted(&format!("  {glyph} {tier}  "), &g.what);
            f.line(format!("{indent}{} {action}", pen.arrow()));
        }
        f.line(format!("{indent}{} {}", pen.elbow(), pen.dim(&g.place)));
        if let Some(m) = &g.mitigation {
            f.line(format!(
                "{indent}  {}",
                pen.dim(&format!("known mitigation: {m}"))
            ));
        }
    }
    if groups.len() > shown.len() {
        let rest: usize =
            groups.iter().map(|x| x.n).sum::<usize>() - shown.iter().map(|x| x.n).sum::<usize>();
        f.line(format!(
            "    {}",
            pen.dim(&format!("{ell} {rest} more in the JSON report"))
        ));
    }
}

/// At most `max` groups, taken from each tier in turn so that a long list of flags
/// does not hide the fixes, in their original order.
pub(crate) fn pick(groups: &[Group], max: usize) -> Vec<&Group> {
    let mut chosen = vec![false; groups.len()];
    let mut left = max.min(groups.len());
    while left > 0 {
        for tier in [Tier::Flag, Tier::Propose, Tier::Fix] {
            if let Some(i) = (0..groups.len()).find(|&i| !chosen[i] && groups[i].tier == tier)
                && left > 0
            {
                chosen[i] = true;
                left -= 1;
            }
        }
    }
    groups
        .iter()
        .zip(chosen)
        .filter_map(|(g, c)| c.then_some(g))
        .collect()
}

/// Selects the deviations of one kind.
type Keep = dyn Fn(&Deviation) -> bool;

/// Caveats, guide conflicts and resources of other providers; true when shown.
fn to_verify(f: &mut Frame, r: &Report) -> bool {
    let pen = f.pen;
    let mut lines: Vec<(String, String)> = Vec::new();
    let caveat = |d: &Deviation| d.severity == Severity::Caveat;
    let conflict = |d: &Deviation| d.conflict.is_some();
    let kinds: [(&Keep, &str); 2] = [
        (&caveat, "documented difference"),
        (
            &conflict,
            "the guide says not available, the public data says available",
        ),
    ];
    for (keep, what) in kinds {
        for rule in unique(r.deviations.iter().filter(|d| keep(d)).map(|d| &d.rule)) {
            let of_rule = || r.deviations.iter().filter(|d| keep(d) && d.rule == *rule);
            let by = if of_rule().any(|d| d.decided_by == DecidedBy::Guide) {
                "ESC User Guide"
            } else {
                "AWS docs"
            };
            lines.push((
                format!(
                    "{} ({})",
                    rule.replace('-', " "),
                    plural_n(of_rule().count(), "resource")
                ),
                format!("{what}, {by}"),
            ));
        }
    }
    if !r.out_of_scope.is_empty() {
        lines.push((
            plural_n(r.out_of_scope.len(), "resource"),
            "of providers other than aws and awscc, not assessed".into(),
        ));
    }
    if lines.is_empty() {
        return false;
    }
    f.section("To verify", "");
    let w = lines
        .iter()
        .map(|(a, _)| a.chars().count())
        .max()
        .unwrap_or(0)
        .min(44);
    for (a, b) in lines {
        f.line(format!(
            "  {} {}  {}",
            pen.verify(),
            pad(&fit(&clean(&a), w, pen.ellipsis()), w),
            pen.dim(&b)
        ));
    }
    true
}

/// The warnings, short, each with what to do on the line below. Checks that did not
/// run come under "Not checked", the rest under "Notes"; true when any is shown.
fn notes(f: &mut Frame, r: &Report) -> bool {
    let pen = f.pen;
    let p = &r.data_provenance;
    let target = clean(&p.target_region);
    let mut region = match &p.source_region {
        Some(from) => format!(" --from {}", clean(from)),
        None => String::new(),
    };
    if p.target_region != crate::cli::DEFAULT_REGION {
        region.push_str(&format!(" --to {target}"));
    }
    let rescan = match p.input.as_str() {
        "" | "." | "stdin" => format!("esc-preflight scan{region} --profile <name>"),
        i => format!("esc-preflight scan {}{region} --profile <name>", clean(i)),
    };
    let live_hint =
        || (p.live.is_none()).then(|| format!("live mode checks them: {}", pen.acc(&rescan)));
    let items = |w: &Warning<WarningCode>| {
        let v: Vec<String> = w.items.iter().map(|x| clean(x)).collect();
        list(&v, 3)
    };
    let mut unchecked: Vec<(String, Option<String>)> = Vec::new();
    let mut other: Vec<(String, Option<String>)> = Vec::new();
    for (i, w) in r.warnings.iter().enumerate() {
        match w.code {
            WarningCode::PropertiesUnchecked if !p.macros.is_empty() => unchecked.push((
                format!(
                    "Resource properties: the transform {} rewrites resources at deployment.",
                    items(w)
                ),
                Some("check the processed template".into()),
            )),
            WarningCode::PropertiesUnchecked if p.schema_denied => unchecked.push((
                "Resource properties: the role may not call cloudformation:DescribeType.".into(),
                Some("add it from iam/esc-preflight-readonly.json".into()),
            )),
            WarningCode::PropertiesUnchecked => unchecked.push((
                format!("Resource properties: {target} publishes no CloudFormation schema bundle."),
                live_hint(),
            )),
            WarningCode::ValuesUnchecked => unchecked.push((
                format!("Values no source lists for {target}: {}.", items(w)),
                if w.message.contains("check the others") {
                    live_hint().map(|h| format!("{h}; check the others in the target"))
                } else if w.message.contains("Run in live mode") {
                    live_hint()
                } else {
                    Some("check them in the target before you deploy".into())
                },
            )),
            WarningCode::PublicDataUnknown => unchecked.push((
                format!("Unknown to the public data: {}.", items(w)),
                live_hint(),
            )),
            WarningCode::StaleRules => unchecked.push((
                format!(
                    "Rules whose sentence left the ESC User Guide: {}.",
                    items(w)
                ),
                Some("check the guide: the restriction may be lifted".into()),
            )),
            WarningCode::AccountChecksSkipped => unchecked.push((
                format!("Account checks skipped: {}.", items(w)),
                r.account.as_ref().and_then(|a| {
                    a.skipped
                        .first()
                        .map(|s| clean(s.reason.trim_end_matches('.')))
                }),
            )),
            // Shown with the caveats under "To verify".
            WarningCode::GuideConflict => {}
            WarningCode::PublicDataRegionUnlisted => other.push((
                format!("No public availability data covers {target}; live mode decided alone."),
                None,
            )),
            WarningCode::InputRegionMismatch => {
                let cmd = r
                    .warning_commands
                    .iter()
                    .find(|(k, ..)| *k == i)
                    .map(|(.., c)| clean(c));
                other.push((
                    format!("The input was produced for {}, not {target}.", items(w)),
                    Some(match cmd {
                        Some(c) => format!("{CDK_HINT} {}", pen.acc(&c)),
                        None => match p.source_format {
                            SourceFormat::TerraformPlan => "plan it for the target and scan again",
                            SourceFormat::Cloudformation => {
                                "produce it for the target and scan again"
                            }
                        }
                        .into(),
                    }),
                ));
            }
        }
    }
    for (title, list) in [("Not checked", &unchecked), ("Notes", &other)] {
        if list.is_empty() {
            continue;
        }
        if title == "Notes" && !unchecked.is_empty() {
            f.blank();
        }
        f.section(title, "");
        for (text, hint) in list {
            f.para(&format!("  {} ", pen.note()), text);
            if let Some(h) = hint {
                f.para(&format!("    {} ", pen.elbow()), h);
            }
        }
    }
    !(unchecked.is_empty() && other.is_empty())
}

/// The causes that count as blockers, as the verdict and `outcome.blocker` do.
fn blocks(kind: CauseType) -> bool {
    matches!(
        kind,
        CauseType::Availability
            | CauseType::Deviation
            | CauseType::Depth
            | CauseType::Account
            | CauseType::Zones
    )
}

pub(crate) struct Group {
    pub tier: Tier,
    pub what: String,
    pub action: String,
    /// `action` is a replacement to type, not prose.
    pub code: bool,
    pub n: usize,
    /// A change of the group blocks deployment: not available, a documented
    /// deviation, a value the target does not offer, an account check, zones.
    pub blocks: bool,
    /// Where: the resource and its type, or how many places in how many resources.
    pub place: String,
    /// The first known mitigation, as its summary.
    pub mitigation: Option<String>,
}

/// Required changes that read the same in short, worst tier first, then the most
/// frequent.
pub(crate) fn change_groups(r: &Report) -> Vec<Group> {
    let format_of = |c: &RequiredChange| match r.data_provenance.source_format {
        SourceFormat::TerraformPlan => 2,
        SourceFormat::Cloudformation if c.cdk_path.is_some() => 1,
        SourceFormat::Cloudformation => 0,
    };
    let mut groups: Vec<(Group, Vec<&RequiredChange>)> = Vec::new();
    for c in &r.required_changes {
        // A single, uniform replacement is the most precise action there is.
        let reps: Vec<&str> = c
            .edits
            .iter()
            .map(|e| {
                e.replace.as_ref().map(|r| match format_of(c) {
                    1 => r.cdk.as_str(),
                    2 => r.terraform.as_str(),
                    _ => r.cloudformation.as_str(),
                })
            })
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default();
        let (action, code) = match reps.first() {
            Some(first) if reps.iter().all(|x| x == first) => ((*first).to_string(), true),
            _ => (c.brief.action.clone(), false),
        };
        let (what, action) = (clean(&c.brief.what), clean(&action));
        match groups
            .iter_mut()
            .find(|(x, _)| x.tier == c.tier && x.what == what && x.action == action)
        {
            Some((x, cs)) => {
                x.n += 1;
                cs.push(c);
            }
            None => groups.push((
                Group {
                    tier: c.tier,
                    what,
                    action,
                    code,
                    n: 1,
                    blocks: false,
                    place: String::new(),
                    mitigation: c.mitigations.first().map(|m| clean(&m.summary)),
                },
                vec![c],
            )),
        }
    }
    let type_of = |c: &RequiredChange| {
        c.resource_type.clone().or_else(|| {
            r.findings
                .iter()
                .find(|f| f.logical_id == c.logical_id)
                .map(|f| f.resource_type.clone())
        })
    };
    let mut out: Vec<Group> = groups
        .into_iter()
        .map(|(mut x, cs)| {
            let ids = unique(cs.iter().map(|c| c.logical_id.as_str()));
            let places: usize = cs.iter().map(|c| c.edits.len()).sum();
            let types = unique(cs.iter().filter_map(|c| type_of(c)).map(|t| clean(&t)));
            let c = cs[0];
            x.blocks = cs.iter().any(|c| blocks(c.cause.kind));
            x.place = match ids.as_slice() {
                ["*"] => "the whole input".into(),
                [_] => {
                    let id = clean(&crate::tui::short_id(&c.logical_id, c.cdk_path.as_deref()));
                    match types.first() {
                        _ if places > 1 => format!("{places} places in {id}"),
                        Some(t) if c.cause.kind != CauseType::Hazard => format!("{id}  {t}"),
                        _ => id,
                    }
                }
                ids if places > 0 => format!("{places} places in {} resources", ids.len()),
                ids => format!("{} resources: {}", ids.len(), list(&types, 2)),
            };
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
