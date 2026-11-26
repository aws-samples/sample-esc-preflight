//! The summaries of `plan` and `compare`, in the same frame as the scan's.

use crate::compare::{CompareWarningCode, Comparison};
use crate::plan::{Plan, PlanEntry};
use crate::provider::knowledge::State;
use crate::report::{Report, clean, list, unique};
use crate::rules::{DataDecision, MovePath};
use crate::tui::{Frame, Pen, Run, Style, elapsed, fit, pad};

use super::{input_kind_label, plural_n};

/// Lines per list before the rest is left to the JSON report.
const SHOWN: usize = 8;

fn more(f: &mut Frame, pen: &Pen, rest: usize) {
    if rest > 0 {
        f.line(format!(
            "    {}",
            pen.dim(&format!(
                "{} {rest} more in the JSON report",
                pen.ellipsis()
            ))
        ));
    }
}

fn warnings_section<C>(f: &mut Frame, warnings: &[crate::report::Warning<C>]) {
    if warnings.is_empty() {
        return;
    }
    let pen = f.pen;
    f.section("Notes", "");
    for w in warnings {
        f.para(&format!("  {} ", pen.note()), &clean(&w.message));
    }
    f.blank();
}

fn verdict(f: &mut Frame, glyph: String, text: &str, counts: Vec<String>) {
    let pen = f.pen;
    let head = format!("{glyph} {}", pen.bold(text));
    let joined = counts.join(&pen.dim(pen.dot()));
    if counts.is_empty() {
        f.line(head);
    } else if crate::tui::width(&head) + 3 + crate::tui::width(&joined) <= f.inner() {
        f.line(format!("{head}   {joined}"));
    } else {
        // The counts under the verdict, as many on a line as fit.
        f.line(head);
        let sep = pen.dim(pen.dot());
        let mut cur = String::new();
        for c in counts {
            let next = if cur.is_empty() {
                c.clone()
            } else {
                format!("{cur}{sep}{c}")
            };
            if !cur.is_empty() && 2 + crate::tui::width(&next) > f.inner() {
                f.line(format!("  {cur}"));
                cur = c;
            } else {
                cur = next;
            }
        }
        f.line(format!("  {cur}"));
    }
    f.blank();
}

/// Dim text after `lead`, wrapped under it line by line.
fn dim_fitted(f: &mut Frame, lead: &str, text: &str) {
    let pen = f.pen;
    let indent = crate::tui::width(lead);
    for (i, l) in crate::tui::wrap(text, f.inner().saturating_sub(indent))
        .iter()
        .enumerate()
    {
        let head = if i == 0 {
            lead.to_string()
        } else {
            " ".repeat(indent)
        };
        f.line(format!("{head}{}", pen.dim(l)));
    }
}

/// The plan, for a workload deployed with infrastructure as code: what redeploys with
/// it, which data stores to fill after the deployment and how, what is blocked, and
/// what has no known way yet; then the steps in order.
pub fn plan_summary(p: &Plan, r: &Report, st: Style, run: &Run) -> String {
    let (s, prov, rp) = (&p.summary, &p.data_provenance, &r.data_provenance);
    let mut f = Frame::new(st);
    let pen = f.pen;
    let dot = pen.dot();
    let target = clean(&prov.target_region);
    let source = prov.source_region.as_deref().map(clean);

    let mut how = vec![
        match prov.crosses_partition {
            Some(true) => "another partition",
            Some(false) => "same partition",
            None => "partition limits not applied",
        }
        .to_string(),
        if rp.live.is_some() {
            "live mode".into()
        } else {
            "public mode".into()
        },
    ];
    if let Some(e) = run.elapsed {
        how.push(elapsed(e));
    }
    let mut what = vec![input_kind_label(rp.input_kind).to_string()];
    if rp.stacks > 1 {
        what.push(plural_n(rp.stacks, "stack"));
    }
    what.push(plural_n(s.resources, "resource"));
    f.blank();
    f.boxed(vec![
        format!(
            "{}  {}",
            pen.bold(&clean(&rp.input)),
            pen.dim(&what.join(dot))
        ),
        format!(
            "{} {} {}  {}",
            pen.bold(source.as_deref().unwrap_or("unknown source")),
            pen.arrow(),
            pen.bold(&target),
            pen.dim(&how.join(dot))
        ),
    ]);
    f.blank();

    let fill: Vec<&PlanEntry> = p.resources.iter().filter(|e| to_fill(e)).collect();
    let switch: Vec<&PlanEntry> = p.resources.iter().filter(|e| at_switch(e)).collect();
    let blocked: Vec<&PlanEntry> = p
        .resources
        .iter()
        .filter(|e| e.path == MovePath::Blocked)
        .collect();
    // Unknown: no rule covers the type, or its mechanism does not cross the partitions.
    let (no_way, no_rule): (Vec<&PlanEntry>, Vec<&PlanEntry>) = p
        .resources
        .iter()
        .filter(|e| e.path == MovePath::Unknown)
        .partition(|e| e.rule.is_some());
    let with_way = s.resources - blocked.len() - no_way.len() - no_rule.len();
    let mut counts = vec![format!("{with_way} deploy with IaC")];
    if !fill.is_empty() {
        counts.push(pen.acc(&format!("{} of them with data to fill", fill.len())));
    }
    if !blocked.is_empty() {
        counts.push(pen.red(&format!("{} blocked", blocked.len())));
    }
    let decide = no_way.len() + no_rule.len();
    if decide > 0 {
        counts.push(format!("{decide} to decide"));
    }
    let (glyph, text) = if !blocked.is_empty() {
        (pen.block(), format!("Not ready for {target}"))
    } else if decide > 0 {
        (
            pen.act(),
            format!("Ready for {target} after the decisions below"),
        )
    } else {
        (pen.ok(), format!("Ready for {target}"))
    };
    verdict(&mut f, glyph, &text, counts);

    let id = |e: &PlanEntry| clean(&crate::tui::short_id(&e.logical_id, e.cdk_path.as_deref()));
    let (n_before, n_after) = (
        fill.iter().filter(|e| before_deploy(e)).count(),
        fill.iter().filter(|e| !before_deploy(e)).count(),
    );
    if !fill.is_empty() {
        let mut right = Vec::new();
        if n_before > 0 {
            right.push(format!("{n_before} before deploying"));
        }
        if n_after > 0 {
            right.push(format!("{n_after} after deploying"));
        }
        f.section("Data to fill", right.join(dot));
        data_rows(&mut f, &fill, &id, &|e| {
            if before_deploy(e) {
                "before deploying"
            } else {
                "after deploying"
            }
        });
    }
    if !switch.is_empty() {
        f.section("At the switch", plural_n(switch.len(), "resource"));
        data_rows(&mut f, &switch, &id, &|e| match e.data {
            Some(DataDecision::Drain) => "while switching",
            _ => "after deploying",
        });
    }
    if !blocked.is_empty() {
        f.section(
            "Blocked",
            format!("{}{dot}from the scan", plural_n(blocked.len(), "resource")),
        );
        let w = column(&blocked, &id, f.inner() / 3);
        let type_w = f.inner().saturating_sub(w + 7);
        for e in blocked.iter().take(SHOWN) {
            let by: Vec<String> = e
                .blocked_by
                .iter()
                .map(|b| match b.as_str() {
                    "availability" => "not available".to_string(),
                    b => b.replace('-', " "),
                })
                .collect();
            dim_fitted(
                &mut f,
                &format!(
                    "  {} {}  ",
                    pen.block(),
                    pad(&fit(&id(e), w, pen.ellipsis()), w)
                ),
                &format!(
                    "{}: {}",
                    fit(&clean(&e.resource_type), type_w, pen.ellipsis()),
                    by.join(", ")
                ),
            );
        }
        more(&mut f, &pen, blocked.len().saturating_sub(SHOWN));
        f.blank();
    }
    if decide > 0 {
        f.section("To decide", plural_n(decide, "resource"));
        // By type: how many, and why there is no known way.
        let mut rows: Vec<(String, usize, String)> = Vec::new();
        for (list, why) in [
            (&no_way, "no documented way across partitions"),
            (&no_rule, "no rule covers it yet"),
        ] {
            for e in list.iter() {
                let t = clean(&e.resource_type);
                let why = why.to_string();
                match rows.iter_mut().find(|(x, _, w)| *x == t && *w == why) {
                    Some((_, n, _)) => *n += 1,
                    None => rows.push((t, 1, why)),
                }
            }
        }
        let shown: Vec<_> = rows.iter().take(SHOWN).collect();
        let w = shown
            .iter()
            .map(|(t, n, _)| t.chars().count() + if *n > 1 { 4 } else { 0 })
            .max()
            .unwrap_or(0)
            .min(f.inner() / 2);
        for (t, n, why) in &shown {
            // The count stays when the type is cut.
            let times = if *n > 1 {
                format!(" {}", pen.times(*n))
            } else {
                String::new()
            };
            let cut = fit(t, w - crate::tui::width(&times), pen.ellipsis());
            dim_fitted(
                &mut f,
                &format!("  {} {}  ", pen.verify(), pad(&format!("{cut}{times}"), w)),
                why,
            );
        }
        let rest: usize = rows.iter().skip(SHOWN).map(|(_, n, _)| n).sum();
        more(&mut f, &pen, rest);
        f.blank();
    }

    f.section("Steps", "");
    let scan = &r.summary;
    let mut steps = Vec::new();
    let findings = scan.flags + scan.proposals + scan.fixes;
    if findings > 0 {
        steps.push(format!(
            "Apply the scan's {} to the IaC",
            plural_n(findings, "required change")
        ));
    }
    match (blocked.len(), decide) {
        (0, 0) => {}
        (b, 0) => steps.push(format!(
            "Replace or drop the {} under Blocked",
            plural_n(b, "resource")
        )),
        (0, d) => steps.push(format!(
            "Decide how the {} under To decide {}",
            plural_n(d, "resource"),
            if d == 1 { "moves" } else { "move" }
        )),
        (b, d) => steps.push(format!(
            "Replace or drop the {} under Blocked, and decide how the {d} under To decide {}",
            plural_n(b, "resource"),
            if d == 1 { "moves" } else { "move" }
        )),
    }
    if n_before > 0 {
        steps.push(format!(
            "For the {} marked \"before deploying\", copy the export, snapshot or image to {target}",
            plural_n(n_before, "data store")
        ));
    }
    let stacks = match rp.stacks {
        n if n > 1 => format!("the {n} stacks"),
        _ => "the input".into(),
    };
    steps.push(if n_before > 0 {
        format!("Deploy {stacks} in {target}; those data stores deploy from their copies")
    } else {
        format!("Deploy {stacks} in {target}")
    });
    if n_after > 0 {
        steps.push(format!(
            "Fill the {} marked \"after deploying\"",
            plural_n(n_after, "data store")
        ));
    }
    let with = if switch.is_empty() {
        String::new()
    } else {
        format!(
            ", with the {} under At the switch",
            plural_n(switch.len(), "resource")
        )
    };
    steps.push(match &source {
        Some(src) => format!("Switch traffic to {target}{with}, then retire the source in {src}"),
        None => format!("Switch traffic to {target}{with}, then retire the source"),
    });
    for (k, step) in steps.iter().enumerate() {
        f.para(&format!("  {} ", pen.acc(&format!("{}", k + 1))), step);
    }
    f.blank();

    warnings_section(&mut f, &p.warnings);
    f.fitted("", &crate::tui::json_line(&pen, run, None));
    f.render(&format!("esc-preflight {}", clean(&rp.tool_version)))
}

/// The widest first column of `items`, at most `max`.
fn column(items: &[&PlanEntry], id: &dyn Fn(&PlanEntry) -> String, max: usize) -> usize {
    items
        .iter()
        .take(SHOWN)
        .map(|e| id(e).chars().count())
        .max()
        .unwrap_or(0)
        .min(max)
}

/// Not in the target and not on its roadmap: the user needs an alternative.
fn no_roadmap(s: Option<State>) -> bool {
    matches!(s, Some(State::NotExpanding | State::NotAvailable))
}

/// A data store whose content a redeploy does not bring along.
fn to_fill(e: &PlanEntry) -> bool {
    matches!(e.path, MovePath::Replicate | MovePath::Restore)
}

/// A redeployed resource whose content is handled while traffic switches: a queue to
/// drain, a key to re-create and re-encrypt under.
fn at_switch(e: &PlanEntry) -> bool {
    e.path == MovePath::Redeploy
        && matches!(e.data, Some(DataDecision::Recreate | DataDecision::Drain))
}

/// Resources grouped by type, `when` and mechanism, each group with its ids and how.
fn data_rows(
    f: &mut Frame,
    entries: &[&PlanEntry],
    id: &dyn Fn(&PlanEntry) -> String,
    when: &dyn Fn(&PlanEntry) -> &'static str,
) {
    let pen = f.pen;
    let mut groups: Vec<(&'static str, String, String, Vec<String>)> = Vec::new();
    for e in entries {
        let (w, t, how) = (when(e), clean(&e.resource_type), clean(&fill_text(e)));
        match groups
            .iter_mut()
            .find(|(x, y, h, _)| *x == w && *y == t && *h == how)
        {
            Some((.., ids)) => ids.push(id(e)),
            None => groups.push((w, t, how, vec![id(e)])),
        }
    }
    groups.sort_by_key(|(w, ..)| *w != "before deploying");
    for (w, t, how, ids) in groups.iter().take(SHOWN) {
        let name = if ids.len() > 1 {
            format!("{t} {}", pen.times(ids.len()))
        } else {
            t.clone()
        };
        dim_fitted(f, &format!("  {} {}  ", pen.act(), name), &list(ids, 3));
        f.para(&format!("    {} ", pen.elbow()), &format!("{w}: {how}"));
    }
    let rest: usize = groups.iter().skip(SHOWN).map(|g| g.3.len()).sum();
    more(f, &pen, rest);
    f.blank();
}

/// The data store deploys from a copy, a snapshot, export or image, that must be in
/// the target first.
fn before_deploy(e: &PlanEntry) -> bool {
    e.path == MovePath::Restore
}

/// How to fill a data store, from its mechanism.
fn fill_text(e: &PlanEntry) -> String {
    e.via.clone().unwrap_or_default()
}

/// The comparison: counts, then the first entries of each list.
pub fn compare_summary(c: &Comparison, st: Style, run: &Run) -> String {
    let (s, p) = (&c.summary, &c.data_provenance);
    let mut f = Frame::new(st);
    let pen = f.pen;
    let dot = pen.dot();
    let (from, to) = (clean(&c.from), clean(&c.to));

    let mut how = vec![match &p.live_account_id {
        Some(a) => format!("live mode for {to}, account {}", clean(a)),
        None => "public mode".into(),
    }];
    let mut sources = Vec::new();
    match p.cloudformation_url.as_deref() {
        Some(crate::provider::capabilities::URL) => sources.push("capabilities API, Knowledge MCP"),
        Some(_) => sources.push("Knowledge MCP"),
        None => {}
    }
    if !p.china_bundle_urls.is_empty() {
        sources.push("China schema bundle");
    }
    if p.from_schemas.is_some() && p.to_schemas.is_some() {
        sources.push("resource schemas");
    }
    if !sources.is_empty() {
        how.push(sources.join(", "));
    }
    if let Some(e) = run.elapsed {
        how.push(elapsed(e));
    }
    f.blank();
    let products = !c.warnings.iter().any(|w| {
        matches!(
            w.code,
            CompareWarningCode::PublicDataRegionUnlisted | CompareWarningCode::ProductsUnchecked
        )
    });
    let schemas = p.from_schemas.is_some() && p.to_schemas.is_some();
    // What was compared, so a missing part is visible before the lists.
    let mut scope = Vec::new();
    if products {
        scope.push("products");
    }
    scope.push("resource types");
    if products {
        scope.push("config values");
    }
    scope.push(if schemas {
        "properties"
    } else {
        "properties not compared"
    });
    // The scope stays on the Region line when it fits, else it wraps under the mode.
    let regions = format!("{} {} {}", pen.bold(&from), pen.arrow(), pen.bold(&to));
    let room = f.inner().saturating_sub(4);
    let one = format!("{regions}  {}", pen.dim(&scope.join(dot)));
    let lines = if crate::tui::width(&one) <= room {
        vec![one, pen.dim(&how.join(dot))]
    } else {
        let mut v = vec![regions, pen.dim(&how.join(dot))];
        // Whole items per line, so "properties not compared" stays together.
        let mut cur = String::new();
        for item in &scope {
            let next = if cur.is_empty() {
                item.to_string()
            } else {
                format!("{cur}{dot}{item}")
            };
            if !cur.is_empty() && crate::tui::width(&next) > room {
                v.push(pen.dim(&cur));
                cur = item.to_string();
            } else {
                cur = next;
            }
        }
        v.push(pen.dim(&cur));
        v
    };
    f.boxed(lines);
    f.blank();

    let mut counts = Vec::new();
    if products {
        counts.push(plural_n(s.products, "product"));
    }
    counts.push(plural_n(s.resource_types, "resource type"));
    if products {
        counts.push(plural_n(s.config_values, "config value"));
    }
    if schemas {
        counts.push(plural_n(s.properties, "property").replace("propertys", "properties"));
    }
    // Products with no roadmap in the target: the gaps that need an alternative.
    for (state, label) in [
        (State::NotExpanding, "not expanding"),
        (State::NotAvailable, "not available"),
    ] {
        let n = c
            .products
            .iter()
            .filter(|g| g.to_state == Some(state))
            .count();
        if products && n > 0 {
            counts.push(pen.red(&format!("{n} {label}")));
        }
    }
    let gaps = s.products + s.resource_types + s.config_values + s.properties;
    let (glyph, text) = if gaps == 0 {
        (pen.ok(), format!("{to} offers everything compared"))
    } else {
        (pen.act(), format!("Not in {to}"))
    };
    verdict(&mut f, glyph, &text, counts);

    let state_label = |st: Option<State>, launch: &Option<String>| match (st, launch) {
        (Some(State::Planned), Some(q)) => format!("planned {q}"),
        (Some(s), _) => crate::remediation::id(s).replace('-', " "),
        (None, _) => "not listed".into(),
    };
    if products {
        f.section("Products", plural_n(s.products, "product"));
        let groups = unique(
            c.products
                .iter()
                .map(|g| state_label(g.to_state, &g.to_launch)),
        );
        if groups.is_empty() {
            f.line(format!("  {} none missing", pen.ok()));
        }
        for label in &groups {
            let group: Vec<_> = c
                .products
                .iter()
                .filter(|g| state_label(g.to_state, &g.to_launch) == *label)
                .collect();
            let names: Vec<String> = group.iter().map(|g| clean(&g.name)).collect();
            let blocks = group.first().is_some_and(|g| no_roadmap(g.to_state));
            f.line(format!(
                "  {} {}{}  {}",
                if blocks { pen.block() } else { pen.act() },
                pad(label, 16),
                pen.bold(&format!("{:>4}", names.len())),
                pen.dim(&fit(&list(&names, 3), f.inner() - 28, pen.ellipsis()))
            ));
        }
        f.blank();
    }

    f.section("Resource types", plural_n(s.resource_types, "type"));
    let mut by_product: Vec<(String, Option<State>, usize)> = Vec::new();
    for g in &c.resource_types {
        let name = g
            .product
            .as_deref()
            .map_or_else(|| "no known product".into(), clean);
        match by_product.iter_mut().find(|(n, ..)| *n == name) {
            Some((_, _, k)) => *k += 1,
            None => by_product.push((name, g.to_state, 1)),
        }
    }
    by_product.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
    if by_product.is_empty() {
        f.line(format!("  {} none missing", pen.ok()));
    }
    let w = by_product
        .iter()
        .take(SHOWN)
        .map(|(n, ..)| n.chars().count())
        .max()
        .unwrap_or(0)
        .min(48);
    for (name, state, n) in by_product.iter().take(SHOWN) {
        let glyph = if no_roadmap(*state) {
            pen.block()
        } else {
            pen.act()
        };
        f.line(format!(
            "  {} {}{}  {}",
            glyph,
            pad(&fit(name, w, pen.ellipsis()), w),
            pen.bold(&format!("{n:>5}")),
            pen.dim(&state_label(*state, &None))
        ));
    }
    let rest: usize = by_product.iter().skip(SHOWN).map(|(.., n)| n).sum();
    more(&mut f, &pen, rest);
    f.blank();

    if products {
        f.section("Config values", plural_n(s.config_values, "value"));
        if c.config_values.is_empty() {
            f.line(format!("  {} none missing", pen.ok()));
        }
        for g in c.config_values.iter().take(SHOWN) {
            let (t, prop) = g.key.rsplit_once("::").unwrap_or(("", &g.key));
            f.line(format!(
                "  {} {}{}  {}",
                pen.act(),
                pad(&fit(&clean(&format!("{t} {prop}")), 48, pen.ellipsis()), 48),
                pen.bold(&format!("{:>5}", g.missing.len())),
                pen.dim(&fit(
                    &list(&g.missing.iter().map(|m| clean(m)).collect::<Vec<_>>(), 3),
                    f.inner() - 60,
                    pen.ellipsis()
                ))
            ));
        }
        more(&mut f, &pen, c.config_values.len().saturating_sub(SHOWN));
        f.blank();
    }

    if schemas {
        f.section(
            "Properties",
            plural_n(s.properties, "property").replace("propertys", "properties"),
        );
        if c.properties.is_empty() {
            f.line(format!("  {} none missing", pen.ok()));
        }
        for g in c.properties.iter().take(SHOWN) {
            f.line(format!(
                "  {} {}  {}",
                pen.act(),
                clean(&g.resource_type),
                pen.dim(&list(
                    &g.missing.iter().map(|m| clean(m)).collect::<Vec<_>>(),
                    3
                ))
            ));
        }
        more(&mut f, &pen, c.properties.len().saturating_sub(SHOWN));
        f.blank();
    }
    warnings_section(&mut f, &c.warnings);
    f.fitted("", &crate::tui::json_line(&pen, run, None));
    f.render(&format!("esc-preflight {}", clean(&p.tool_version)))
}
