//! The summaries of `plan` and `compare`, in the same frame as the scan's.

use crate::compare::{CompareWarningCode, Comparison};
use crate::plan::{Plan, PlanEntry};
use crate::provider::knowledge::State;
use crate::report::{Report, clean, list, unique};
use crate::rules::MovePath;
use crate::tui::{Frame, Pen, Run, Style, elapsed, fit, pad};

use super::{input_kind_label, plural_n};

/// A list line: glyph, resource, detail.
type Item = (String, String, String);

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
    let counts = counts.join(&pen.dim(pen.dot()));
    f.line(format!(
        "{glyph} {}{}",
        pen.bold(text),
        if counts.is_empty() {
            String::new()
        } else {
            format!("   {counts}")
        }
    ));
    f.blank();
}

/// The plan: paths, waves, and the resources that need attention.
pub fn plan_summary(p: &Plan, r: &Report, st: Style, run: &Run) -> String {
    let (s, prov, rp) = (&p.summary, &p.data_provenance, &r.data_provenance);
    let mut f = Frame::new(st);
    let pen = f.pen;
    let dot = pen.dot();
    let target = clean(&prov.target_region);
    let source = prov
        .source_region
        .as_deref()
        .map_or_else(|| "unknown source".to_string(), clean);

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
    f.blank();
    f.boxed(vec![
        format!(
            "{}  {}",
            pen.bold(&clean(&rp.input)),
            pen.dim(&format!(
                "{}{dot}{}",
                input_kind_label(rp.input_kind),
                plural_n(s.resources, "resource")
            ))
        ),
        format!(
            "{} {} {}  {}",
            pen.bold(&source),
            pen.arrow(),
            pen.bold(&target),
            pen.dim(&how.join(dot))
        ),
    ]);
    f.blank();

    let mut counts = Vec::new();
    if s.blocked > 0 {
        counts.push(pen.red(&format!("{} blocked", s.blocked)));
    }
    if s.data_to_move > 0 {
        counts.push(format!("{} with data to move", s.data_to_move));
    }
    if s.unknown > 0 {
        counts.push(format!("{} without a known path", s.unknown));
    }
    let waves = plural_n(s.waves, "wave");
    let (glyph, text) = if s.blocked > 0 {
        (
            pen.block(),
            format!("Not every resource can move to {target}"),
        )
    } else if s.unknown > 0 {
        (
            pen.act(),
            format!("{} in {waves}", plural_n(s.resources, "resource")),
        )
    } else {
        (
            pen.ok(),
            format!("Every resource has a path to {target}, in {waves}"),
        )
    };
    verdict(&mut f, glyph, &text, counts);

    f.section("Paths", plural_n(s.resources, "resource"));
    for (path, n, what) in [
        (
            MovePath::Redeploy,
            s.redeploy,
            "deploy the input again in the target",
        ),
        (
            MovePath::Replicate,
            s.replicate,
            "a service copies the content",
        ),
        (
            MovePath::Restore,
            s.restore,
            "copy a snapshot or export and restore it",
        ),
        (
            MovePath::Blocked,
            s.blocked,
            "a scan finding blocks the resource",
        ),
        (
            MovePath::Unknown,
            s.unknown,
            "no rule covers it, or its mechanism does not cross partitions",
        ),
    ] {
        if n == 0 {
            continue;
        }
        let glyph = match path {
            MovePath::Blocked => pen.block(),
            MovePath::Unknown => pen.verify(),
            _ => pen.act(),
        };
        f.line(format!(
            "  {glyph} {}{}  {}",
            pad(&crate::remediation::id(path), 10),
            pen.bold(&format!("{n:>4}")),
            pen.dim(what)
        ));
    }
    f.blank();

    f.section("Waves", waves.clone());
    let last = p.resources.iter().map(|e| e.wave).max().unwrap_or(0);
    let mut shown = 0;
    for w in 1..=last {
        let in_wave: Vec<&PlanEntry> = p
            .resources
            .iter()
            .filter(|e| e.wave == w && e.path != MovePath::Blocked)
            .collect();
        if in_wave.is_empty() {
            continue;
        }
        shown += 1;
        if shown > SHOWN {
            continue;
        }
        let moving = in_wave.iter().filter(|e| moves_data(e)).count();
        f.line(format!(
            "  {}  {}{}",
            pen.acc(&format!("{w:>2}")),
            plural_n(in_wave.len(), "resource"),
            if moving > 0 {
                pen.dim(&format!("{dot}{moving} with data to move"))
            } else {
                String::new()
            }
        ));
    }
    if shown > SHOWN {
        f.line(format!(
            "    {}",
            pen.dim(&format!(
                "{} {} more waves in the JSON report",
                pen.ellipsis(),
                shown - SHOWN
            ))
        ));
    }
    f.blank();

    let id = |e: &PlanEntry| clean(&crate::tui::short_id(&e.logical_id, e.cdk_path.as_deref()));
    let lists: [(&str, Vec<Item>); 3] = [
        (
            "Data to move",
            p.resources
                .iter()
                .filter(|e| moves_data(e))
                .map(|e| {
                    (
                        pen.act(),
                        id(e),
                        clean(e.via.as_deref().unwrap_or_default()),
                    )
                })
                .collect(),
        ),
        (
            "Blocked",
            p.resources
                .iter()
                .filter(|e| e.path == MovePath::Blocked)
                .map(|e| {
                    (
                        pen.block(),
                        id(e),
                        format!("by {}", e.blocked_by.join(", ")),
                    )
                })
                .collect(),
        ),
        (
            "Unknown",
            p.resources
                .iter()
                .filter(|e| e.path == MovePath::Unknown)
                .map(|e| (pen.verify(), id(e), clean(&e.resource_type)))
                .collect(),
        ),
    ];
    for (title, items) in lists {
        if items.is_empty() {
            continue;
        }
        f.section(title, plural_n(items.len(), "resource"));
        let w = items
            .iter()
            .take(SHOWN)
            .map(|(_, a, _)| a.chars().count())
            .max()
            .unwrap_or(0)
            .min(f.inner() / 2);
        for (g, a, b) in items.iter().take(SHOWN) {
            f.line(format!(
                "  {g} {}  {}",
                pad(&fit(a, w, pen.ellipsis()), w),
                pen.dim(b)
            ));
        }
        more(&mut f, &pen, items.len().saturating_sub(SHOWN));
        f.blank();
    }
    warnings_section(&mut f, &p.warnings);
    f.fitted("", &crate::tui::json_line(&pen, run, None));
    f.render(&format!("esc-preflight {}", clean(&rp.tool_version)))
}

fn moves_data(e: &PlanEntry) -> bool {
    matches!(e.path, MovePath::Replicate | MovePath::Restore)
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
    f.boxed(vec![
        format!(
            "{} {} {}  {}",
            pen.bold(&from),
            pen.arrow(),
            pen.bold(&to),
            pen.dim(&format!("what {from} offers and {to} does not"))
        ),
        pen.dim(&how.join(dot)),
    ]);
    f.blank();

    let products = !c.warnings.iter().any(|w| {
        matches!(
            w.code,
            CompareWarningCode::PublicDataRegionUnlisted | CompareWarningCode::ProductsUnchecked
        )
    });
    let schemas = p.from_schemas.is_some() && p.to_schemas.is_some();
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
            let names: Vec<String> = c
                .products
                .iter()
                .filter(|g| state_label(g.to_state, &g.to_launch) == *label)
                .map(|g| clean(&g.name))
                .collect();
            f.line(format!(
                "  {} {}{}  {}",
                pen.act(),
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
        f.line(format!(
            "  {} {}{}  {}",
            pen.act(),
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
