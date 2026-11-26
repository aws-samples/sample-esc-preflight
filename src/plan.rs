//! `plan`: how each resource of the input moves to the target, in waves.
//!
//! The plan runs the scan, then reads the mechanism rules: a resource is redeployed
//! from the input, replicated by a service, or restored from a copy; blocked when a
//! scan finding blocks it; unknown when no rule covers its type. Across partitions, a
//! mechanism the documentation does not confirm there falls back to the rule's
//! documented fallback, or to unknown. The plan executes nothing.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use crate::model::{Origin, SourceFormat, Template};
use crate::remediation::CauseType;
use crate::report::Report;
use crate::rules::{self, Boundary, Content, DataDecision, Kind, Layer, MovePath};

#[derive(Debug, Clone)]
pub struct Plan {
    pub data_provenance: PlanProvenance,
    pub summary: PlanSummary,
    /// The mechanism rules the resources use, by rule id.
    pub mechanisms: BTreeMap<String, Mechanism>,
    pub resources: Vec<PlanEntry>,
    pub warnings: Vec<PlanWarning>,
}

pub type PlanWarning = crate::report::Warning<PlanWarningCode>;

/// How a mechanism rule moves a resource, and the AWS page it rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct Mechanism {
    /// The named mechanism.
    pub via: String,
    /// Where the resource lives: global, regional or zonal.
    pub scope: Boundary,
    /// What the resource holds: configuration, code, data or supplemental records.
    pub holds: Content,
    /// Whether `via` works across partitions; absent where the documentation does not
    /// say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub works_across_partitions: Option<bool>,
    pub doc: String,
    /// The documented alternative for a move across partitions, where `via` does not
    /// work or is not documented to work there; resources that take it say `fallback`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback: Option<MechanismFallback>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct MechanismFallback {
    pub via: String,
    pub doc: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PlanWarningCode {
    /// No source Region: partition limits are not applied.
    NoSourceRegion,
    /// The source Region is the target, as for an input produced for the target.
    SourceIsTarget,
    /// The input was produced for another Region than `--from`; `--from` is used.
    SourceMismatch,
    /// Scan findings on the whole input, such as a quota, block every resource.
    BlocksWholeInput,
    /// The Terraform plan names no references, so waves follow the layers only.
    LayersOnly,
    /// References form a cycle, so the order within it is not decided by them.
    ReferenceCycle,
}

fn warning(code: PlanWarningCode, message: String) -> PlanWarning {
    PlanWarning::new(code, message, Vec::new())
}

#[derive(Debug, Clone)]
pub struct PlanProvenance {
    /// The input's environment, else `--from`; null when neither names a Region.
    pub source_region: Option<String>,
    pub target_region: String,
    /// The move goes to another partition; null when the source is unknown.
    pub crosses_partition: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct PlanSummary {
    pub resources: usize,
    /// Waves that have resources.
    pub waves: usize,
    pub redeploy: usize,
    pub replicate: usize,
    pub restore: usize,
    pub blocked: usize,
    pub unknown: usize,
    /// Resources whose content is replicated or restored.
    pub data_to_move: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct PlanEntry {
    pub logical_id: String,
    pub resource_type: String,
    pub cdk_path: Option<String>,
    pub path: MovePath,
    /// The named mechanism.
    pub via: Option<String>,
    pub data: Option<DataDecision>,
    pub boundary: Option<Boundary>,
    pub content: Option<Content>,
    pub layer: Option<Layer>,
    /// 1-based. A resource is in a later wave than everything it references, and
    /// foundation, shared and workload resources start at waves 1, 2 and 3.
    pub wave: usize,
    /// Scan findings that block the resource in the target, as cause ids.
    pub blocked_by: Vec<String>,
    /// Whether `via` works across partitions; null where the documentation does not say.
    pub crosses_partition: Option<bool>,
    /// `via` is the rule's documented fallback for a move across partitions.
    pub fallback: bool,
    /// The mechanism rule, and the AWS page it rests on.
    pub rule: Option<String>,
    pub doc: Option<String>,
    pub note: Option<String>,
}

/// The rule for a resource: rules with conditions come first, so a multi-Region key
/// is not taken for a single-Region one.
fn rule_for(
    resource_type: &str,
    props: &Value,
    facts: &crate::extractor::PartitionFacts,
) -> Option<&'static rules::Rule> {
    let mut candidates: Vec<&rules::Rule> = rules::for_target(Kind::Mechanism, facts)
        .filter(|r| r.matches(resource_type, props, facts))
        .collect();
    candidates.sort_by_key(|r| r.when.is_empty());
    candidates.into_iter().next()
}

pub fn build(
    report: &Report,
    template: &Template,
    facts: &crate::extractor::PartitionFacts,
    from: Option<&str>,
) -> Plan {
    let mut warnings = Vec::new();
    let input = template
        .envs()
        .into_iter()
        .filter_map(|e| e.region)
        .find(|r| facts.region_partition.contains_key(r));
    // `--from` wins: the input is often produced for the target already.
    let source_region = from.map(String::from).or_else(|| input.clone());
    if let (Some(i), Some(f)) = (&input, from)
        && i != f
    {
        warnings.push(PlanWarning::new(
            PlanWarningCode::SourceMismatch,
            format!("The input was produced for {i}; the plan uses --from {f} as the source."),
            vec![i.clone()],
        ));
    }
    if source_region.as_deref() == Some(facts.target_region.as_str()) {
        warnings.push(PlanWarning::new(
            PlanWarningCode::SourceIsTarget,
            format!(
                "The input was produced for the target, {}, and --from is not set. Pass --from with the Region the workload runs in today.",
                facts.target_region
            ),
            vec![facts.target_region.clone()],
        ));
    }
    let crosses = source_region
        .as_ref()
        .and_then(|r| facts.region_partition.get(r))
        .map(|p| *p != facts.target_partition);
    if crosses.is_none() {
        warnings.push(warning(
            PlanWarningCode::NoSourceRegion,
            "The plan knows no source Region: the input names none the partition data knows, and --from is not set. Pass --from so the plan can apply partition limits.".into(),
        ));
    }
    let (blocked, whole) = blockers(report);
    if !whole.is_empty() {
        let whole: Vec<String> = whole.into_iter().collect();
        warnings.push(PlanWarning::new(
            PlanWarningCode::BlocksWholeInput,
            format!(
                "These scan findings block the whole input until resolved: {}.",
                whole.join(", ")
            ),
            whole,
        ));
    }
    let mut entries: BTreeMap<String, PlanEntry> = BTreeMap::new();
    let mut mechanisms: BTreeMap<String, Mechanism> = BTreeMap::new();
    for r in template.resources.values() {
        let rule = rule_for(r.deployed_type(), r.deployed_properties(), facts);
        let m = rule.and_then(|r| r.mechanism.as_ref());
        let mut e = PlanEntry {
            logical_id: r.logical_id.clone(),
            resource_type: r.resource_type.clone(),
            cdk_path: r.cdk_path.clone(),
            path: m.map_or(MovePath::Unknown, |m| m.path),
            via: m.map(|m| m.via.clone()),
            data: m.and_then(|m| m.data),
            boundary: m.map(|m| m.boundary),
            content: m.map(|m| m.content),
            layer: m.map(|m| m.layer),
            wave: 0,
            blocked_by: blocked
                .get(r.logical_id.as_str())
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default(),
            crosses_partition: m.and_then(|m| m.crosses_partition),
            fallback: false,
            rule: rule.map(|r| r.id.clone()),
            doc: rule.map(|r| r.source.url().to_string()),
            note: None,
        };
        if let (Some(rule), Some(m)) = (rule, m) {
            let alt = m
                .fallback
                .as_ref()
                .filter(|_| crosses == Some(true) && m.crosses_partition != Some(true));
            mechanisms
                .entry(rule.id.clone())
                .or_insert_with(|| Mechanism {
                    via: m.via.clone(),
                    scope: m.boundary,
                    holds: m.content,
                    works_across_partitions: m.crosses_partition,
                    doc: rule.source.url().to_string(),
                    fallback: alt.map(|f| MechanismFallback {
                        via: f.via.clone(),
                        doc: f.url.clone(),
                    }),
                });
        }
        if let (Some(m), Some(true)) = (m, crosses)
            && m.crosses_partition != Some(true)
        {
            let why = if m.crosses_partition == Some(false) {
                "does not work"
            } else {
                "is not documented to work"
            };
            match &m.fallback {
                Some(f) => {
                    e.path = f.path;
                    e.via = Some(f.via.clone());
                    e.data = f.data;
                    e.doc = Some(f.url.clone());
                    // The fallback's page documents it for moves between partitions.
                    e.crosses_partition = Some(true);
                    e.fallback = true;
                    e.note = Some(format!(
                        "The move crosses partitions, where \"{}\" {why}. The plan uses the documented alternative: {}.",
                        m.via, f.via
                    ));
                }
                None => {
                    e.note = Some(format!(
                        "The move crosses partitions, where \"{}\" {why}. Choose another way to move the content.",
                        m.via
                    ));
                    e.path = MovePath::Unknown;
                    e.via = None;
                    e.data = None;
                }
            }
        }
        if m.is_none() {
            e.note = Some("No mechanism rule covers this resource type.".into());
        }
        if !e.blocked_by.is_empty() {
            e.path = MovePath::Blocked;
        }
        entries.insert(r.logical_id.clone(), e);
    }
    let cycle = waves(template, &mut entries);
    if !cycle.is_empty() {
        let cycle: Vec<String> = cycle.into_iter().collect();
        // The plan JSON has no locals, so a module output read through one counts as
        // the whole module, which can close a cycle the configuration does not have.
        let locals = if template.format == SourceFormat::TerraformPlan {
            " A module output that goes through a local counts as depending on the whole module, so the cycle may not exist in the configuration."
        } else {
            ""
        };
        warnings.push(PlanWarning::new(
            PlanWarningCode::ReferenceCycle,
            format!(
                "References form a cycle at {}, so the waves there do not follow every reference.{locals} Check the order of the resources in the cycle before you deploy.",
                crate::report::list(&cycle, 5)
            ),
            cycle,
        ));
    }
    let resources: Vec<PlanEntry> = {
        let mut v: Vec<PlanEntry> = entries.into_values().collect();
        v.sort_by(|a, b| (a.wave, &a.logical_id).cmp(&(b.wave, &b.logical_id)));
        v
    };
    let count = |p: MovePath| resources.iter().filter(|e| e.path == p).count();
    let summary = PlanSummary {
        resources: resources.len(),
        // A blocked resource does not move, so it has no wave.
        waves: resources
            .iter()
            .filter(|e| e.path != MovePath::Blocked)
            .map(|e| e.wave)
            .collect::<BTreeSet<_>>()
            .len(),
        redeploy: count(MovePath::Redeploy),
        replicate: count(MovePath::Replicate),
        restore: count(MovePath::Restore),
        blocked: count(MovePath::Blocked),
        unknown: count(MovePath::Unknown),
        data_to_move: resources.iter().filter(|e| moves_data(e)).count(),
    };
    if template.format == SourceFormat::TerraformPlan && template.depends_on.is_empty() {
        warnings.push(warning(
            PlanWarningCode::LayersOnly,
            "The plan names no references between Terraform resources, so their waves follow the layers only.".into(),
        ));
    }
    mechanisms.retain(|id, _| resources.iter().any(|e| e.rule.as_ref() == Some(id)));
    Plan {
        data_provenance: PlanProvenance {
            source_region,
            target_region: facts.target_region.clone(),
            crosses_partition: crosses,
        },
        summary,
        mechanisms,
        resources,
        warnings,
    }
}

/// What blocks each resource, from the scan's required changes, and the cause ids
/// that block the whole input.
fn blockers(report: &Report) -> (BTreeMap<&str, BTreeSet<String>>, BTreeSet<String>) {
    let mut blocked: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut whole = BTreeSet::new();
    for c in &report.required_changes {
        let blocks = matches!(
            c.cause.kind,
            CauseType::Availability
                | CauseType::Deviation
                | CauseType::Depth
                | CauseType::Account
                | CauseType::Zones
        );
        if !blocks {
            continue;
        }
        let ids: Vec<String> = if c.cause.ids.is_empty() {
            vec![crate::remediation::id(c.cause.kind)]
        } else {
            c.cause.ids.clone()
        };
        if c.logical_id == "*"
            || c.logical_id.starts_with("Parameters/")
            || c.logical_id.contains("/Parameters/")
        {
            whole.extend(ids);
        } else {
            blocked.entry(&c.logical_id).or_default().extend(ids);
        }
    }
    (blocked, whole)
}

/// Resources of other stacks a resource uses: `Fn::ImportValue` of an export, and
/// `Fn::GetAtt` of a nested stack's `Outputs.<name>`, resolve to what that output
/// refers to.
fn imports(
    v: &Value,
    prefix: &str,
    template: &Template,
    stacks: &BTreeMap<&str, BTreeSet<&str>>,
) -> BTreeSet<String> {
    let mut outputs = Vec::new();
    find_imports(v, prefix, template, &mut outputs);
    let mut out = BTreeSet::new();
    for id in outputs {
        let Some(o) = template.outputs.get(&id) else {
            continue;
        };
        // `<stack>/Outputs/<name>`: the output's stack is everything before `Outputs/`.
        let prefix = id.rfind("Outputs/").map_or("", |i| &id[..i]);
        if let Some(ids) = stacks.get(prefix) {
            let mut bare = BTreeSet::new();
            references(&o.properties, ids, &mut bare);
            out.extend(bare.into_iter().map(|b| format!("{prefix}{b}")));
        }
    }
    out
}

fn find_imports(v: &Value, prefix: &str, template: &Template, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                match (k.as_str(), x) {
                    ("Fn::ImportValue", Value::String(name)) => {
                        out.extend(template.exports.get(name).cloned());
                    }
                    ("Fn::GetAtt", Value::Array(a)) => {
                        if let (Some(stack), Some(name)) = (
                            a.first().and_then(Value::as_str),
                            a.get(1)
                                .and_then(Value::as_str)
                                .and_then(|s| s.strip_prefix("Outputs.")),
                        ) {
                            let id = format!("{prefix}{stack}/Outputs/{name}");
                            if template.outputs.contains_key(&id) {
                                out.push(id);
                            }
                        }
                    }
                    _ => find_imports(x, prefix, template, out),
                }
            }
        }
        Value::Array(a) => a
            .iter()
            .for_each(|x| find_imports(x, prefix, template, out)),
        _ => {}
    }
}

/// Logical ids a CloudFormation resource refers to: `Ref`, `Fn::GetAtt`, `${X}` in
/// `Fn::Sub`, and `DependsOn`.
fn references(v: &Value, ids: &BTreeSet<&str>, out: &mut BTreeSet<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                match (k.as_str(), x) {
                    ("Ref", Value::String(s)) if ids.contains(s.as_str()) => {
                        out.insert(s.clone());
                    }
                    ("Fn::GetAtt", Value::Array(a)) => {
                        if let Some(s) = a.first().and_then(Value::as_str)
                            && ids.contains(s)
                        {
                            out.insert(s.to_string());
                        }
                    }
                    ("Fn::GetAtt", Value::String(s)) => {
                        if let Some(id) = s.split('.').next()
                            && ids.contains(id)
                        {
                            out.insert(id.to_string());
                        }
                    }
                    ("Fn::Sub", _) => {
                        let text = match x {
                            Value::String(s) => s.as_str(),
                            Value::Array(a) => a.first().and_then(Value::as_str).unwrap_or(""),
                            _ => "",
                        };
                        for part in text.split("${").skip(1) {
                            let name = part.split('}').next().unwrap_or("");
                            let id = name.split('.').next().unwrap_or("");
                            if ids.contains(id) {
                                out.insert(id.to_string());
                            }
                        }
                    }
                    _ => {}
                }
                references(x, ids, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| references(x, ids, out)),
        _ => {}
    }
}

/// The stack prefix of a CDK id (`App/Stack/Bucket` -> `App/Stack/`); empty for a
/// plain template.
fn stack_prefix(id: &str) -> &str {
    id.rfind('/').map_or("", |i| &id[..=i])
}

/// Assigns waves; returns the resources where a reference cycle closed.
fn waves(template: &Template, entries: &mut BTreeMap<String, PlanEntry>) -> BTreeSet<String> {
    // References name resources of the same stack by their bare logical id.
    let mut stacks: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for id in template.resources.keys() {
        let p = stack_prefix(id);
        stacks.entry(p).or_default().insert(&id[p.len()..]);
    }
    let deps: BTreeMap<&str, BTreeSet<String>> = template
        .resources
        .values()
        .map(|r| {
            let mut out = BTreeSet::new();
            if r.origin == Origin::Cfn {
                let prefix = stack_prefix(&r.logical_id);
                let mut bare = BTreeSet::new();
                references(&r.properties, &stacks[prefix], &mut bare);
                out.extend(bare.into_iter().map(|b| format!("{prefix}{b}")));
                out.extend(imports(&r.properties, prefix, template, &stacks));
            }
            // CloudFormation `DependsOn`, and Terraform references.
            for d in template.depends_on.get(&r.logical_id).into_iter().flatten() {
                if template.resources.contains_key(d) {
                    out.insert(d.clone());
                }
            }
            out.remove(&r.logical_id);
            (r.logical_id.as_str(), out)
        })
        .collect();
    let start = |e: &PlanEntry| match e.layer {
        Some(Layer::Foundation) => 1,
        Some(Layer::Shared) => 2,
        Some(Layer::Workload) | None => 3,
    };
    /// `None` in the memo marks a resource in progress: reaching it again closes a
    /// cycle, which contributes nothing to the wave and is recorded.
    fn wave(
        id: &str,
        deps: &BTreeMap<&str, BTreeSet<String>>,
        start: &dyn Fn(&str) -> usize,
        memo: &mut BTreeMap<String, Option<usize>>,
        cycle: &mut BTreeSet<String>,
    ) -> usize {
        match memo.get(id) {
            Some(Some(w)) => return *w,
            Some(None) => {
                cycle.insert(id.to_string());
                return 0;
            }
            None => {}
        }
        memo.insert(id.to_string(), None);
        let after = deps
            .get(id)
            .into_iter()
            .flatten()
            .map(|d| wave(d, deps, start, memo, cycle))
            .max()
            .unwrap_or(0);
        let w = start(id).max(after + 1);
        memo.insert(id.to_string(), Some(w));
        w
    }
    let starts: BTreeMap<String, usize> = entries
        .iter()
        .map(|(id, e)| (id.clone(), start(e)))
        .collect();
    let start_of = |id: &str| starts.get(id).copied().unwrap_or(3);
    let mut memo = BTreeMap::new();
    let mut cycle = BTreeSet::new();
    let all: Vec<String> = entries.keys().cloned().collect();
    for id in all {
        let w = wave(&id, &deps, &start_of, &mut memo, &mut cycle);
        if let Some(e) = entries.get_mut(&id) {
            e.wave = w;
        }
    }
    cycle
}

fn moves_data(e: &PlanEntry) -> bool {
    matches!(e.path, MovePath::Replicate | MovePath::Restore)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::partition;
    use crate::reader;

    fn plan(json: &str, target: &str, from: Option<&str>) -> Plan {
        let t = reader::parse_text(json).unwrap();
        let facts = partition::facts(target).unwrap();
        let report = crate::report::tests::empty_report(target);
        build(&report, &t, &facts, from)
    }

    const APP: &str = r#"{"Resources":{
        "Vpc":{"Type":"AWS::EC2::VPC"},
        "Sub":{"Type":"AWS::EC2::Subnet","Properties":{"VpcId":{"Ref":"Vpc"}}},
        "Role":{"Type":"AWS::IAM::Role"},
        "Table":{"Type":"AWS::DynamoDB::Table"},
        "Key":{"Type":"AWS::KMS::Key","Properties":{"MultiRegion":true}},
        "Repo":{"Type":"AWS::ECR::Repository"},
        "Fn":{"Type":"AWS::Lambda::Function","Properties":{
            "Role":{"Fn::GetAtt":["Role","Arn"]},
            "Environment":{"Variables":{"T":{"Fn::Sub":"${Table}"}}}},
            "DependsOn":["Sub"]},
        "Odd":{"Type":"AWS::Some::Thing"}}}"#;

    fn by_id<'a>(p: &'a Plan, id: &str) -> &'a PlanEntry {
        p.resources.iter().find(|e| e.logical_id == id).unwrap()
    }

    #[test]
    fn within_a_partition_mechanisms_apply() {
        let p = plan(APP, "eu-west-1", Some("eu-central-1"));
        assert_eq!(p.data_provenance.crosses_partition, Some(false));
        assert_eq!(
            by_id(&p, "Table").path,
            MovePath::Restore,
            "export and import"
        );
        let key = by_id(&p, "Key");
        assert_eq!(
            (key.path, key.rule.as_deref()),
            (MovePath::Replicate, Some("move-multi-region-key"))
        );
        assert_eq!(by_id(&p, "Odd").path, MovePath::Unknown);
        assert_eq!(p.summary.unknown, 1);
        // Waves: layers first, then references.
        assert_eq!(by_id(&p, "Vpc").wave, 1);
        assert_eq!(by_id(&p, "Sub").wave, 2, "after the VPC it references");
        assert_eq!(by_id(&p, "Fn").wave, 3);
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
    }

    #[test]
    fn across_partitions_documented_fallbacks_or_unknown() {
        let p = plan(APP, "eusc-de-east-1", Some("eu-central-1"));
        assert_eq!(p.data_provenance.crosses_partition, Some(true));
        let t = by_id(&p, "Table");
        assert_eq!(t.path, MovePath::Restore, "export and import");
        assert!(!t.fallback, "the export crosses partitions itself");
        assert_eq!(t.crosses_partition, Some(true));
        let k = by_id(&p, "Key");
        assert_eq!(
            (k.path, k.data),
            (MovePath::Redeploy, Some(DataDecision::Recreate))
        );
        assert!(
            k.note
                .as_deref()
                .is_some_and(|n| n.contains("documented alternative: a new key")),
            "{:?}",
            k.note
        );
        let r = by_id(&p, "Repo");
        assert_eq!(r.path, MovePath::Unknown);
        assert!(
            r.note
                .as_deref()
                .is_some_and(|n| n.contains("does not work"))
        );
        assert_eq!(by_id(&p, "Vpc").path, MovePath::Redeploy);
    }

    #[test]
    fn without_a_source_partition_limits_are_not_applied() {
        let p = plan(APP, "eusc-de-east-1", None);
        assert_eq!(p.data_provenance.crosses_partition, None);
        assert_eq!(by_id(&p, "Repo").path, MovePath::Replicate);
        assert_eq!(p.warnings[0].code, PlanWarningCode::NoSourceRegion);
    }

    #[test]
    fn scan_blockers_block_their_resource() {
        let t = reader::parse_text(APP).unwrap();
        let facts = partition::facts("eu-west-1").unwrap();
        let mut report = crate::report::tests::empty_report("eu-west-1");
        report
            .required_changes
            .push(crate::remediation::RequiredChange::new(
                "Table",
                crate::remediation::Tier::Flag,
                crate::remediation::Cause::new(CauseType::Availability, []),
                "r".into(),
                "c".into(),
                crate::remediation::brief("x", "y"),
            ));
        let p = build(&report, &t, &facts, Some("eu-central-1"));
        let e = by_id(&p, "Table");
        assert_eq!(
            (e.path, e.blocked_by.clone()),
            (MovePath::Blocked, vec!["availability".to_string()])
        );
        let text = crate::summary::plan_summary(
            &p,
            &report,
            crate::tui::Style::default(),
            &crate::tui::Run::default(),
        );
        assert!(
            text.lines()
                .any(|l| l.contains(" Blocked ") && l.contains("1 resource ")),
            "{text}"
        );
        assert!(text.contains("Not ready for eu-west-1"), "{text}");
    }

    #[test]
    fn the_summary_follows_a_move_with_iac() {
        let t = reader::parse_text(APP).unwrap();
        let summary = |target: &str| {
            let facts = partition::facts(target).unwrap();
            let report = crate::report::tests::empty_report(target);
            let p = build(&report, &t, &facts, Some("eu-central-1"));
            crate::summary::plan_summary(
                &p,
                &report,
                crate::tui::Style::default(),
                &crate::tui::Run::default(),
            )
        };
        let text = summary("eu-west-1");
        let line = |needle: &str| text.lines().any(|l| l.contains(needle));
        // With a way, blocked and to decide add up to the 8 resources.
        assert!(
            line("7 deploy with IaC - 3 of them with data to fill - 1 to decide"),
            "{text}"
        );
        assert!(line("before deploying: export the table"), "{text}");
        assert!(
            line("after deploying: a multi-Region replica key"),
            "{text}"
        );
        assert!(
            line("Decide how the 1 resource under To decide moves"),
            "{text}"
        );
        assert!(line("retire the source in eu-central-1"), "{text}");
        assert!(!line("At the switch"), "{text}");
        assert!(
            line("Ready for eu-west-1 after the decisions below"),
            "{text}"
        );
        // Across partitions the key is new content, handled at the switch, not data to fill.
        let text = summary("eusc-de-east-1");
        let line = |needle: &str| text.lines().any(|l| l.contains(needle));
        assert!(line(" At the switch "), "{text}");
        assert!(line("after deploying: a new key in the target"), "{text}");
        assert!(line("with the 1 resource under At the switch"), "{text}");
        // Every resource with a known way: ready.
        let vpc = reader::parse_text(r#"{"Resources":{"Vpc":{"Type":"AWS::EC2::VPC"}}}"#).unwrap();
        let facts = partition::facts("eu-west-1").unwrap();
        let report = crate::report::tests::empty_report("eu-west-1");
        let p = build(&report, &vpc, &facts, Some("eu-central-1"));
        let text = crate::summary::plan_summary(
            &p,
            &report,
            crate::tui::Style::default(),
            &crate::tui::Run::default(),
        );
        assert!(
            text.contains("+ Ready for eu-west-1\n") || text.contains("+ Ready for eu-west-1 "),
            "{text}"
        );
    }

    #[test]
    fn cdk_stacks_reference_by_bare_id_and_cycles_end() {
        let mut t = Template::default();
        let mut add = |id: &str, ty: &str, props: Value| {
            t.resources.insert(
                id.into(),
                crate::model::Resource {
                    logical_id: id.into(),
                    resource_type: ty.into(),
                    properties: props,
                    origin: Origin::Cfn,
                    env: None,
                    cdk_path: None,
                    deployed: None,
                },
            );
        };
        add("App/Net/Vpc", "AWS::EC2::VPC", Value::Null);
        add(
            "App/Net/Sub",
            "AWS::EC2::Subnet",
            serde_json::json!({"VpcId": {"Ref": "Vpc"}}),
        );
        add("App/Other/Vpc", "AWS::EC2::VPC", Value::Null);
        add("A", "AWS::Some::A", Value::Null);
        add("B", "AWS::Some::B", Value::Null);
        add("C", "AWS::Some::C", Value::Null);
        for (x, ys) in [("A", ["B", "C"]), ("B", ["A", "C"]), ("C", ["A", "B"])] {
            t.depends_on
                .insert(x.into(), ys.iter().map(|y| y.to_string()).collect());
        }
        let facts = partition::facts("eu-west-1").unwrap();
        let p = build(
            &crate::report::tests::empty_report("eu-west-1"),
            &t,
            &facts,
            Some("eu-central-1"),
        );
        assert_eq!(
            by_id(&p, "App/Net/Sub").wave,
            2,
            "after its own stack's VPC"
        );
        assert_eq!(by_id(&p, "App/Other/Vpc").wave, 1);
        assert!(by_id(&p, "A").wave >= 3, "a cycle ends");
        let report = crate::report::tests::empty_report("eusc-de-east-1");
        let text = crate::summary::plan_summary(
            &p,
            &report,
            crate::tui::Style::default(),
            &crate::tui::Run::default(),
        );
        assert!(!text.contains(" 0 resources"), "{text}");
    }

    /// `--from` wins over the input's environment, which is often the target.
    #[test]
    fn from_overrides_an_input_produced_for_the_target() {
        let mut t = reader::parse_text(APP).unwrap();
        for r in t.resources.values_mut() {
            r.env = Some(crate::model::DeployEnv {
                region: Some("eusc-de-east-1".into()),
                account: None,
            });
        }
        let facts = partition::facts("eusc-de-east-1").unwrap();
        let report = crate::report::tests::empty_report("eusc-de-east-1");
        let codes = |p: &Plan| p.warnings.iter().map(|w| w.code).collect::<Vec<_>>();
        let alone = build(&report, &t, &facts, None);
        assert_eq!(alone.data_provenance.crosses_partition, Some(false));
        assert_eq!(codes(&alone), [PlanWarningCode::SourceIsTarget]);
        assert_eq!(alone.warnings[0].items, ["eusc-de-east-1"]);
        let p = build(&report, &t, &facts, Some("eu-central-1"));
        assert_eq!(p.data_provenance.crosses_partition, Some(true));
        assert_eq!(codes(&p), [PlanWarningCode::SourceMismatch]);
        assert_eq!(by_id(&p, "Repo").path, MovePath::Unknown);
    }

    #[test]
    fn waves_follow_imports_and_nested_stack_outputs() {
        use serde_json::json;
        let mut t = crate::model::Template::default();
        let res = |id: &str, ty: &str, props: Value| crate::model::Resource {
            logical_id: id.into(),
            resource_type: ty.into(),
            properties: props,
            origin: Origin::Cfn,
            env: None,
            cdk_path: None,
            deployed: None,
        };
        for r in [
            res("Net/Vpc", "AWS::EC2::VPC", json!({})),
            res(
                "App/Fn",
                "AWS::Lambda::Function",
                json!({"Env": {"Fn::ImportValue": "Net:VpcId"}}),
            ),
            res("App/Inner/Queue", "AWS::SQS::Queue", json!({})),
            res(
                "App/Topic",
                "AWS::SNS::Topic",
                json!({"X": {"Fn::GetAtt": ["Inner", "Outputs.QueueArn"]}}),
            ),
        ] {
            t.resources.insert(r.logical_id.clone(), r);
        }
        t.outputs.insert(
            "Net/Outputs/VpcId".into(),
            res(
                "Net/Outputs/VpcId",
                crate::model::OUTPUT_TYPE,
                json!({"Ref": "Vpc"}),
            ),
        );
        t.outputs.insert(
            "App/Inner/Outputs/QueueArn".into(),
            res(
                "App/Inner/Outputs/QueueArn",
                crate::model::OUTPUT_TYPE,
                json!({"Fn::GetAtt": ["Queue", "Arn"]}),
            ),
        );
        t.exports
            .insert("Net:VpcId".into(), "Net/Outputs/VpcId".into());
        let facts = partition::facts("eusc-de-east-1").unwrap();
        let report = crate::report::tests::empty_report("eusc-de-east-1");
        let p = build(&report, &t, &facts, Some("eu-central-1"));
        assert!(by_id(&p, "App/Fn").wave > by_id(&p, "Net/Vpc").wave);
        assert!(by_id(&p, "App/Topic").wave > by_id(&p, "App/Inner/Queue").wave);
    }

    #[test]
    fn a_reference_cycle_warns() {
        let p = plan(
            r#"{"Resources":{
              "A":{"Type":"AWS::SQS::Queue","Properties":{"X":{"Ref":"B"}}},
              "B":{"Type":"AWS::SQS::Queue","Properties":{"X":{"Ref":"A"}}}}}"#,
            "eu-west-1",
            Some("eu-central-1"),
        );
        let w = p
            .warnings
            .iter()
            .find(|w| w.code == PlanWarningCode::ReferenceCycle)
            .unwrap();
        assert!(
            w.message.contains('A') || w.message.contains('B'),
            "{}",
            w.message
        );
        assert!(
            plan(APP, "eu-west-1", Some("eu-central-1"))
                .warnings
                .iter()
                .all(|w| w.code != PlanWarningCode::ReferenceCycle)
        );
    }

    #[test]
    fn terraform_waves_follow_references() {
        let input = r#"{"format_version":"1.2","planned_values":{"root_module":{
            "resources":[
              {"address":"aws_vpc.main","mode":"managed","type":"aws_vpc","name":"main","provider_name":"registry.terraform.io/hashicorp/aws","values":{}},
              {"address":"aws_subnet.a[0]","mode":"managed","type":"aws_subnet","name":"a","provider_name":"registry.terraform.io/hashicorp/aws","values":{}},
              {"address":"aws_sns_topic.t","mode":"managed","type":"aws_sns_topic","name":"t","provider_name":"registry.terraform.io/hashicorp/aws","values":{}},
              {"address":"aws_sns_topic.l","mode":"managed","type":"aws_sns_topic","name":"l","provider_name":"registry.terraform.io/hashicorp/aws","values":{}},
              {"address":"aws_sns_topic.d","mode":"managed","type":"aws_sns_topic","name":"d","provider_name":"registry.terraform.io/hashicorp/aws","values":{}},
              {"address":"aws_sns_topic.i","mode":"managed","type":"aws_sns_topic","name":"i","provider_name":"registry.terraform.io/hashicorp/aws","values":{}}],
            "child_modules":[{"address":"module.app","resources":[
              {"address":"module.app.aws_lambda_function.f","mode":"managed","type":"aws_lambda_function","name":"f","provider_name":"registry.terraform.io/hashicorp/aws","values":{}},
              {"address":"module.app.aws_sqs_queue.q","mode":"managed","type":"aws_sqs_queue","name":"q","provider_name":"registry.terraform.io/hashicorp/aws","values":{}}]}]}},
          "configuration":{"root_module":{
            "resources":[
              {"address":"aws_vpc.main","mode":"managed","type":"aws_vpc","name":"main","expressions":{}},
              {"address":"aws_subnet.a","mode":"managed","type":"aws_subnet","name":"a","expressions":{"vpc_id":{"references":["aws_vpc.main.id","aws_vpc.main"]}}},
              {"address":"aws_sns_topic.t","mode":"managed","type":"aws_sns_topic","name":"t","expressions":{"name":{"references":["module.app.queue_name","module.app"]}}},
              {"address":"aws_sns_topic.l","mode":"managed","type":"aws_sns_topic","name":"l","expressions":{"name":{"references":["module.app.via_local","module.app"]}}},
              {"address":"aws_sns_topic.d","mode":"managed","type":"aws_sns_topic","name":"d","depends_on":["module.app"],"expressions":{"name":{"references":["module.app.queue_name","module.app"]}}},
              {"address":"aws_sns_topic.i","mode":"managed","type":"aws_sns_topic","name":"i","expressions":{"name":{"references":["module.app[0].queue_name","module.app[0]","module.app"]}}}],
            "module_calls":{"app":{"expressions":{"subnet":{"references":["aws_subnet.a"]},"name":{"constant_value":"x"}},"module":{
              "resources":[{"address":"aws_lambda_function.f","mode":"managed","type":"aws_lambda_function","name":"f",
                "expressions":{"vpc_config":[{"subnet_ids":{"references":["var.subnet"]}}],"role":{"references":["data.aws_iam_role.r.arn"]}}},
                {"address":"data.aws_iam_role.r","mode":"data","type":"aws_iam_role","name":"r",
                "expressions":{"name":{"references":["aws_sqs_queue.q.name"]}}},
                {"address":"aws_sqs_queue.q","mode":"managed","type":"aws_sqs_queue","name":"q",
                "expressions":{"name":{"references":["var.name"]}}}],
              "outputs":{"queue_name":{"expression":{"references":["aws_sqs_queue.q.name","aws_sqs_queue.q"]}},
                "via_local":{"expression":{"references":["local.x"]}}}}}}}}}"#;
        let p = plan(input, "eu-west-1", Some("eu-central-1"));
        assert!(
            p.warnings
                .iter()
                .all(|w| w.code != PlanWarningCode::LayersOnly)
        );
        let w = |id: &str| by_id(&p, id).wave;
        assert!(w("aws_subnet.a[0]") > w("aws_vpc.main"));
        assert!(w("module.app.aws_lambda_function.f") > w("aws_subnet.a[0]"));
        // Through the data source; through a module output to what it references.
        assert!(w("module.app.aws_lambda_function.f") > w("module.app.aws_sqs_queue.q"));
        assert!(w("aws_sns_topic.t") > w("module.app.aws_sqs_queue.q"));
        assert!(w("aws_sns_topic.t") <= w("module.app.aws_lambda_function.f"));
        // An indexed module call: the output, not the whole module.
        assert!(w("aws_sns_topic.i") > w("module.app.aws_sqs_queue.q"));
        assert!(w("aws_sns_topic.i") <= w("module.app.aws_lambda_function.f"));
        // Through a local: after the whole module.
        assert!(w("aws_sns_topic.l") > w("module.app.aws_lambda_function.f"));
        // `depends_on` the module beside an output reference: after the whole module.
        assert!(w("aws_sns_topic.d") > w("module.app.aws_lambda_function.f"));
        assert!(
            p.warnings
                .iter()
                .all(|w| w.code != PlanWarningCode::ReferenceCycle)
        );
    }

    #[test]
    fn committed_schema_matches_the_plan_types() {
        crate::report::tests::assert_committed_schema::<crate::output::PlanOut>("plan.schema.json");
    }
}
