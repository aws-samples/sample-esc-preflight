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
use crate::report::{Report, clean};
use crate::rules::{self, Boundary, Content, DataDecision, Kind, Layer, MovePath};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct Plan {
    #[schemars(extend("const" = 1))]
    pub schema_version: u32,
    pub data_provenance: PlanProvenance,
    pub summary: PlanSummary,
    pub resources: Vec<PlanEntry>,
    pub warnings: Vec<PlanWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct PlanWarning {
    pub code: PlanWarningCode,
    pub message: String,
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
    /// Terraform waves follow the layers only.
    LayersOnly,
}

fn warning(code: PlanWarningCode, message: String) -> PlanWarning {
    PlanWarning { code, message }
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct PlanProvenance {
    pub tool_version: String,
    pub source_format: SourceFormat,
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
        warnings.push(warning(
            PlanWarningCode::SourceMismatch,
            format!("The input was produced for {i}; the plan uses --from {f} as the source."),
        ));
    }
    if source_region.as_deref() == Some(facts.target_region.as_str()) {
        warnings.push(warning(
            PlanWarningCode::SourceIsTarget,
            format!(
                "The input was produced for the target, {}, and --from is not set. Pass --from with the Region the workload runs in today.",
                facts.target_region
            ),
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
        warnings.push(warning(
            PlanWarningCode::BlocksWholeInput,
            format!(
                "These scan findings block the whole input until resolved: {}.",
                whole.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    let mut entries: BTreeMap<String, PlanEntry> = BTreeMap::new();
    for r in template.resources.values() {
        let rule = rule_for(&r.resource_type, &r.properties, facts);
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
            rule: rule.map(|r| r.id.clone()),
            doc: rule.map(|r| r.source.url().to_string()),
            note: None,
        };
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
                    e.note = Some(format!(
                        "The move crosses partitions, where {} {why}; this is the documented alternative.",
                        m.via
                    ));
                }
                None => {
                    e.note = Some(format!(
                        "The move crosses partitions, and {} {why} there; choose another way to move the content.",
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
    waves(template, &mut entries);
    let resources: Vec<PlanEntry> = {
        let mut v: Vec<PlanEntry> = entries.into_values().collect();
        v.sort_by(|a, b| (a.wave, &a.logical_id).cmp(&(b.wave, &b.logical_id)));
        v
    };
    let count = |p: MovePath| resources.iter().filter(|e| e.path == p).count();
    let summary = PlanSummary {
        resources: resources.len(),
        waves: resources
            .iter()
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
    if template.format == SourceFormat::TerraformPlan {
        warnings.push(warning(
            PlanWarningCode::LayersOnly,
            "esc-preflight does not read references between Terraform resources, so their waves follow the layers only.".into(),
        ));
    }
    Plan {
        schema_version: SCHEMA_VERSION,
        data_provenance: PlanProvenance {
            tool_version: env!("CARGO_PKG_VERSION").into(),
            source_format: template.format,
            source_region,
            target_region: facts.target_region.clone(),
            crosses_partition: crosses,
        },
        summary,
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

fn waves(template: &Template, entries: &mut BTreeMap<String, PlanEntry>) {
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
                for d in template.depends_on.get(&r.logical_id).into_iter().flatten() {
                    if template.resources.contains_key(d) {
                        out.insert(d.clone());
                    }
                }
                out.remove(&r.logical_id);
            }
            (r.logical_id.as_str(), out)
        })
        .collect();
    let start = |e: &PlanEntry| match e.layer {
        Some(Layer::Foundation) => 1,
        Some(Layer::Shared) => 2,
        Some(Layer::Workload) | None => 3,
    };
    /// `None` in the memo marks a resource in progress: a cycle, which CloudFormation
    /// would reject at deployment, contributes nothing.
    fn wave(
        id: &str,
        deps: &BTreeMap<&str, BTreeSet<String>>,
        start: &dyn Fn(&str) -> usize,
        memo: &mut BTreeMap<String, Option<usize>>,
    ) -> usize {
        match memo.get(id) {
            Some(Some(w)) => return *w,
            Some(None) => return 0,
            None => {}
        }
        memo.insert(id.to_string(), None);
        let after = deps
            .get(id)
            .into_iter()
            .flatten()
            .map(|d| wave(d, deps, start, memo))
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
    let all: Vec<String> = entries.keys().cloned().collect();
    for id in all {
        let w = wave(&id, &deps, &start_of, &mut memo);
        if let Some(e) = entries.get_mut(&id) {
            e.wave = w;
        }
    }
}

fn moves_data(e: &PlanEntry) -> bool {
    matches!(e.path, MovePath::Replicate | MovePath::Restore)
}

/// The terminal summary: paths, waves, and the resources that need attention.
pub fn text_summary(p: &Plan) -> String {
    const SHOWN: usize = 8;
    let s = &p.summary;
    let prov = &p.data_provenance;
    let mut out = vec![format!(
        "esc-preflight plan, {} resources, {} -> {}{}",
        s.resources,
        prov.source_region.as_deref().unwrap_or("unknown source"),
        prov.target_region,
        match prov.crosses_partition {
            Some(true) => " (another partition)",
            _ => "",
        }
    )];
    out.push(String::new());
    out.push(format!(
        "  PATHS  redeploy {}  replicate {}  restore {}  blocked {}  unknown {}",
        s.redeploy, s.replicate, s.restore, s.blocked, s.unknown
    ));
    out.push(String::new());
    out.push(format!("  WAVES  {}", s.waves));
    let last = p.resources.iter().map(|e| e.wave).max().unwrap_or(0);
    for w in 1..=last {
        let in_wave: Vec<&PlanEntry> = p.resources.iter().filter(|e| e.wave == w).collect();
        if in_wave.is_empty() {
            continue;
        }
        let moving = in_wave.iter().filter(|e| moves_data(e)).count();
        out.push(format!(
            "    {w}  {} resources{}",
            in_wave.len(),
            if moving > 0 {
                format!(", {moving} with data to move")
            } else {
                String::new()
            }
        ));
    }
    let mut list = |title: &str, items: Vec<String>| {
        if items.is_empty() {
            return;
        }
        out.push(String::new());
        out.push(format!("  {title}  {}", items.len()));
        for i in items.iter().take(SHOWN) {
            out.push(format!("    {i}"));
        }
        if items.len() > SHOWN {
            out.push(format!(
                "    +{} more in the JSON report",
                items.len() - SHOWN
            ));
        }
    };
    list(
        "DATA TO MOVE",
        p.resources
            .iter()
            .filter(|e| moves_data(e))
            .map(|e| {
                format!(
                    "{}  {}: {}",
                    clean(&e.logical_id),
                    clean(&e.resource_type),
                    e.via.as_deref().unwrap_or_default()
                )
            })
            .collect(),
    );
    list(
        "BLOCKED",
        p.resources
            .iter()
            .filter(|e| e.path == MovePath::Blocked)
            .map(|e| format!("{}  by {}", clean(&e.logical_id), e.blocked_by.join(", ")))
            .collect(),
    );
    list(
        "UNKNOWN",
        p.resources
            .iter()
            .filter(|e| e.path == MovePath::Unknown)
            .map(|e| format!("{}  {}", clean(&e.logical_id), clean(&e.resource_type)))
            .collect(),
    );
    for w in &p.warnings {
        out.push(String::new());
        out.push(format!("  ! {}", clean(&w.message)));
    }
    out.push(String::new());
    out.join("\n")
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
        assert_eq!(by_id(&p, "Table").path, MovePath::Replicate);
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
        assert!(
            t.note
                .as_deref()
                .is_some_and(|n| n.contains("not documented"))
        );
        assert_eq!(t.crosses_partition, Some(true), "the fallback works there");
        let k = by_id(&p, "Key");
        assert_eq!(
            (k.path, k.data),
            (MovePath::Redeploy, Some(DataDecision::Recreate))
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
        assert!(text_summary(&p).contains("BLOCKED  1"));
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
        let text = text_summary(&p);
        assert!(!text.contains("0 resources"), "{text}");
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
        let p = build(&report, &t, &facts, Some("eu-central-1"));
        assert_eq!(p.data_provenance.crosses_partition, Some(true));
        assert_eq!(codes(&p), [PlanWarningCode::SourceMismatch]);
        assert_eq!(by_id(&p, "Repo").path, MovePath::Unknown);
    }

    #[test]
    fn committed_schema_matches_the_plan_types() {
        crate::report::tests::assert_committed_schema::<Plan>("plan.schema.json");
    }
}
