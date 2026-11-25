//! The JSON that `scan`, `plan` and `compare` write (schema version 2).
//!
//! The in-memory results (`Report`, `Plan`, `Comparison`) stay flat, because the
//! terminal summaries read them; this module shapes them for agents and CI. Every
//! output has the same `run` and `sources` blocks, groups repeated decisions, and
//! leaves out keys that are null or empty lists.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::compare::{CompareWarningCode, Comparison};
use crate::deviation::Documented;
use crate::matcher::{Evidence, Finding, Listed, Roadmap, Verdict};
use crate::model::{DecidedBy, DeployEnv, InputKind, OutOfScope};
use crate::plan::{Mechanism, Plan, PlanSummary, PlanWarningCode};
use crate::provider::knowledge::State;
use crate::provider::live::LiveProvenance;
use crate::provider::schema::SchemaSource;
use crate::remediation::{Cause, CauseType, RequiredChange, Tier};
use crate::report::{Outcome, Report, Summary, TerraformProvenance, Warning, WarningCode};
use crate::rules::{DataDecision, Layer, MovePath};

/// Version of the JSON shape, the same for all three commands. Adding a key or an
/// enum value keeps it; removing or renaming one, or changing what one means,
/// increments it.
pub const SCHEMA_VERSION: u32 = 2;

/// Compact JSON by default, indented with `pretty`. Null values and empty lists are
/// left out.
pub fn to_json(v: &impl Serialize, pretty: bool) -> String {
    let mut s = if pretty {
        serde_json::to_string_pretty(v)
    } else {
        serde_json::to_string(v)
    }
    .expect("serializes");
    s.push('\n');
    s
}

/// Live mode read the target account; public mode used public data only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Public,
    Live,
}

/// What ran, on what, against what.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct Run {
    pub tool_version: String,
    pub mode: Mode,
    /// What produced the input; picks the `replace` expression. Scan and plan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_kind: Option<InputKind>,
    /// The Region the workload runs in today. Plan and compare; for plan, null when
    /// neither the input nor `--from` names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_region: Option<String>,
    pub target_region: String,
    /// The account the input moves to, when `--account` is given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_account: Option<String>,
    /// The move goes to another partition. Plan; null when the source is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crosses_partition: Option<bool>,
    /// Where the input was synthesized (CDK) or planned (Terraform). Scan.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub input_environments: Vec<InputEnvironment>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct InputEnvironment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Property values written for this environment by synthesis or planning.
    pub literal_places: usize,
    /// Distinct zones of the environment the input uses.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub zones_used: Vec<String>,
}

/// Where the data came from, and when.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct Sources {
    /// When the public data was fetched; `live.fetched_at` is when the account was read.
    pub fetched_at: String,
    /// The public availability data; null when none covers the target, so live mode
    /// decides alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public: Option<PublicSources>,
    /// The ESC User Guide's table of contents, when the target is in its partition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_guide_url: Option<String>,
    /// botocore release of the bundled partition data. Scan and plan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terraform: Option<TerraformProvenance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live: Option<LiveSources>,
    /// The target's CloudFormation resource schemas the property checks read. Scan and
    /// plan; null when none were read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schemas: Option<SchemaSources>,
    /// The schemas whose properties were compared. Compare; null when properties were
    /// not compared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compared_schemas: Option<ComparedSchemas>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct PublicSources {
    /// Where services and APIs came from: the AWS Knowledge MCP server, or the AWS SDK
    /// endpoint data for China.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services_url: Option<String>,
    /// Where the CloudFormation types and config values came from: the Builder Center
    /// capabilities API, the Knowledge MCP server when the API failed, or a China
    /// Region's schema bundle.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub types_urls: Vec<String>,
    /// Where product and roadmap states came from: the capabilities API, with the
    /// Knowledge MCP server for the not-expanding state. Null for China, which
    /// publishes none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub products_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct LiveSources {
    pub account_id: String,
    /// When the account was read. Scan and plan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub depth_probes: Vec<crate::depth::DepthKind>,
    /// The caller's role has ReadOnlyAccess (or AdministratorAccess) attached, so an
    /// AccessDenied from a service means the service is not offered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only_access: Option<bool>,
}

impl From<&LiveProvenance> for LiveSources {
    fn from(l: &LiveProvenance) -> Self {
        Self {
            account_id: l.account_id.clone(),
            fetched_at: Some(l.fetched_at.clone()),
            depth_probes: l.depth_probes.clone(),
            read_only_access: l.read_only_access,
        }
    }
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct SchemaSources {
    pub source: SchemaSource,
    /// The bundle read, for `bundle`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Resource types whose schema was read.
    pub types: usize,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ComparedSchemas {
    /// Types whose schema both Regions gave.
    pub types: usize,
    pub from: SchemaRef,
    pub to: SchemaRef,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct SchemaRef {
    pub source: SchemaSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

// ---------------------------------------------------------------- scan

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct Scan {
    #[schemars(extend("const" = 2))]
    pub schema_version: u32,
    pub run: Run,
    pub sources: Sources,
    pub summary: Summary,
    pub outcome: Outcome,
    /// Resources that need action or verification; with `--all`, also available
    /// resources whose depth checks or sources say something.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<ScanFinding>,
    /// With `--all`: the available resources, logical ids by resource type.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub available: BTreeMap<String, Vec<String>>,
    /// Features that work with a documented difference, and guide restrictions the
    /// public data contradicts (`conflict`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<Caveat>,
    /// With `--all`: every difference the ESC User Guide documents for the services in
    /// the input.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub documented_differences: Vec<Documented>,
    /// The actions, grouped: one entry per decision, with the resources it applies to.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required_changes: Vec<ChangeGroup>,
    /// Terraform resources of providers other than aws and awscc.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub out_of_scope: Vec<OutOfScope>,
    /// Live mode's checks of the target account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<crate::account::AccountChecks>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning<WarningCode>>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ScanFinding {
    pub logical_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdk_path: Option<String>,
    pub resource_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    pub verdict: Verdict,
    /// What each source said, where live mode ran or a source disagrees with `verdict`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roadmap: Option<Roadmap>,
    /// Why the verdict is what it is; left out where a required change says it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The source that decided whether the resource is offered. Roadmap states always
    /// come from the public availability data.
    pub decided_by: DecidedBy,
    /// Property values checked against what the target offers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub depth: Vec<DepthOut>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct DepthOut {
    pub kind: crate::depth::DepthKind,
    /// Property path: `Properties.` first for CloudFormation, `values.` (the plan
    /// attribute path) for Terraform.
    pub path: String,
    /// The value as written, `engine version` for engine checks.
    pub value: String,
    /// Null until a source answered, or when none could.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<crate::depth::DepthSource>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct Caveat {
    pub logical_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdk_path: Option<String>,
    pub resource_type: String,
    pub rule: String,
    /// The documented difference, as the guide or the AWS page states it.
    pub documented: String,
    pub source: String,
    pub decided_by: DecidedBy,
    /// The feature the public data lists as available although the guide says it is
    /// not: a guide conflict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflict: Option<String>,
}

/// One decision and the resources it applies to.
#[derive(Debug, Clone, PartialEq, Serialize, schemars::JsonSchema)]
pub struct ChangeGroup {
    pub tier: Tier,
    pub cause: Cause,
    /// For hardcoded literals: `breaks` when any literal of the change does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<crate::extractor::Impact>,
    pub decided_by: DecidedBy,
    pub change: String,
    /// What must hold for a proposed change to be right.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub precondition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consequence: Option<String>,
    /// The documented sentence a deviation or dependency rests on, and its page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documented: Option<DocumentedSentence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    /// Values the target offers, for the owner to choose from.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
    /// Known ways around the gap, each from an AWS page.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mitigations: Vec<crate::mitigations::Mitigation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, PartialEq, Serialize, schemars::JsonSchema)]
pub struct DocumentedSentence {
    pub text: String,
    pub url: String,
}

/// A resource a change applies to, and where in it.
#[derive(Debug, Clone, PartialEq, Serialize, schemars::JsonSchema)]
pub struct Target {
    /// The logical id, Terraform address, `Outputs/<name>`, `Globals/<section>`,
    /// `Parameters/<name>`, or `*` for the whole input.
    pub logical_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdk_path: Option<String>,
    /// The resource type, for changes that are not about a hardcoded literal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    /// The product's state in the target, for a resource that is not available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roadmap: Option<Roadmap>,
    /// Why the change exists, where `places` and the group do not say it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub places: Vec<Place>,
}

/// One value to change: `find` in the value at `path`, replaced by `replace`.
#[derive(Debug, Clone, PartialEq, Serialize, schemars::JsonSchema)]
pub struct Place {
    /// Property path: `Properties.` first for CloudFormation, `values.` (the plan
    /// attribute path) for Terraform.
    pub path: String,
    /// The literal; absent for a property that is set at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub find: Option<String>,
    /// The expression for the input's kind (see `run.input_kind`); absent where the
    /// owner decides or chooses among `candidates`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replace: Option<String>,
    /// The whole value `find` sits in, cut at 200 characters, to locate it in source;
    /// for proposals and flags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub within: Option<String>,
}

pub fn scan(r: &Report) -> Scan {
    let p = &r.data_provenance;
    let mut envs: Vec<InputEnvironment> = p.input_environments.iter().map(env).collect();
    for e in &r.environment_literals {
        let i = match envs
            .iter()
            .position(|x| x.region == e.env.region && x.account == e.env.account)
        {
            Some(i) => i,
            None => {
                envs.push(env(&e.env));
                envs.len() - 1
            }
        };
        envs[i].literal_places += e.places;
        envs[i].zones_used.extend(e.zones.iter().cloned());
    }
    let (findings, available) = findings(r);
    Scan {
        schema_version: SCHEMA_VERSION,
        run: Run {
            tool_version: p.tool_version.clone(),
            mode: mode(p.live.is_some()),
            input_kind: Some(p.input_kind),
            source_region: None,
            target_region: p.target_region.clone(),
            target_account: p.target_account.clone(),
            crosses_partition: None,
            input_environments: envs,
        },
        sources: sources(r),
        summary: r.summary.clone(),
        outcome: r.outcome,
        findings,
        available,
        caveats: r
            .deviations
            .iter()
            .filter(|d| !d.blocks())
            .map(|d| Caveat {
                logical_id: d.logical_id.clone(),
                cdk_path: cdk_path(r, &d.logical_id),
                resource_type: d.resource_type.clone(),
                rule: d.rule.clone(),
                documented: d.documented.clone(),
                source: d.source.clone(),
                decided_by: d.decided_by,
                conflict: d.conflict.clone(),
            })
            .collect(),
        documented_differences: r.documented_differences.clone(),
        required_changes: groups(&r.required_changes, p.input_kind),
        out_of_scope: r.out_of_scope.clone(),
        account: r.account.clone(),
        warnings: r.warnings.clone(),
    }
}

fn env(e: &DeployEnv) -> InputEnvironment {
    InputEnvironment {
        region: e.region.clone(),
        account: e.account.clone(),
        literal_places: 0,
        zones_used: Vec::new(),
    }
}

fn mode(live: bool) -> Mode {
    if live { Mode::Live } else { Mode::Public }
}

fn cdk_path(r: &Report, id: &str) -> Option<String> {
    r.findings
        .iter()
        .find(|f| f.logical_id == id)
        .and_then(|f| f.cdk_path.clone())
}

fn sources(r: &Report) -> Sources {
    let p = &r.data_provenance;
    Sources {
        fetched_at: p.fetched_at.clone(),
        public: p.knowledge.as_ref().map(|k| PublicSources {
            services_url: Some(k.url.clone()),
            types_urls: vec![k.cloudformation_url.clone()],
            products_url: k.products_url.clone(),
        }),
        user_guide_url: p.user_guide.as_ref().map(|g| g.toc_url.clone()),
        partition_data: Some(p.partitions_version.clone()),
        terraform: p.terraform.clone(),
        live: p.live.as_ref().map(LiveSources::from),
        schemas: p.schemas.as_ref().map(|s| SchemaSources {
            source: s.source,
            url: s.url.clone(),
            types: s.types,
        }),
        compared_schemas: None,
    }
}

/// A finding that says nothing beyond its type and id: available, no divergence, and
/// every depth value offered.
fn plain(f: &Finding) -> bool {
    f.verdict == Verdict::Available
        && !f.divergence
        && f.depth.iter().all(|d| d.offered == Some(true))
}

fn findings(r: &Report) -> (Vec<ScanFinding>, BTreeMap<String, Vec<String>>) {
    let mut available: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut out = Vec::new();
    for f in &r.findings {
        if plain(f) && f.depth.is_empty() {
            available
                .entry(f.resource_type.clone())
                .or_default()
                .push(f.logical_id.clone());
            continue;
        }
        let agrees = |e: &Evidence| {
            e.live.is_none()
                && matches!(
                    (e.public, f.verdict),
                    (Listed::Available, Verdict::Available)
                        | (Listed::NotAvailable, Verdict::NotAvailable)
                        | (Listed::Unknown, Verdict::CannotAssess)
                )
        };
        out.push(ScanFinding {
            logical_id: f.logical_id.clone(),
            cdk_path: f.cdk_path.clone(),
            resource_type: f.resource_type.clone(),
            service: f.service.clone(),
            verdict: f.verdict,
            evidence: f.evidence.clone().filter(|e| !agrees(e)),
            roadmap: f.roadmap.clone(),
            // A not-available resource has an availability change; the note says
            // nothing else when it is the change's text.
            note: f.note.clone().filter(|n| {
                !r.required_changes.iter().any(|c| {
                    c.cause.kind == CauseType::Availability
                        && c.logical_id == f.logical_id
                        && c.change == *n
                })
            }),
            decided_by: f.decided_by,
            depth: f
                .depth
                .iter()
                .map(|d| DepthOut {
                    kind: d.kind,
                    path: property_path(&f.resource_type, &d.path),
                    value: d.value.clone(),
                    offered: d.offered,
                    source: d.source,
                })
                .collect(),
        });
    }
    (out, available)
}

/// Paths start where hazard paths do: at `Properties.` in a CloudFormation resource,
/// at `values.` (the plan attribute path) in a Terraform resource.
pub(crate) fn property_path(resource_type: &str, path: &str) -> String {
    let root = if resource_type.contains("::") {
        "Properties"
    } else {
        "values"
    };
    if path.starts_with(&format!("{root}.")) {
        path.to_string()
    } else {
        format!("{root}.{path}")
    }
}

/// Changes with the same decision become one group, in the order they first appear.
fn groups(changes: &[RequiredChange], kind: InputKind) -> Vec<ChangeGroup> {
    let mut out: Vec<ChangeGroup> = Vec::new();
    let mut keys: Vec<ChangeGroup> = Vec::new();
    for c in changes {
        let mut g = ChangeGroup {
            tier: c.tier,
            cause: c.cause.clone(),
            impact: c.impact,
            decided_by: c.decided_by,
            change: c.change.clone(),
            precondition: c.precondition.clone(),
            consequence: c.consequence.clone(),
            documented: c.documented.as_ref().map(|(text, url)| DocumentedSentence {
                text: text.clone(),
                url: url.clone(),
            }),
            doc: c.doc.clone(),
            candidates: c.candidates.clone(),
            mitigations: c.mitigations.clone(),
            targets: Vec::new(),
        };
        let mut target = target(c, kind);
        // The header without targets is the grouping key.
        match keys.iter().position(|k| *k == g) {
            // Places of one resource in one decision go under one target.
            Some(i) => match out[i].targets.iter_mut().find(|t| t.same_resource(&target)) {
                Some(t) => t.places.append(&mut target.places),
                None => out[i].targets.push(target),
            },
            None => {
                keys.push(g.clone());
                g.targets.push(target);
                out.push(g);
            }
        }
    }
    out
}

impl Target {
    /// Equal but for the places.
    fn same_resource(&self, o: &Target) -> bool {
        self.logical_id == o.logical_id
            && self.cdk_path == o.cdk_path
            && self.resource_type == o.resource_type
            && self.roadmap == o.roadmap
            && self.reason == o.reason
    }
}

fn target(c: &RequiredChange, kind: InputKind) -> Target {
    // The places and the group say what a literal or documented difference is; the
    // reason says it again in prose.
    // An availability reason names the type and the target, unless it names the
    // service a custom resource calls. A depth reason also names the engine of a
    // version, which the place does not.
    let derivable = match c.cause.kind {
        CauseType::Hazard | CauseType::Deviation | CauseType::Dependency => true,
        CauseType::Availability => c
            .resource_type
            .as_ref()
            .is_some_and(|t| !t.starts_with("Custom::")),
        _ => false,
    };
    let resource = c
        .resource_type
        .as_ref()
        .filter(|_| c.cause.kind != CauseType::Hazard);
    Target {
        logical_id: c.logical_id.clone(),
        cdk_path: c.cdk_path.clone(),
        resource_type: resource.cloned(),
        roadmap: c.roadmap.clone(),
        reason: (!derivable).then(|| c.reason.clone()),
        places: c
            .edits
            .iter()
            .map(|e| Place {
                path: match resource {
                    Some(t) => property_path(t, &e.path),
                    None => e.path.clone(),
                },
                find: (!e.find.is_empty()).then(|| e.find.clone()),
                replace: e.replace.as_ref().map(|r| {
                    match kind {
                        InputKind::CdkAssembly => &r.cdk,
                        InputKind::TerraformPlan => &r.terraform,
                        InputKind::Cloudformation | InputKind::Sam => &r.cloudformation,
                    }
                    .clone()
                }),
                within: e.within.clone().filter(|w| *w != e.find),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------- plan

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct PlanOut {
    #[schemars(extend("const" = 2))]
    pub schema_version: u32,
    pub run: Run,
    /// The sources of the scan the plan ran: `blocked` depends on them.
    pub sources: Sources,
    pub summary: PlanSummary,
    /// The mechanism rules the resources use, by rule id.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub mechanisms: BTreeMap<String, Mechanism>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<PlanResource>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning<PlanWarningCode>>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct PlanResource {
    pub logical_id: String,
    pub resource_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdk_path: Option<String>,
    pub path: MovePath,
    /// The mechanism rule, a key of `mechanisms`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// The resource moves by the rule's `fallback`, not by its `via`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub fallback: bool,
    /// What happens to the resource's data: migrate, recreate, drain or leave.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_action: Option<DataDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<Layer>,
    /// 1-based. A resource is in a later wave than everything it references, and
    /// foundation, shared and workload resources start at waves 1, 2 and 3. Null for a
    /// blocked resource, which does not move.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wave: Option<usize>,
    /// Scan findings that block the resource in the target, as cause ids.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub blocked_by: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub fn plan(p: &Plan, r: &Report) -> PlanOut {
    let prov = &p.data_provenance;
    PlanOut {
        schema_version: SCHEMA_VERSION,
        run: Run {
            tool_version: r.data_provenance.tool_version.clone(),
            mode: mode(r.data_provenance.live.is_some()),
            input_kind: Some(r.data_provenance.input_kind),
            source_region: prov.source_region.clone(),
            target_region: prov.target_region.clone(),
            target_account: r.data_provenance.target_account.clone(),
            crosses_partition: prov.crosses_partition,
            input_environments: Vec::new(),
        },
        sources: sources(r),
        summary: p.summary.clone(),
        mechanisms: p.mechanisms.clone(),
        resources: p
            .resources
            .iter()
            .map(|e| PlanResource {
                logical_id: e.logical_id.clone(),
                resource_type: e.resource_type.clone(),
                cdk_path: e.cdk_path.clone(),
                path: e.path,
                rule: e.rule.clone(),
                fallback: e.fallback,
                data_action: e.data,
                layer: e.layer,
                wave: (e.path != MovePath::Blocked).then_some(e.wave),
                blocked_by: e.blocked_by.clone(),
                note: e.note.clone(),
            })
            .collect(),
        warnings: p.warnings.clone(),
    }
}

// ---------------------------------------------------------------- compare

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct CompareOut {
    #[schemars(extend("const" = 2))]
    pub schema_version: u32,
    pub run: Run,
    pub sources: Sources,
    pub summary: crate::compare::CompareSummary,
    /// Products and features available in the source Region and not in the target,
    /// by their state there.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub products: Vec<ProductGroup>,
    /// CloudFormation resource types available in the source Region and not in the
    /// target, by product.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resource_types: Vec<TypeGroup>,
    /// Config values, such as instance types, the source offers and the target does
    /// not.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub config_values: Vec<ConfigOut>,
    /// Top-level properties of types both offer that the target's schema lacks.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<crate::compare::PropertyGap>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning<CompareWarningCode>>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ProductGroup {
    /// The state in the target; null when the target does not list the products.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,
    /// Quarter of a planned launch in the target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct TypeGroup {
    /// The product the types belong to, as the source Region lists it; null for types
    /// without a known product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// The product's state in the target; null when no product is known or the target
    /// does not list it. `available` means the service is there and CloudFormation
    /// lacks the types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ConfigOut {
    pub resource_type: String,
    pub property: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
}

pub fn compare(c: &Comparison) -> CompareOut {
    let p = &c.data_provenance;
    let mut products: Vec<ProductGroup> = Vec::new();
    for g in &c.products {
        match products
            .iter_mut()
            .find(|x| x.state == g.to_state && x.launch == g.to_launch)
        {
            Some(x) => x.names.push(g.name.clone()),
            None => products.push(ProductGroup {
                state: g.to_state,
                launch: g.to_launch.clone(),
                names: vec![g.name.clone()],
            }),
        }
    }
    // The state is the product's, so one group per product.
    let mut types: BTreeMap<Option<String>, (Option<State>, Vec<String>)> = BTreeMap::new();
    for g in &c.resource_types {
        types
            .entry(g.product.clone())
            .or_insert((g.to_state, Vec::new()))
            .1
            .push(g.resource_type.clone());
    }
    let schema_ref = |s: &crate::provider::schema::SchemaProvenance| SchemaRef {
        source: s.source,
        url: s.url.clone(),
    };
    let mut types_urls: Vec<String> = p.cloudformation_url.iter().cloned().collect();
    types_urls.extend(p.china_bundle_urls.iter().cloned());
    CompareOut {
        schema_version: SCHEMA_VERSION,
        run: Run {
            tool_version: p.tool_version.clone(),
            mode: mode(p.live_account_id.is_some()),
            input_kind: None,
            source_region: Some(c.from.clone()),
            target_region: c.to.clone(),
            target_account: None,
            crosses_partition: None,
            input_environments: Vec::new(),
        },
        sources: Sources {
            fetched_at: p.fetched_at.clone(),
            public: Some(PublicSources {
                services_url: None,
                types_urls,
                products_url: p.products_url.clone(),
            }),
            user_guide_url: None,
            partition_data: None,
            terraform: None,
            live: p.live_account_id.as_ref().map(|a| LiveSources {
                account_id: a.clone(),
                fetched_at: None,
                depth_probes: Vec::new(),
                read_only_access: None,
            }),
            schemas: None,
            compared_schemas: match (&p.from_schemas, &p.to_schemas) {
                (Some(a), Some(b)) => Some(ComparedSchemas {
                    types: p.compared_types,
                    from: schema_ref(a),
                    to: schema_ref(b),
                }),
                _ => None,
            },
        },
        summary: c.summary.clone(),
        products,
        resource_types: types
            .into_iter()
            .map(|(product, (state, types))| TypeGroup {
                product,
                state,
                types,
            })
            .collect(),
        config_values: c
            .config_values
            .iter()
            .map(|g| {
                let (t, prop) = g.key.rsplit_once("::").unwrap_or(("", &g.key));
                ConfigOut {
                    resource_type: t.to_string(),
                    property: prop.to_string(),
                    missing: g.missing.clone(),
                }
            })
            .collect(),
        properties: c.properties.clone(),
        warnings: c.warnings.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compare::{CompareProvenance, CompareSummary, ConfigGap, ProductGap, TypeGap};
    use crate::report::tests::{assert_committed_schema, output_schema, schema_errors};

    fn valid<T: schemars::JsonSchema>(json: &str) {
        let schema = output_schema::<T>();
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        let mut errors = Vec::new();
        schema_errors(&v, &schema, &schema, "", &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
    }

    /// Writes `golden` with `UPDATE_GOLDEN=1`, else compares with it.
    fn golden(file: &str, actual: &str) {
        let path = format!("{}/tests/fixtures/{file}", env!("CARGO_MANIFEST_DIR"));
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::write(&path, actual).unwrap();
        }
        let expected =
            std::fs::read_to_string(&path).expect("golden file exists; run with UPDATE_GOLDEN=1");
        assert_eq!(actual, expected, "{file}");
    }

    fn sample_plan() -> (Plan, Report) {
        let input = crate::test_inputs::SAMPLE_TEMPLATE;
        let t = crate::reader::parse_text(input).unwrap();
        let report = crate::report::tests::fixed(input);
        let facts = crate::provider::partition::facts("eusc-de-east-1").unwrap();
        (
            crate::plan::build(&report, &t, &facts, Some("eu-central-1")),
            report,
        )
    }

    fn comparison() -> Comparison {
        let product = |name: &str, state, launch: Option<&str>| ProductGap {
            name: name.into(),
            to_state: state,
            to_launch: launch.map(String::from),
        };
        let types = |t: &str, product: Option<&str>, state| TypeGap {
            resource_type: t.into(),
            product: product.map(String::from),
            to_state: state,
        };
        Comparison {
            from: "eu-central-1".into(),
            to: "eusc-de-east-1".into(),
            data_provenance: CompareProvenance {
                tool_version: "test".into(),
                cloudformation_url: Some(crate::provider::capabilities::URL.into()),
                products_url: Some(crate::provider::capabilities::URL.into()),
                china_bundle_urls: vec![],
                fetched_at: "1970-01-01T00:00:00Z".into(),
                live_account_id: None,
                from_schemas: None,
                to_schemas: None,
                compared_types: 0,
            },
            summary: CompareSummary {
                products: 3,
                resource_types: 3,
                config_values: 2,
                properties: 0,
            },
            products: vec![
                product("Amazon Kendra", Some(State::NotExpanding), None),
                product("Amazon Q Business", Some(State::Planned), Some("2027 Q1")),
                product("AWS IoT Core", Some(State::NotExpanding), None),
            ],
            resource_types: vec![
                types(
                    "AWS::Kendra::Index",
                    Some("Amazon Kendra"),
                    Some(State::NotExpanding),
                ),
                types(
                    "AWS::Kendra::DataSource",
                    Some("Amazon Kendra"),
                    Some(State::NotExpanding),
                ),
                types("AWS::Old::Thing", None, None),
            ],
            config_values: vec![ConfigGap {
                key: "AWS::EC2::Instance::InstanceType".into(),
                missing: vec!["p5.48xlarge".into(), "u-6tb1.112xlarge".into()],
            }],
            properties: vec![],
            warnings: vec![crate::compare::CompareWarning::new(
                CompareWarningCode::PropertiesUnchecked,
                "eusc-de-east-1 publishes no CloudFormation schema bundle.".into(),
                Vec::new(),
            )],
        }
    }

    #[test]
    fn committed_schema_matches_the_comparison_types() {
        assert_committed_schema::<CompareOut>("compare.schema.json");
    }

    #[test]
    fn json_is_compact_unless_pretty() {
        let c = compare(&comparison());
        let compact = to_json(&c, false);
        assert_eq!(compact.lines().count(), 1);
        assert!(compact.starts_with(r#"{"schema_version":2,"run":{"#));
        assert!(to_json(&c, true).lines().count() > 10);
    }

    #[test]
    fn compare_groups_by_state_and_product() {
        let json = to_json(&compare(&comparison()), true);
        valid::<CompareOut>(&json);
        golden("compare.golden.json", &json);
        let c = compare(&comparison());
        assert_eq!(
            c.products.len(),
            2,
            "not-expanding, and planned for 2027 Q1"
        );
        assert_eq!(c.products[0].names, ["Amazon Kendra", "AWS IoT Core"]);
        // The product-less group sorts first.
        assert_eq!(c.resource_types[0].product, None);
        assert_eq!(c.resource_types[1].types.len(), 2);
        assert_eq!(
            (
                c.config_values[0].resource_type.as_str(),
                c.config_values[0].property.as_str()
            ),
            ("AWS::EC2::Instance", "InstanceType")
        );
        assert!(c.sources.compared_schemas.is_none());
    }

    #[test]
    fn plan_names_each_mechanism_once_and_blocked_resources_have_no_wave() {
        let (p, r) = sample_plan();
        let out = plan(&p, &r);
        let json = to_json(&out, true);
        valid::<PlanOut>(&json);
        golden("sample-plan.golden.json", &json);
        assert!(!out.mechanisms.is_empty());
        for e in &out.resources {
            if let Some(rule) = &e.rule {
                assert!(out.mechanisms.contains_key(rule), "{rule}");
            }
            assert_eq!(
                e.wave.is_none(),
                e.path == MovePath::Blocked,
                "{}",
                e.logical_id
            );
        }
        assert!(out.resources.iter().any(|e| e.path == MovePath::Blocked));
        assert_eq!(out.run.mode, Mode::Public);
        assert_eq!(out.run.input_kind, Some(InputKind::Cloudformation));
    }

    #[test]
    fn a_fallback_is_named_on_the_rule_and_the_resource() {
        let t =
            crate::reader::parse_text(r#"{"Resources":{"Table":{"Type":"AWS::DynamoDB::Table"}}}"#)
                .unwrap();
        let r = crate::report::tests::empty_report("eusc-de-east-1");
        let facts = crate::provider::partition::facts("eusc-de-east-1").unwrap();
        let out = plan(
            &crate::plan::build(&r, &t, &facts, Some("eu-central-1")),
            &r,
        );
        let e = &out.resources[0];
        assert!(e.fallback && e.path == MovePath::Restore, "{e:?}");
        let m = &out.mechanisms[e.rule.as_ref().unwrap()];
        assert!(
            m.fallback
                .as_ref()
                .is_some_and(|f| f.via.contains("export"))
        );
        let json = to_json(&out, false);
        valid::<PlanOut>(&json);
        assert!(json.contains(r#""fallback":true"#));
    }

    #[test]
    fn compared_schemas_say_how_many_types_both_gave() {
        use crate::provider::schema::SchemaProvenance;
        let mut c = comparison();
        let side = |url: &str| SchemaProvenance {
            source: SchemaSource::Bundle,
            url: Some(url.into()),
            types: 0,
        };
        c.data_provenance.from_schemas = Some(side("a"));
        c.data_provenance.to_schemas = Some(side("b"));
        c.data_provenance.compared_types = 7;
        c.data_provenance.live_account_id = Some("111122223333".into());
        let out = compare(&c);
        let s = out.sources.compared_schemas.as_ref().unwrap();
        assert_eq!((s.types, s.from.url.as_deref()), (7, Some("a")));
        assert_eq!(out.run.mode, Mode::Live);
        valid::<CompareOut>(&to_json(&out, false));
    }

    fn change(id: &str, find: &str) -> RequiredChange {
        let mut c = RequiredChange::new(
            id,
            Tier::Fix,
            Cause::new(CauseType::Hazard, ["arn-partition".to_string()]),
            format!("hardcoded `{find}`"),
            "Build the ARN from the partition instead of the literal.".into(),
            crate::remediation::brief("", ""),
        );
        c.edits = vec![crate::remediation::Edit {
            path: "Properties.Arn".into(),
            find: find.into(),
            replace: Some(crate::remediation::Replacement {
                cloudformation: "arn:${AWS::Partition}:".into(),
                cdk: "arn:${Aws.PARTITION}:".into(),
                terraform: "arn:${data.aws_partition.current.partition}:".into(),
            }),
            within: None,
        }];
        c
    }

    #[test]
    fn equal_decisions_share_a_group_and_a_resource_shares_a_target() {
        let mut other = change("B", "arn:aws:");
        other.change = "Something else.".into();
        let g = groups(
            &[
                change("A", "arn:aws:"),
                change("B", "arn:aws:"),
                change("A", "arn:aws:"),
                other,
            ],
            InputKind::CdkAssembly,
        );
        assert_eq!(g.len(), 2);
        let ids: Vec<&str> = g[0].targets.iter().map(|t| t.logical_id.as_str()).collect();
        assert_eq!(ids, ["A", "B"]);
        assert_eq!(g[0].targets[0].places.len(), 2);
        let place = &g[0].targets[0].places[0];
        assert_eq!(place.replace.as_deref(), Some("arn:${Aws.PARTITION}:"));
        assert!(g[0].targets[0].reason.is_none(), "places say it");
        let tf = groups(&[change("A", "arn:aws:")], InputKind::TerraformPlan);
        assert_eq!(
            tf[0].targets[0].places[0].replace.as_deref(),
            Some("arn:${data.aws_partition.current.partition}:")
        );
    }

    #[test]
    fn findings_keep_evidence_only_when_it_says_something() {
        let r = crate::report::tests::fixed(crate::test_inputs::SAMPLE_TEMPLATE);
        let out = scan(&r);
        for f in &out.findings {
            if let Some(e) = &f.evidence {
                assert!(
                    e.live.is_some()
                        || !matches!(
                            (e.public, f.verdict),
                            (Listed::Available, Verdict::Available)
                                | (Listed::NotAvailable, Verdict::NotAvailable)
                                | (Listed::Unknown, Verdict::CannotAssess)
                        ),
                    "{}",
                    f.logical_id
                );
            }
        }
        // Unfiltered, as with `--all`: plain findings become the inventory.
        assert!(!out.available.is_empty());
        let mut gaps = r.clone();
        crate::report::gaps_only(&mut gaps);
        let out = scan(&gaps);
        assert!(out.available.is_empty() && out.documented_differences.is_empty());
        assert!(!r.documented_differences.is_empty());
    }

    #[test]
    fn depth_paths_start_where_hazard_paths_do() {
        assert_eq!(
            property_path("AWS::EC2::Instance", "InstanceType"),
            "Properties.InstanceType"
        );
        assert_eq!(
            property_path("AWS::EC2::Instance", "Properties.X"),
            "Properties.X"
        );
        assert_eq!(
            property_path("aws_instance", "instance_type"),
            "values.instance_type"
        );
        assert_eq!(property_path("aws_instance", "values.ami"), "values.ami");
    }
}
