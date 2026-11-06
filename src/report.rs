//! The JSON report and its human-readable summary.

use serde::Serialize;

use crate::deviation::{Deviation, Documented, GuideFindings, GuideProvenance};
use crate::extractor::{EnvLiterals, Scan};
use crate::matcher::{Finding, Verdict};
use crate::model::{DeployEnv, OutOfScope, SourceFormat};
use crate::provider::live::LiveProvenance;
use crate::remediation::{self, Context, RequiredChange, Tier};

#[derive(Debug, Clone, Serialize)]
pub struct TerraformProvenance {
    pub aws_provider_version: String,
    pub awscc_provider_version: String,
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Provenance {
    pub tool_version: String,
    pub source_format: SourceFormat,
    pub mode: String,
    pub target_region: String,
    /// Where the input was synthesized (CDK cloud assembly) or planned (Terraform).
    pub input_environments: Vec<DeployEnv>,
    pub botocore_version: String,
    pub botocore_urls: Vec<String>,
    pub regional_table_url: String,
    pub regional_table_source_version: String,
    /// Regional-table service names in the target region with no mapping to a service.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub regional_table_unmapped: Vec<String>,
    /// ESC endpoints page, when the target is in its partition.
    pub endpoints_docs_url: Option<String>,
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
    pub available_single_source: usize,
    pub not_available: usize,
    pub disputed: usize,
    pub cannot_assess: usize,
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
    /// Services where public sources disagree. Useful feedback for AWS data owners.
    pub source_disagreements: Vec<String>,
    /// Terraform resources of providers other than aws and awscc.
    pub out_of_scope: Vec<OutOfScope>,
    pub warnings: Vec<String>,
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
        deviations: guide.deviations.len(),
        ..Summary::default()
    };
    let mut changes = Vec::new();
    let mut disagreements = std::collections::BTreeSet::new();
    for f in &findings {
        match &f.verdict {
            Verdict::Available { single_source } => {
                s.available += 1;
                if *single_source {
                    s.available_single_source += 1;
                }
            }
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
        if let (Some(svc), Some(ev)) = (&f.service, &f.evidence)
            && (ev.regional_table_listed.is_some() || ev.user_guide_listed.is_some())
            && (ev.botocore_listed || ev.endpoints_page_listed == Some(true))
                != (ev.regional_table_listed == Some(true) || ev.user_guide_listed == Some(true))
        {
            disagreements.insert(svc.clone());
        }
        if f.verdict == Verdict::NotAvailable {
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
            ));
        }
    }
    changes.extend(
        guide
            .deviations
            .iter()
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
        ));
    }
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
    let mut warnings = Vec::new();
    for region in provenance
        .input_environments
        .iter()
        .filter_map(|e| e.region.as_ref())
        .filter(|r| **r != provenance.target_region)
    {
        warnings.push(format!(
            "The input was produced for {region}, not {}. {produce} it for the target region so region-specific values resolve as they will be deployed.",
            provenance.target_region
        ));
    }
    warnings.dedup();
    let cfn_types = provenance.source_format == SourceFormat::Cloudformation
        || findings
            .iter()
            .any(|f| f.resource_type.starts_with("awscc_"));
    if !provenance.regional_table_unmapped.is_empty() {
        warnings.push(format!(
            "Regional-table services not mapped to a service, so they count as no claim: {}.",
            provenance.regional_table_unmapped.join(", ")
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
    if provenance.live.is_none() && cfn_types {
        let guide = if provenance.user_guide.is_some() {
            ", unless the ESC User Guide documents it"
        } else {
            ""
        };
        warnings.push(format!(
            "Public sources list services, not resource types. A type the service does not support in {} is only found in live mode{guide}.",
            provenance.target_region
        ));
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
        source_disagreements: disagreements.into_iter().collect(),
        out_of_scope,
        warnings,
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
            || !matches!(
                f.verdict,
                Verdict::Available {
                    single_source: false
                }
            )
    });
}

pub fn to_json(report: &Report) -> String {
    let mut s = serde_json::to_string_pretty(report).expect("report serializes");
    s.push('\n');
    s
}

/// The human-readable summary. `color` adds ANSI colors to non-zero counts only.
pub fn text_summary(r: &Report, color: bool) -> String {
    let s = &r.summary;
    let p = &r.data_provenance;
    let paint = |code: &str, text: String| {
        if color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text
        }
    };
    let line = |label: &str, n: usize, code: &str| {
        let text = format!("  {label}: {n}");
        if n > 0 { paint(code, text) } else { text }
    };
    let (red, yellow, green) = ("31", "33", "32");
    let mut out = vec![
        format!(
            "{} resources checked against {} (botocore {}, regional table {}, mode {})",
            s.resources,
            p.target_region,
            p.botocore_version,
            p.regional_table_source_version,
            p.mode
        ),
        line("available", s.available, green)
            + &format!(" ({} single-source)", s.available_single_source),
        line("not available", s.not_available, red),
        line("disputed", s.disputed, yellow),
        line("cannot assess", s.cannot_assess, yellow),
        line("hardcoded values", s.hazards, yellow),
        line("environment literals", s.environment_literals, yellow),
        line("divergences", s.divergences, yellow),
        line("depth blockers", s.depth_blockers, red),
        line("documented deviations", s.deviations, red),
        format!(
            "  required changes: {} fix, {} propose, {} flag",
            s.fixes, s.proposals, s.flags
        ),
    ];
    out.extend(
        r.warnings
            .iter()
            .map(|w| format!("{} {w}", paint(yellow, "warning:".into()))),
    );
    out.join("\n") + "\n"
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
    use crate::provider::{PublicData, botocore, endpoints_page, guide, regional_table, terraform};
    use crate::{deviation, extractor, matcher, reader};

    fn data() -> PublicData {
        PublicData {
            botocore: botocore::tests::fixture(),
            regional_table: regional_table::tests::fixture(),
            endpoints_page: Some(endpoints_page::tests::fixture()),
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
            botocore_version: String::new(),
            botocore_urls: vec![],
            regional_table_url: String::new(),
            regional_table_source_version: String::new(),
            regional_table_unmapped: vec![],
            endpoints_docs_url: None,
            user_guide: None,
            fetched_at: "1970-01-01T00:00:00Z".into(),
            terraform: None,
            live: None,
        }
    }

    fn fixed_report(input: &str) -> String {
        let t = reader::parse(input).unwrap();
        let data = data();
        let prov = Provenance {
            botocore_version: data.botocore.botocore_version.clone(),
            regional_table_url: regional_table::URL.into(),
            regional_table_source_version: data.regional_table.source_version.clone(),
            endpoints_docs_url: Some(endpoints_page::URL.into()),
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
        let findings = matcher::assess(&t, &data, None);
        let scan = extractor::hazards(&t, &data.botocore.partition);
        let (g, gp) = deviation::assess(&t, &findings, data.guide.as_ref().unwrap());
        let prov = Provenance {
            user_guide: Some(gp),
            ..prov
        };
        to_json(&build(
            prov,
            findings,
            scan,
            g,
            t.out_of_scope.clone(),
            &Context {
                single_region: data.botocore.partition.target_regions == 1,
                ..Context::default()
            },
        ))
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
        let t = reader::parse(crate::test_inputs::SAMPLE_TEMPLATE).unwrap();
        let findings = matcher::assess(&t, &data(), None);
        let clean = findings
            .iter()
            .filter(|f| {
                matches!(
                    f.verdict,
                    Verdict::Available {
                        single_source: false
                    }
                )
            })
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
        let t = reader::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/cdk.out"
        ))
        .unwrap();
        let data = data();
        let mut scan = extractor::hazards(&t, &data.botocore.partition);
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
