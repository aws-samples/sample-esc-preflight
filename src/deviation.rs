//! Documented feature differences and dependencies that a resource in the input has.
//!
//! Each rule ties a sentence of the ESC User Guide or of another AWS page to resource
//! types and, optionally, property values. A guide rule is active only while its
//! sentence is on the live guide. A blocker whose feature the Knowledge MCP data lists
//! as available is a guide conflict: the guide is likely outdated, so it warns instead
//! of blocking.

use serde::Serialize;

use crate::extractor::PartitionFacts;
use crate::matcher::{Finding, Verdict};
use crate::model::{DecidedBy, Template};
use crate::provider::guide::{GuideData, Page};
use crate::provider::knowledge::{Knowledge, State};
use crate::rules::{self, Kind, Rule, Source};
pub use crate::rules::{RuleRemediation, Severity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct Deviation {
    pub logical_id: String,
    pub resource_type: String,
    pub rule: String,
    /// The documented difference, as the guide or the AWS page states it.
    pub documented: String,
    pub source: String,
    pub decided_by: DecidedBy,
    pub severity: Severity,
    #[serde(skip)]
    pub(crate) feature: Option<String>,
    /// The feature the public availability data lists as available although the guide says it
    /// is not: a guide conflict, reported as a warning.
    pub conflict: Option<String>,
    #[serde(skip)]
    pub remediation: Option<RuleRemediation>,
}

impl Deviation {
    /// Blocks deployment: a blocker the public availability data does not contradict.
    pub fn blocks(&self) -> bool {
        self.severity == Severity::Blocker && self.conflict.is_none()
    }
}

/// The differences one guide page documents for a service the input uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct Documented {
    pub page: String,
    pub url: String,
    pub differences: Vec<String>,
}

/// Something a resource needs that stays outside the target, or that the move cannot
/// take along, from a dependency rule. The owner decides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct Dependency {
    pub logical_id: String,
    pub resource_type: String,
    pub rule: String,
    /// The documented sentence the dependency rests on.
    pub documented: String,
    pub source: String,
    pub decided_by: DecidedBy,
    #[serde(skip)]
    pub remediation: Option<RuleRemediation>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct GuideFindings {
    pub deviations: Vec<Deviation>,
    pub dependencies: Vec<Dependency>,
    pub documented: Vec<Documented>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct GuideProvenance {
    pub toc_url: String,
    /// Guide pages read, for the terminal summary.
    #[serde(skip)]
    pub pages: usize,
    /// Rules that match the input but whose sentence is no longer on the guide: the
    /// restriction may have been lifted, or the wording changed.
    pub stale_rules: Vec<String>,
}

/// The documented substitute for a resource type, from a rule that fires on the type
/// alone. Used when the type itself is not available in the target.
pub fn substitute_for(resource_type: &str, facts: &PartitionFacts) -> Option<RuleRemediation> {
    rules::for_target(Kind::Deviation, facts)
        .find(|r| r.when.is_empty() && r.types.iter().any(|t| t == resource_type))
        .and_then(|r| r.remediation.clone())
}

/// Deviations and dependencies for every target; the guide provenance when the ESC
/// User Guide was read.
pub fn assess(
    template: &Template,
    findings: &[Finding],
    guide: Option<&GuideData>,
    k: &Knowledge,
    facts: &PartitionFacts,
) -> (GuideFindings, Option<GuideProvenance>) {
    let (mut deviations, stale_rules) = find(template, guide, facts, Kind::Deviation);
    let gone = |id: &str| {
        findings
            .iter()
            .any(|f| f.logical_id == id && f.verdict == Verdict::NotAvailable)
    };
    let dependencies = find(template, guide, facts, Kind::Dependency)
        .0
        .into_iter()
        .filter(|d| !gone(&d.logical_id))
        .map(|d| Dependency {
            logical_id: d.logical_id,
            resource_type: d.resource_type,
            rule: d.rule,
            documented: d.documented,
            source: d.source,
            decided_by: d.decided_by,
            remediation: d.remediation,
        })
        .collect();
    for d in deviations
        .iter_mut()
        .filter(|d| d.severity == Severity::Blocker)
    {
        d.conflict = d.feature.clone().filter(|f| {
            k.products
                .get(f)
                .is_some_and(|p| p.state == State::Available)
        });
    }
    // A resource that is not available at all already carries a required change.
    deviations.retain(|d| !gone(&d.logical_id));
    let mut documented: Vec<Documented> = Vec::new();
    for (f, g) in findings.iter().flat_map(|f| guide.map(|g| (f, g))) {
        for p in g.pages_for(f.service.as_deref(), &f.resource_type) {
            if !p.differences.is_empty() && !documented.iter().any(|d| d.url == p.url) {
                documented.push(Documented {
                    page: p.title.clone(),
                    url: p.url.clone(),
                    differences: p.differences.clone(),
                });
            }
        }
    }
    documented.sort_by(|a, b| a.url.cmp(&b.url));
    (
        GuideFindings {
            deviations,
            dependencies,
            documented,
        },
        guide.map(|g| GuideProvenance {
            toc_url: g.toc_url.clone(),
            pages: g.pages.len(),
            stale_rules,
        }),
    )
}

/// Rule hits of `kind` in the input, and the ids of stale rules that apply to it.
fn find(
    template: &Template,
    guide: Option<&GuideData>,
    facts: &PartitionFacts,
    kind: Kind,
) -> (Vec<Deviation>, Vec<String>) {
    let (mut out, mut stale) = (Vec::new(), Vec::new());
    for rule in rules::for_target(kind, facts) {
        let hits: Vec<_> = template
            .resources
            .values()
            .filter(|r| rule.matches(r.deployed_type(), r.deployed_properties(), facts))
            .collect();
        if hits.is_empty() {
            continue;
        }
        let anchored = match (&rule.source, guide) {
            // Without the guide, its rules cannot be checked, so they are not used.
            (Source::Guide { .. }, None) => continue,
            (Source::Guide { .. }, Some(g)) => anchor(rule, g),
            (Source::Doc { url, quote }, _) => Some((url.clone(), quote.clone())),
        };
        let Some((url, documented)) = anchored else {
            stale.push(rule.id.clone());
            continue;
        };
        out.extend(hits.into_iter().map(|r| Deviation {
            logical_id: r.logical_id.clone(),
            resource_type: r.resource_type.clone(),
            rule: rule.id.clone(),
            documented: documented.clone(),
            source: url.clone(),
            decided_by: match rule.source {
                Source::Guide { .. } => DecidedBy::Guide,
                Source::Doc { .. } => DecidedBy::Rule,
            },
            severity: rule.severity,
            feature: rule.feature.clone(),
            conflict: None,
            remediation: rule.remediation.clone(),
        }));
    }
    out.sort_by(|a, b| (&a.logical_id, &a.rule).cmp(&(&b.logical_id, &b.rule)));
    (out, stale)
}

/// The source URL and the documented sentence a rule rests on. A guide rule needs its
/// difference on the fetched guide; a doc rule's quote is checked by the network test.
fn anchor(rule: &Rule, guide: &GuideData) -> Option<(String, String)> {
    match &rule.source {
        Source::Guide { page, text, also } => {
            let p: &Page = guide.page(page)?;
            p.differences
                .iter()
                .find(|d| d.contains(text.as_str()) && also.iter().all(|a| d.contains(a.as_str())))
                .map(|d| (p.url.clone(), d.clone()))
        }
        Source::Doc { url, quote } => Some((url.clone(), quote.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Origin, Resource};
    use crate::provider::{guide, partition};
    use crate::reader;
    use serde::Deserialize;
    use serde_json::Value;

    fn esc() -> PartitionFacts {
        partition::facts("eusc-de-east-1").unwrap()
    }

    /// The guide rules, with their page, text and extra fragments.
    fn guide_rules() -> Vec<(&'static Rule, &'static str, &'static str, &'static [String])> {
        rules::all()
            .iter()
            .filter_map(|r| match &r.source {
                Source::Guide { page, text, also } => {
                    Some((r, page.as_str(), text.as_str(), also.as_slice()))
                }
                Source::Doc { .. } => None,
            })
            .collect()
    }

    fn scan(template: &str) -> (Vec<Deviation>, Vec<String>) {
        find(
            &reader::parse_text(template).unwrap(),
            Some(&guide::tests::fixture()),
            &esc(),
            Kind::Deviation,
        )
    }

    fn assessed(template: &str) -> Vec<Deviation> {
        let t = reader::parse_text(template).unwrap();
        let k = crate::provider::knowledge::tests::fixture();
        assess(&t, &[], Some(&guide::tests::fixture()), &k, &esc())
            .0
            .deviations
    }

    /// A guide on which every rule is active, to test conditions apart from anchors.
    fn all_active() -> GuideData {
        let mut pages: Vec<guide::Page> = Vec::new();
        for (_, page, text, also) in guide_rules() {
            let item = std::iter::once(text.to_string())
                .chain(also.iter().cloned())
                .collect::<Vec<_>>()
                .join(" ");
            match pages.iter_mut().find(|p| p.slug == page) {
                Some(p) => p.differences.push(item),
                None => pages.push(guide::Page {
                    url: format!("{}{page}.html", guide::BASE),
                    slug: page.to_string(),
                    title: String::new(),
                    services: Vec::new(),
                    type_prefixes: Vec::new(),
                    differences: vec![item],
                    text: String::new(),
                }),
            }
        }
        GuideData {
            toc_url: String::new(),
            pages,
        }
    }

    /// A target the rule applies to.
    fn target_of(r: &Rule) -> PartitionFacts {
        let mut f = if r.scope.partitions.iter().any(|p| p == "aws-eusc") {
            esc()
        } else {
            partition::facts(r.scope.regions.first().map_or("eu-west-1", |s| s.as_str())).unwrap()
        };
        if r.scope.within_partition {
            f.source_partition = Some(f.target_partition.clone());
        }
        assert!(r.scope.applies(&f), "{}", r.id);
        f
    }

    fn fired(resource_type: &str, props: Value, g: &GuideData, f: &PartitionFacts) -> Vec<String> {
        let origin = match resource_type {
            t if t.starts_with("AWS::") => Origin::Cfn,
            t if t.starts_with("awscc_") => Origin::TfAwscc,
            _ => Origin::TfAws,
        };
        let mut t = Template::default();
        t.resources.insert(
            "R".into(),
            Resource {
                logical_id: "R".into(),
                resource_type: resource_type.into(),
                properties: props,
                origin,
                env: None,
                cdk_path: None,
                deployed: None,
            },
        );
        [Kind::Deviation, Kind::Dependency]
            .into_iter()
            .flat_map(|k| find(&t, Some(g), f, k).0)
            .map(|d| d.rule)
            .collect()
    }

    /// Every rule with conditions has a case that fires and a near miss that does not;
    /// every type-only rule fires on each of its types and on nothing else.
    #[test]
    fn rule_cases() {
        #[derive(Deserialize)]
        struct Cases {
            cases: Vec<(String, String, Value, bool)>,
        }
        let cases: Cases =
            serde_json::from_str(include_str!("../tests/fixtures/rule-cases.json")).unwrap();
        let g = all_active();
        let by_id = |id: &str| rules::all().iter().find(|r| r.id == id).unwrap();
        for (rule, ty, props, fires) in &cases.cases {
            let hit = fired(ty, props.clone(), &g, &target_of(by_id(rule))).contains(rule);
            assert_eq!(hit, *fires, "{rule} on {ty} {props}");
        }
        for r in rules::all()
            .iter()
            .filter(|r| matches!(r.kind, Kind::Deviation | Kind::Dependency))
        {
            let mine = || cases.cases.iter().filter(|c| c.0 == r.id);
            let f = target_of(r);
            if r.when.is_empty() {
                for ty in &r.types {
                    assert!(
                        fired(ty, Value::Null, &g, &f).contains(&r.id),
                        "{} on {ty}",
                        r.id
                    );
                }
                assert!(mine().next().is_none(), "{} needs no cases", r.id);
            } else {
                assert!(mine().any(|c| c.3), "{} has no case that fires", r.id);
                assert!(mine().any(|c| !c.3), "{} has no near miss", r.id);
                assert!(
                    fired(&r.types[0], Value::Null, &g, &f)
                        .iter()
                        .all(|x| *x != r.id),
                    "{} fires without properties",
                    r.id
                );
            }
        }
    }

    /// ESC substitutes apply to ESC only, not to every single-Region partition.
    #[test]
    fn substitutes_follow_the_rule_scope() {
        let t = "AWS::DynamoDB::GlobalTable";
        assert!(substitute_for(t, &esc()).is_some());
        let iso_e = partition::facts("eu-isoe-west-1").unwrap();
        assert_eq!(iso_e.target_regions, 1);
        assert!(substitute_for(t, &iso_e).is_none());
    }

    #[test]
    fn rule_features_are_products() {
        let k = crate::provider::knowledge::tests::fixture();
        for r in rules::all() {
            if let Some(f) = &r.feature {
                assert!(k.products.contains_key(f), "{}: {f}", r.id);
            }
        }
    }

    /// Every rule's sentence is on the live guide, and every feature is still a
    /// product. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn no_stale_rules_on_the_live_guide() {
        let client =
            crate::provider::http::Client::new(std::time::Duration::from_secs(30)).unwrap();
        let g = guide::fetch(&client).unwrap();
        let k = crate::provider::availability(
            &client,
            &["eusc-de-east-1"],
            &crate::provider::knowledge::Needs::default(),
        )
        .unwrap()
        .regions
        .remove(0);
        let gone: Vec<_> = rules::all()
            .iter()
            .filter_map(|r| r.feature.as_ref().filter(|f| !k.products.contains_key(*f)))
            .collect();
        assert!(gone.is_empty(), "{gone:?}");
        let (service, feature) = crate::depth::GRAVITON_FEATURE;
        assert!(
            k.features
                .contains_key(&(service.to_string(), feature.to_string())),
            "the Lambda arm64 check reads this feature"
        );
        let stale: Vec<_> = guide_rules()
            .into_iter()
            .filter(|(r, ..)| anchor(r, &g).is_none())
            .map(|(r, ..)| &r.id)
            .collect();
        assert!(stale.is_empty(), "{stale:?}");
    }

    /// Rules quoting other AWS pages fire for every target, also without the guide.
    #[test]
    fn doc_rules_fire_without_the_guide() {
        let t = reader::parse_text(
            r#"{"Resources":{
                "F":{"Type":"AWS::Lambda::Function","Properties":{"Runtime":"python3.7"}},
                "P":{"Type":"AWS::IAM::ManagedPolicy","Properties":{"PolicyDocument":
                    {"Statement":[{"Condition":{"StringEquals":{"aws:RequestedRegion":"eu-west-1"}}}]}}}}}"#,
        )
        .unwrap();
        let k = crate::provider::knowledge::tests::fixture();
        let euw1 = partition::facts("eu-west-1").unwrap();
        let (g, prov) = assess(&t, &[], None, &k, &euw1);
        assert!(prov.is_none(), "no guide, no guide provenance");
        assert_eq!(
            g.deviations
                .iter()
                .map(|d| (d.rule.as_str(), d.decided_by))
                .collect::<Vec<_>>(),
            [("lambda-runtime-create-blocked", DecidedBy::Rule)]
        );
        assert!(g.deviations[0].blocks());
        assert_eq!(g.dependencies.len(), 1);
        assert_eq!(g.dependencies[0].rule, "iam-requested-region-condition");
        let esc_guide = assess(&t, &[], Some(&guide::tests::fixture()), &k, &esc());
        assert_eq!(esc_guide.0.deviations.len(), 1, "and for ESC as well");
        assert!(esc_guide.1.is_some_and(|p| p.stale_rules.is_empty()));
    }

    #[test]
    fn type_rule_fires_with_the_documented_sentence() {
        let (d, _) = scan(r#"{"Resources":{"T":{"Type":"AWS::DynamoDB::GlobalTable"}}}"#);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].rule, "dynamodb-global-tables");
        assert_eq!(d[0].documented, "Global Tables and Cross-Region Restore.");
        assert!(d[0].source.ends_with("/dynamodb.html"));
    }

    #[test]
    fn property_conditions() {
        let http = r#"{"Resources":{"A":{"Type":"AWS::ApiGatewayV2::Api","Properties":{"ProtocolType":"HTTP"}}}}"#;
        let ws = r#"{"Resources":{"A":{"Type":"AWS::ApiGatewayV2::Api","Properties":{"ProtocolType":"WEBSOCKET"}}}}"#;
        let plain = r#"{"Resources":{"S":{"Type":"AWS::SecretsManager::Secret","Properties":{"ReplicaRegions":[]}}}}"#;
        let multi = r#"{"Resources":{"S":{"Type":"AWS::SecretsManager::Secret","Properties":{"ReplicaRegions":[{"Region":"x"}]}}}}"#;
        assert_eq!(scan(http).0.len(), 1);
        // The fixture page has no WebSockets sentence, so that rule is stale, not fired.
        let (d, stale) = scan(ws);
        assert!(d.is_empty() && stale.contains(&"apigateway-websocket-api".to_string()));
        assert!(scan(plain).0.is_empty());
        assert_eq!(scan(multi).0.len(), 1);
    }

    #[test]
    fn a_contradicted_blocker_is_a_guide_conflict() {
        let http = r#"{"Resources":{"A":{"Type":"AWS::ApiGatewayV2::Api","Properties":{"ProtocolType":"HTTP"}}}}"#;
        let d = assessed(http);
        assert_eq!(d[0].conflict.as_deref(), Some("HTTP API"));
        assert!(!d[0].blocks());
    }

    #[test]
    fn terraform_block_conditions() {
        let t = |replica: &str| {
            format!(
                r#"{{"format_version":"1.2","planned_values":{{"root_module":{{"resources":[{{"address":"aws_dynamodb_table.t","mode":"managed","type":"aws_dynamodb_table","provider_name":"registry.terraform.io/hashicorp/aws","values":{{"replica":{replica}}}}}]}}}}}}"#
            )
        };
        assert!(scan(&t("[]")).0.is_empty());
        assert_eq!(
            scan(&t(r#"[{"region_name":"x"}]"#)).0[0].rule,
            "dynamodb-table-replica"
        );
    }
}
