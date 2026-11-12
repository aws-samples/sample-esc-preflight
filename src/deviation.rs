//! Documented feature differences that a resource in the input uses.
//!
//! Each rule ties a sentence of the ESC User Guide to resource types and, optionally,
//! property values. A rule is active only while its sentence is on the live page.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::matcher::{Finding, Verdict};
use crate::model::Template;
use crate::provider::guide::{GuideData, Page};

const RULES_JSON: &str = include_str!("../data/esc-guide-rules.json");

#[derive(Debug, Deserialize)]
struct Rules {
    rules: Vec<Rule>,
}

fn rules() -> Vec<Rule> {
    serde_json::from_str::<Rules>(RULES_JSON)
        .expect("bundled rules are valid")
        .rules
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    id: String,
    page: String,
    /// A fragment of one documented difference.
    text: String,
    /// Further fragments that must be in the same difference, for list items.
    #[serde(default)]
    also: Vec<String>,
    types: Vec<String>,
    /// Alternatives: the rule fires if any matches. Empty: the type alone fires it.
    #[serde(default)]
    when: Vec<Cond>,
    /// The documented substitute, for features that cannot exist in a single-region
    /// partition. Without one the deviation is left to the owner.
    remediation: Option<RuleRemediation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleRemediation {
    /// The change in a few words, for the terminal summary.
    pub action: String,
    pub change: String,
    pub consequence: String,
    /// AWS documentation of the substitute.
    pub doc: String,
}

/// `all` conditions must all match; otherwise `path` is tested with at most one of
/// `equals` (case-insensitive), `prefix` or `contains`, and without one it needs a
/// non-empty value. `contains` also searches intrinsic functions, as JSON text.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cond {
    #[serde(default)]
    all: Vec<Cond>,
    path: Option<String>,
    equals: Option<String>,
    prefix: Option<String>,
    contains: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Deviation {
    pub logical_id: String,
    pub resource_type: String,
    pub rule: String,
    /// The documented difference, as the guide states it.
    pub documented: String,
    pub source: String,
    #[serde(skip)]
    pub remediation: Option<RuleRemediation>,
}

/// The differences one guide page documents for a service the input uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Documented {
    pub page: String,
    pub url: String,
    pub differences: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct GuideFindings {
    pub deviations: Vec<Deviation>,
    pub documented: Vec<Documented>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuideProvenance {
    pub toc_url: String,
    pub pages: usize,
    /// Rules that match the input but whose sentence is no longer on the guide: the
    /// restriction may have been lifted, or the wording changed.
    pub stale_rules: Vec<String>,
    /// Guide pages that map to no known service.
    pub unmapped_pages: Vec<String>,
}

/// The documented substitute for a resource type, from a rule that fires on the type
/// alone. Used when the type itself is not available in the target.
pub fn substitute_for(resource_type: &str) -> Option<RuleRemediation> {
    static RULES: std::sync::OnceLock<Vec<Rule>> = std::sync::OnceLock::new();
    RULES
        .get_or_init(rules)
        .iter()
        .find(|r| r.when.is_empty() && r.types.iter().any(|t| t == resource_type))
        .and_then(|r| r.remediation.clone())
}

pub fn assess(
    template: &Template,
    findings: &[Finding],
    guide: &GuideData,
) -> (GuideFindings, GuideProvenance) {
    let (mut deviations, stale_rules) = find(template, guide);
    // A resource that is not available at all already carries a required change.
    deviations.retain(|d| {
        !findings
            .iter()
            .any(|f| f.logical_id == d.logical_id && f.verdict == Verdict::NotAvailable)
    });
    let mut documented: Vec<Documented> = Vec::new();
    for f in findings {
        for p in guide.pages_for(f.service.as_deref(), &f.resource_type) {
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
            documented,
        },
        GuideProvenance {
            toc_url: guide.toc_url.clone(),
            pages: guide.pages.len(),
            stale_rules,
            unmapped_pages: guide.unmapped.clone(),
        },
    )
}

/// Deviations found in the input, and the ids of stale rules that apply to it.
fn find(template: &Template, guide: &GuideData) -> (Vec<Deviation>, Vec<String>) {
    let rules = rules();
    let (mut out, mut stale) = (Vec::new(), Vec::new());
    for rule in &rules {
        let hits: Vec<_> = template
            .resources
            .values()
            .filter(|r| {
                rule.types.contains(&r.resource_type)
                    && (rule.when.is_empty() || rule.when.iter().any(|c| c.matches(&r.properties)))
            })
            .collect();
        if hits.is_empty() {
            continue;
        }
        let Some((page, documented)) = anchor(rule, guide) else {
            stale.push(rule.id.clone());
            continue;
        };
        out.extend(hits.into_iter().map(|r| Deviation {
            logical_id: r.logical_id.clone(),
            resource_type: r.resource_type.clone(),
            rule: rule.id.clone(),
            documented: documented.clone(),
            source: page.url.clone(),
            remediation: rule.remediation.clone(),
        }));
    }
    out.sort_by(|a, b| (&a.logical_id, &a.rule).cmp(&(&b.logical_id, &b.rule)));
    (out, stale)
}

/// The page and the one documented difference a rule quotes, if still on the guide.
fn anchor<'g>(rule: &Rule, guide: &'g GuideData) -> Option<(&'g Page, &'g String)> {
    let p = guide.page(&rule.page)?;
    p.differences
        .iter()
        .find(|d| d.contains(&rule.text) && rule.also.iter().all(|a| d.contains(a)))
        .map(|d| (p, d))
}

impl Cond {
    fn matches(&self, props: &Value) -> bool {
        if !self.all.is_empty() {
            return self.all.iter().all(|c| c.matches(props));
        }
        let Some(path) = &self.path else {
            return false;
        };
        let mut values = vec![props];
        for key in path.split('.') {
            values = values
                .into_iter()
                .flat_map(|v| match v {
                    Value::Array(a) => a.iter().filter_map(|x| x.get(key)).collect(),
                    v => v.get(key).into_iter().collect::<Vec<_>>(),
                })
                .collect();
        }
        // A list of scalars matches if any element does.
        let values: Vec<&Value> = values
            .into_iter()
            .flat_map(|v| match v {
                Value::Array(a) if a.iter().all(|x| !x.is_object()) && !a.is_empty() => {
                    a.iter().collect()
                }
                v => vec![v],
            })
            .collect();
        values.into_iter().any(|v| {
            if let Some(want) = &self.equals {
                v.as_str().is_some_and(|s| s.eq_ignore_ascii_case(want))
            } else if let Some(p) = &self.prefix {
                v.as_str().is_some_and(|s| s.starts_with(p.as_str()))
            } else if let Some(c) = &self.contains {
                match v {
                    Value::String(s) => s.contains(c.as_str()),
                    v => v.to_string().contains(c.as_str()),
                }
            } else {
                !matches!(v, Value::Null | Value::Bool(false))
                    && v.as_array().is_none_or(|a| !a.is_empty())
                    && v.as_object().is_none_or(|o| !o.is_empty())
                    && v.as_str().is_none_or(|s| !s.is_empty())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Origin, Resource};
    use crate::provider::guide;
    use crate::reader;

    fn scan(template: &str) -> (Vec<Deviation>, Vec<String>) {
        find(&reader::parse(template).unwrap(), &guide::tests::fixture())
    }

    fn well_formed(c: &Cond) -> bool {
        let ops = [&c.equals, &c.prefix, &c.contains]
            .iter()
            .filter(|o| o.is_some())
            .count();
        if c.all.is_empty() {
            c.path.as_deref().is_some_and(|p| !p.is_empty()) && ops <= 1
        } else {
            c.path.is_none() && ops == 0 && c.all.iter().all(well_formed)
        }
    }

    /// A guide on which every rule is active, to test conditions apart from anchors.
    fn all_active() -> GuideData {
        let mut pages: Vec<guide::Page> = Vec::new();
        for r in rules() {
            let item = std::iter::once(r.text.clone())
                .chain(r.also)
                .collect::<Vec<_>>()
                .join(" ");
            match pages.iter_mut().find(|p| p.slug == r.page) {
                Some(p) => p.differences.push(item),
                None => pages.push(guide::Page {
                    url: format!("{}{}.html", guide::BASE, r.page),
                    slug: r.page,
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
            unmapped: Vec::new(),
        }
    }

    fn fired(resource_type: &str, props: Value, g: &GuideData) -> Vec<String> {
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
            },
        );
        find(&t, g).0.into_iter().map(|d| d.rule).collect()
    }

    #[test]
    fn rules_are_well_formed() {
        let rules = rules();
        let ids: std::collections::BTreeSet<_> = rules.iter().map(|r| &r.id).collect();
        assert_eq!(ids.len(), rules.len(), "rule ids are unique");
        for r in &rules {
            assert!(!r.types.is_empty() && !r.text.is_empty(), "{}", r.id);
            assert!(r.when.iter().all(well_formed), "{}", r.id);
            assert!(r.also.iter().all(|a| !a.is_empty()), "{}", r.id);
            if let Some(m) = &r.remediation {
                assert!(
                    !m.action.is_empty() && m.action.len() <= 45,
                    "{}: action is required and short",
                    r.id
                );
                assert!(
                    !m.change.is_empty() && !m.consequence.is_empty(),
                    "{}",
                    r.id
                );
                assert!(
                    m.doc.starts_with("https://docs.aws.amazon.com/"),
                    "{}",
                    r.id
                );
            }
        }
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
        for (rule, ty, props, fires) in &cases.cases {
            let hit = fired(ty, props.clone(), &g).contains(rule);
            assert_eq!(hit, *fires, "{rule} on {ty} {props}");
        }
        for r in rules() {
            let mine = || cases.cases.iter().filter(|c| c.0 == r.id);
            if r.when.is_empty() {
                for ty in &r.types {
                    assert!(
                        fired(ty, Value::Null, &g).contains(&r.id),
                        "{} on {ty}",
                        r.id
                    );
                }
                assert!(mine().next().is_none(), "{} needs no cases", r.id);
            } else {
                assert!(mine().any(|c| c.3), "{} has no case that fires", r.id);
                assert!(mine().any(|c| !c.3), "{} has no near miss", r.id);
                assert!(
                    fired(&r.types[0], Value::Null, &g)
                        .iter()
                        .all(|x| *x != r.id),
                    "{} fires without properties",
                    r.id
                );
            }
        }
    }

    /// Every rule's sentence is on the live guide. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn no_stale_rules_on_the_live_guide() {
        let client =
            crate::provider::http::Client::new(std::time::Duration::from_secs(30)).unwrap();
        let g = guide::fetch(&client).unwrap();
        let stale: Vec<_> = rules()
            .into_iter()
            .filter(|r| anchor(r, &g).is_none())
            .map(|r| r.id)
            .collect();
        assert!(stale.is_empty(), "{stale:?}");
    }

    #[test]
    fn type_rule_fires_with_the_documented_sentence() {
        let (d, _) = scan(r#"{"Resources":{"U":{"Type":"AWS::Lambda::Url"}}}"#);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].rule, "lambda-function-urls");
        assert_eq!(d[0].documented, "Function URLs is not available.");
        assert!(d[0].source.ends_with("/lambda.html"));
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
