//! The bundled rules database, `data/rules.json`: one rule set for every command.
//!
//! A rule ties an AWS-documented deviation or deterministic target state to resource
//! types and, optionally, property values. Its source is a difference on the ESC User
//! Guide, checked against the live guide on every run, or a quoted sentence on another
//! AWS page, checked by the network test. Availability itself never comes from rules.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::extractor::PartitionFacts;

const RULES_JSON: &str = include_str!("../data/rules.json");

#[derive(Debug, Deserialize)]
struct Rules {
    rules: Vec<Rule>,
}

/// Every rule, loaded once.
pub fn all() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        serde_json::from_str::<Rules>(RULES_JSON)
            .expect("bundled rules are valid")
            .rules
    })
}

/// The rules of `kind` that apply to the target.
pub fn for_target(kind: Kind, facts: &PartitionFacts) -> impl Iterator<Item = &'static Rule> {
    all()
        .iter()
        .filter(move |r| r.kind == kind && r.scope.applies(facts))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A feature the target does not offer or offers with a difference.
    Deviation,
    /// A literal form that works only in some Regions, with its portable replacement.
    Literal,
    /// A literal the target requires at a property, so it is not a hazard there.
    Exemption,
    /// Something the resource needs that stays outside the target, or that the move
    /// cannot take along. Always flagged for the owner.
    Dependency,
    /// A Service Quotas quota the input's resources count against. Live mode only.
    Quota,
    /// How a resource moves to the target: redeployed, replicated or restored, for
    /// the `plan` command.
    Mechanism,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub kind: Kind,
    pub scope: Scope,
    pub source: Source,
    #[serde(default)]
    pub severity: Severity,
    /// The Knowledge MCP product or feature the sentence restricts, to detect conflicts.
    pub feature: Option<String>,
    #[serde(default)]
    pub types: Vec<String>,
    /// Alternatives: the rule fires if any matches. Empty: the type alone fires it.
    #[serde(default)]
    pub when: Vec<Cond>,
    /// The documented substitute. Without one the deviation is left to the owner.
    pub remediation: Option<RuleRemediation>,
    /// Literal rules: a regex-lite pattern over string values. Capture 1 is the literal,
    /// capture 2 the Region it names.
    pub pattern: Option<String>,
    /// Literal rules: the expression that replaces capture 1, per source format.
    pub replace: Option<crate::remediation::Replacement>,
    /// Exemption rules: property paths (dotted, without list indices) of `types`.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Exemption rules: the literal the property requires.
    pub literal: Option<String>,
    /// Quota rules: the quota, and how the input counts against it.
    pub quota: Option<QuotaSpec>,
    /// Mechanism rules: how the resource moves.
    pub mechanism: Option<MechanismSpec>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Boundary {
    Global,
    Regional,
    Zonal,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Content {
    Configuration,
    Code,
    Data,
    /// Logs, metrics and similar records that stay where they were written.
    Supplemental,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum MovePath {
    /// Deploy the input again in the target.
    Redeploy,
    /// A service mechanism copies the content continuously.
    Replicate,
    /// Copy a backup, snapshot or export and restore it in the target.
    Restore,
    /// A scan finding blocks the resource in the target.
    Blocked,
    /// No rule says how the resource moves.
    Unknown,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum DataDecision {
    /// Move the data with the resource.
    Migrate,
    /// Create new content in the target, such as a new key.
    Recreate,
    /// Let the source empty before switching over.
    Drain,
    /// Keep the history in the source.
    Leave,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Layer {
    Foundation,
    Shared,
    Workload,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MechanismSpec {
    pub boundary: Boundary,
    pub content: Content,
    pub path: MovePath,
    pub via: String,
    pub data: Option<DataDecision>,
    /// Whether `via` works across partitions: true for redeploying, which needs only the
    /// scan's fixes; for a service mechanism, what its page says, null where it is silent.
    pub crosses_partition: Option<bool>,
    pub layer: Layer,
    /// The path for a move across partitions when `via` does not work there.
    pub fallback: Option<Fallback>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fallback {
    pub path: MovePath,
    pub via: String,
    pub data: Option<DataDecision>,
    pub url: String,
    pub quote: String,
}

/// The input needs one unit per resource of `types`, or, with `paths`, the sum of the
/// numbers at those properties; plus `reserve`, which the service keeps back.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaSpec {
    pub service_code: String,
    pub quota_code: String,
    /// The quota's name in Service Quotas.
    pub name: String,
    #[serde(default)]
    pub reserve: u64,
}

/// Exemption rules that apply: `value` at `path` of a resource of this type is required.
pub fn exempt(resource_type: &str, path: &str, value: &str, facts: &PartitionFacts) -> bool {
    let bare: String = path
        .split('.')
        .skip(1)
        .map(|seg| seg.split('[').next().unwrap_or(seg))
        .collect::<Vec<_>>()
        .join(".");
    for_target(Kind::Exemption, facts).any(|r| {
        r.types.iter().any(|t| t == resource_type)
            && r.literal.as_deref() == Some(value)
            && r.paths.iter().any(|p| {
                // Below the property sit intrinsic functions, such as `Fn::Join`.
                bare.strip_prefix(p.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
            })
    })
}

/// A literal rule's matches in `s`: the rule, the literal, its Region and its span.
pub fn literals<'a>(
    s: &'a str,
    facts: &PartitionFacts,
) -> Vec<(&'static Rule, &'a str, &'a str, std::ops::Range<usize>)> {
    static COMPILED: OnceLock<Vec<(&'static Rule, regex_lite::Regex)>> = OnceLock::new();
    let compiled = COMPILED.get_or_init(|| {
        all()
            .iter()
            .filter(|r| r.kind == Kind::Literal)
            .map(|r| {
                let p = r.pattern.as_deref().expect("literal rules have a pattern");
                (
                    r,
                    regex_lite::Regex::new(p).expect("literal rule patterns compile"),
                )
            })
            .collect()
    });
    let mut out = Vec::new();
    for (rule, re) in compiled.iter().filter(|(r, _)| r.scope.applies(facts)) {
        for c in re.captures_iter(s) {
            if let (Some(lit), Some(region)) = (c.get(1), c.get(2)) {
                out.push((*rule, lit.as_str(), region.as_str(), lit.range()));
            }
        }
    }
    out
}

impl Rule {
    /// The rule fires on a resource of this type with these properties.
    pub fn matches(&self, resource_type: &str, props: &Value, facts: &PartitionFacts) -> bool {
        self.types.iter().any(|t| t == resource_type)
            && (self.when.is_empty() || self.when.iter().any(|c| c.matches(props, facts)))
    }
}

/// Target partitions or Regions the rule applies to; both empty: any target.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(default)]
    pub partitions: Vec<String>,
    #[serde(default)]
    pub regions: Vec<String>,
    /// Target Regions the rule does not apply to.
    #[serde(default)]
    pub except_regions: Vec<String>,
    /// Only for moves inside one partition: the input was produced for the target's
    /// partition, or, when the input names no environment, it moves to another account.
    #[serde(default)]
    pub within_partition: bool,
}

impl Scope {
    pub fn applies(&self, facts: &PartitionFacts) -> bool {
        let within = match &facts.source_partition {
            Some(p) => *p == facts.target_partition,
            None => facts.target_account.is_some(),
        };
        ((self.partitions.is_empty() && self.regions.is_empty())
            || self.partitions.contains(&facts.target_partition)
            || self.regions.contains(&facts.target_region))
            && !self.except_regions.contains(&facts.target_region)
            && (!self.within_partition || within)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum Source {
    /// A difference on the ESC User Guide page `page` that contains `text` and every
    /// fragment in `also`. Checked against the live guide on every run.
    Guide {
        page: String,
        text: String,
        #[serde(default)]
        also: Vec<String>,
    },
    /// A sentence on an AWS page, quoted verbatim. Checked by the network test.
    Doc { url: String, quote: String },
}

impl Source {
    /// The page the rule rests on.
    pub fn url(&self) -> &str {
        match self {
            Source::Doc { url, .. } => url,
            Source::Guide { page, .. } => page,
        }
    }
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// The feature is not available.
    #[default]
    Blocker,
    /// The feature works with a documented difference.
    Caveat,
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
/// `equals` or `one_of` (case-insensitive; booleans and numbers as text), `prefix`,
/// `contains`, `not_in` (a string value outside the list), `no_other_region` (a string
/// value without a breaking Region or zone hazard, so no hazard fix changes it) or `absent`
/// (no value), and without one it needs a non-empty value. `contains` also searches
/// intrinsic functions, as JSON text.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cond {
    #[serde(default)]
    all: Vec<Cond>,
    path: Option<String>,
    equals: Option<String>,
    prefix: Option<String>,
    contains: Option<String>,
    #[serde(default)]
    not_in: Vec<String>,
    /// A value in the list (case-insensitive).
    #[serde(default)]
    one_of: Vec<String>,
    #[serde(default)]
    no_other_region: bool,
    #[serde(default)]
    absent: bool,
}

impl Cond {
    pub fn matches(&self, props: &Value, facts: &PartitionFacts) -> bool {
        if !self.all.is_empty() {
            return self.all.iter().all(|c| c.matches(props, facts));
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
        if self.absent {
            return values.iter().all(|v| v.is_null());
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
        // Booleans and numbers compare as text, as YAML and JSON write them.
        let text = |v: &Value| match v {
            Value::String(s) => Some(s.clone()),
            Value::Bool(_) | Value::Number(_) => Some(v.to_string()),
            _ => None,
        };
        values.into_iter().any(|v| {
            if let Some(want) = &self.equals {
                text(v).is_some_and(|s| s.eq_ignore_ascii_case(want))
            } else if !self.one_of.is_empty() {
                text(v).is_some_and(|s| self.one_of.iter().any(|x| x.eq_ignore_ascii_case(&s)))
            } else if let Some(p) = &self.prefix {
                v.as_str().is_some_and(|s| s.starts_with(p.as_str()))
            } else if let Some(c) = &self.contains {
                match v {
                    Value::String(s) => s.contains(c.as_str()),
                    v => v.to_string().contains(c.as_str()),
                }
            } else if self.no_other_region {
                v.as_str()
                    .is_some_and(|s| !crate::extractor::names_other_region(s, facts))
            } else if !self.not_in.is_empty() {
                v.as_str()
                    .is_some_and(|s| !self.not_in.iter().any(|x| x.eq_ignore_ascii_case(s)))
            } else {
                !matches!(v, Value::Null | Value::Bool(false))
                    && v.as_array().is_none_or(|a| !a.is_empty())
                    && v.as_object().is_none_or(|o| !o.is_empty())
                    && v.as_str().is_none_or(|s| !s.is_empty())
            }
        })
    }

    /// One operator per condition, and a path unless it combines others.
    #[cfg(test)]
    pub fn well_formed(&self) -> bool {
        let ops = [&self.equals, &self.prefix, &self.contains]
            .iter()
            .filter(|o| o.is_some())
            .count()
            + usize::from(!self.not_in.is_empty())
            + usize::from(!self.one_of.is_empty())
            + usize::from(self.no_other_region)
            + usize::from(self.absent);
        if self.all.is_empty() {
            self.path.as_deref().is_some_and(|p| !p.is_empty()) && ops <= 1
        } else {
            self.path.is_none() && ops == 0 && self.all.iter().all(Cond::well_formed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::partition;

    #[test]
    fn rules_are_well_formed() {
        let rules = all();
        let ids: std::collections::BTreeSet<_> = rules.iter().map(|r| &r.id).collect();
        assert_eq!(ids.len(), rules.len(), "rule ids are unique");
        for r in rules {
            match r.kind {
                Kind::Deviation => assert!(
                    !r.types.is_empty() && r.pattern.is_none() && r.replace.is_none(),
                    "{}",
                    r.id
                ),
                Kind::Mechanism => assert!(
                    !r.types.is_empty()
                        && matches!(r.source, Source::Doc { .. })
                        && r.mechanism.as_ref().is_some_and(|m| {
                            !matches!(m.path, MovePath::Blocked | MovePath::Unknown)
                                && m.fallback.as_ref().is_none_or(|f| {
                                    f.url.starts_with("https://docs.aws.amazon.com/")
                                        && !f.quote.is_empty()
                                })
                        }),
                    "{}: a mechanism rule names types, a documented source and a path",
                    r.id
                ),
                Kind::Quota => assert!(
                    !r.types.is_empty()
                        && r.when.is_empty()
                        && r.quota.is_some()
                        && matches!(r.source, Source::Doc { .. }),
                    "{}: a quota rule names types, the quota and a documented source",
                    r.id
                ),
                Kind::Dependency => assert!(
                    !r.types.is_empty()
                        && r.remediation.is_some()
                        && matches!(r.source, Source::Doc { .. }),
                    "{}: a dependency names types, a documented source and the change",
                    r.id
                ),
                Kind::Exemption => assert!(
                    !r.types.is_empty() && !r.paths.is_empty() && r.literal.is_some(),
                    "{}: an exemption names types, paths and the literal",
                    r.id
                ),
                Kind::Literal => assert!(
                    r.types.is_empty()
                        && r.when.is_empty()
                        && r.replace.is_some()
                        && r.pattern
                            .as_deref()
                            .is_some_and(|p| regex_lite::Regex::new(p)
                                .is_ok_and(|re| re.captures_len() == 3)),
                    "{}: a literal rule has a pattern with two captures and a replacement",
                    r.id
                ),
            }
            assert!(r.when.iter().all(Cond::well_formed), "{}", r.id);
            match &r.source {
                Source::Guide { page, text, also } => assert!(
                    !page.is_empty() && !text.is_empty() && also.iter().all(|a| !a.is_empty()),
                    "{}",
                    r.id
                ),
                Source::Doc { url, quote } => assert!(
                    url.starts_with("https://docs.aws.amazon.com/") && !quote.is_empty(),
                    "{}",
                    r.id
                ),
            }
            for p in &r.scope.partitions {
                assert!(
                    partition::facts("eusc-de-east-1")
                        .unwrap()
                        .dns_suffixes
                        .values()
                        .any(|ps| ps.contains(p)),
                    "{}: unknown partition {p}",
                    r.id
                );
            }
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

    #[test]
    fn scope_limits_rules_to_their_targets() {
        let esc = partition::facts("eusc-de-east-1").unwrap();
        let euw1 = partition::facts("eu-west-1").unwrap();
        let guide = |r: &&Rule| matches!(r.source, Source::Guide { .. });
        let n = |f| for_target(Kind::Deviation, f).filter(guide).count();
        assert_eq!(
            n(&esc),
            all()
                .iter()
                .filter(|r| r.kind == Kind::Deviation)
                .filter(guide)
                .count()
        );
        assert_eq!(n(&euw1), 0, "the guide rules are ESC rules");
        let any = Scope::default();
        assert!(any.applies(&euw1) && any.applies(&esc));
        let one = Scope {
            regions: vec!["eu-west-1".into()],
            ..Scope::default()
        };
        assert!(one.applies(&euw1) && !one.applies(&esc));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let bad = r#"{"rules":[{"id":"x","kind":"deviation","scope":{},"types":["T"],
            "source":{"guide":{"page":"p","text":"t"}},"typo":1}]}"#;
        assert!(serde_json::from_str::<Rules>(bad).is_err());
        let doc = r#"{"rules":[{"id":"x","kind":"deviation","scope":{},"types":["T"],
            "source":{"doc":{"url":"https://docs.aws.amazon.com/x","quote":"q"}}}]}"#;
        assert!(serde_json::from_str::<Rules>(doc).is_ok());
    }

    #[test]
    fn literal_rules_capture_the_literal_and_its_region() {
        let euw1 = partition::facts("eu-west-1").unwrap();
        let s =
            "b.s3-us-west-2.amazonaws.com/k my-s3-us-west-2-logs foo-s3-us-west-2.amazonaws.com";
        let found = literals(s, &euw1);
        assert_eq!(
            found.len(),
            1,
            "a bucket name or a longer host is not an endpoint"
        );
        assert_eq!((found[0].1, found[0].2), ("s3-us-west-2", "us-west-2"));
        assert_eq!(&s[found[0].3.clone()], "s3-us-west-2");
    }

    /// Every quoted sentence is still on its page. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn doc_quotes_are_on_their_pages() {
        let norm = |s: &str| {
            // Inline tags, such as `<code>` around a Region id, sit inside a sentence.
            let s = regex_lite::Regex::new(r"</?(?:code|a|b|i|em|strong|span)(?:\s[^>]*)?>")
                .unwrap()
                .replace_all(s, "");
            let s = regex_lite::Regex::new(r"<[^>]*>")
                .unwrap()
                .replace_all(&s, " ");
            s.replace(['\u{2010}', '\u{2011}', '\u{2013}', '`'], "-")
                .replace("&nbsp;", " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let mut missing = Vec::new();
        let mut pages = std::collections::BTreeMap::new();
        for r in all() {
            let fallback = r
                .mechanism
                .as_ref()
                .and_then(|m| m.fallback.as_ref())
                .map(|f| (&f.url, &f.quote));
            let doc = match &r.source {
                Source::Doc { url, quote } => Some((url, quote)),
                Source::Guide { .. } => None,
            };
            for (url, quote) in doc.into_iter().chain(fallback) {
                let page = pages.entry(url.clone()).or_insert_with(|| norm(&get(url)));
                if !page.contains(&norm(quote)) {
                    missing.push(&r.id);
                }
            }
        }
        assert!(missing.is_empty(), "{missing:?}");
    }

    /// Rule sources are never fetched at runtime, so they are not on the allowlist.
    fn get(url: &str) -> String {
        reqwest::blocking::Client::builder()
            .user_agent(concat!("esc-preflight/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap()
            .get(url)
            .send()
            .unwrap()
            .text()
            .unwrap()
    }

    fn f() -> PartitionFacts {
        partition::facts("eu-west-1").unwrap()
    }

    /// The runtime lists follow the deprecated runtimes table: create-blocked runtimes
    /// have a past block date, deprecated ones a future one, and every runtime with a
    /// block date is in one list. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn runtime_lists_follow_the_deprecation_table() {
        let url = "https://docs.aws.amazon.com/lambda/latest/dg/runtime-support-policy.html";
        let page = get(url);
        let text = regex_lite::Regex::new(r"<[^>]*>")
            .unwrap()
            .replace_all(&page, " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let table = text
            .rsplit_once("Deprecated runtimes")
            .map(|(_, t)| t)
            .unwrap();
        let date = r"([A-Z][a-z]{2}) (\d{1,2}), (\d{4})";
        let row = regex_lite::Regex::new(&format!(
            r"(\S+) Amazon Linux(?: 2023| 2)? {date} (?:{date}|N/A)"
        ))
        .unwrap();
        let months = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let today = &crate::report::now_utc()[..10];
        let (mut past, mut future) = (Vec::new(), Vec::new());
        for c in row.captures_iter(table) {
            let Some(m) = c.get(5) else { continue };
            let month = months.iter().position(|x| *x == m.as_str()).unwrap() + 1;
            let block = format!("{}-{month:02}-{:0>2}", &c[7], &c[6]);
            let id = c[1].to_string();
            if block.as_str() <= today {
                past.push(id);
            } else {
                future.push(id);
            }
        }
        let list = |id: &str| -> Vec<String> {
            let r = all().iter().find(|r| r.id == id).unwrap();
            let mut l = r.when[0].one_of.clone();
            l.sort();
            l
        };
        past.sort();
        future.sort();
        assert!(!past.is_empty() && !future.is_empty(), "table parsed");
        assert_eq!(list("lambda-runtime-create-blocked"), past);
        assert_eq!(list("lambda-runtime-deprecated"), future);
    }

    #[test]
    fn not_in_and_absent() {
        let c: Cond = serde_json::from_str(r#"{"path":"V","not_in":["a","b"]}"#).unwrap();
        assert!(c.matches(&serde_json::json!({"V": "c"}), &f()));
        assert!(!c.matches(&serde_json::json!({"V": "A"}), &f()));
        assert!(!c.matches(&serde_json::json!({"V": {"Ref": "P"}}), &f()));
        assert!(!c.matches(&serde_json::json!({}), &f()));
        let c: Cond = serde_json::from_str(r#"{"path":"V","absent":true}"#).unwrap();
        assert!(c.matches(&serde_json::json!({}), &f()));
        assert!(c.matches(&Value::Null, &f()));
        assert!(!c.matches(&serde_json::json!({"V": "x"}), &f()));
    }

    #[test]
    fn one_of_and_no_other_region() {
        let c: Cond = serde_json::from_str(r#"{"path":"V","one_of":["a","false"]}"#).unwrap();
        assert!(c.matches(&serde_json::json!({"V": "A"}), &f()));
        assert!(
            c.matches(&serde_json::json!({"V": false}), &f()),
            "a boolean as text"
        );
        assert!(!c.matches(&serde_json::json!({"V": "b"}), &f()));
        assert!(!c.matches(&serde_json::json!({}), &f()));
        let c: Cond = serde_json::from_str(r#"{"path":"V","no_other_region":true}"#).unwrap();
        assert!(c.well_formed());
        let m = |v: &str| c.matches(&serde_json::json!({ "V": v }), &f());
        for name in [
            "logs",
            "acme-invoices-2024",
            "my-app-data-1",
            "logs-111122223333",
        ] {
            assert!(m(name), "{name}");
        }
        assert!(m("acme-eu-west-1-logs"), "the target Region stays as it is");
        assert!(
            m("acme-eu-central-1-logs"),
            "no Region hazard inside a label"
        );
        assert!(
            !m("acme-logs-eu-central-1"),
            "a Region fix changes the name"
        );
        assert!(!m("acme-us-east-1"));
        // ESC moves inside the partition are account moves within its one Region.
        let esc = partition::facts("eusc-de-east-1").unwrap();
        let in_esc = |v: &str| c.matches(&serde_json::json!({ "V": v }), &esc);
        assert!(in_esc("acme-logs-eusc-de-east-1"));
        assert!(!in_esc("acme-logs-eu-central-1"));
        assert!(m("acme-us-east-10"), "not a Region id");
        assert!(!c.matches(&serde_json::json!({"V": {"Fn::Sub": "logs"}}), &f()));
    }

    #[test]
    fn except_regions_and_within_partition() {
        let mut euw1 = partition::facts("eu-west-1").unwrap();
        let use1 = partition::facts("us-east-1").unwrap();
        let not_use1 = Scope {
            partitions: vec!["aws".into()],
            except_regions: vec!["us-east-1".into()],
            ..Scope::default()
        };
        assert!(not_use1.applies(&euw1) && !not_use1.applies(&use1));
        let within = Scope {
            within_partition: true,
            ..Scope::default()
        };
        assert!(!within.applies(&euw1), "no environment and no account");
        euw1.target_account = Some("444455556666".into());
        assert!(within.applies(&euw1), "an account move");
        euw1.source_partition = Some("aws-eusc".into());
        assert!(
            !within.applies(&euw1),
            "names are free in another partition"
        );
        euw1.source_partition = Some("aws".into());
        euw1.target_account = None;
        assert!(within.applies(&euw1));
    }

    #[test]
    fn exemptions_match_the_property_and_the_literal() {
        let euw1 = partition::facts("eu-west-1").unwrap();
        let esc = partition::facts("eusc-de-east-1").unwrap();
        let t = "AWS::CloudFront::Distribution";
        let p = "Properties.DistributionConfig.ViewerCertificate.AcmCertificateArn";
        assert!(exempt(t, p, "us-east-1", &euw1));
        assert!(exempt(
            t,
            &format!("{p}.Fn::Join[1][0]"),
            "us-east-1",
            &euw1
        ));
        assert!(
            !exempt(t, p, "eu-west-1", &euw1),
            "only the required literal"
        );
        assert!(!exempt(t, &format!("{p}X"), "us-east-1", &euw1));
        assert!(!exempt("AWS::S3::Bucket", p, "us-east-1", &euw1));
        assert!(!exempt(t, p, "us-east-1", &esc), "outside the rule scope");
        let tf = "values.viewer_certificate[0].acm_certificate_arn";
        assert!(exempt(
            "aws_cloudfront_distribution",
            tf,
            "us-east-1",
            &euw1
        ));
    }
}
