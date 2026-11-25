//! Known mitigations for gaps: another AWS service, a self-managed build or another
//! partition, each from an AWS page quoted in `data/mitigations.json` (checked by the
//! ignored doc-quote test). A mitigation is attached to the required changes of the
//! resource types or rules it answers; it never changes a verdict.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct File {
    mitigations: Vec<Entry>,
}

#[derive(Deserialize)]
pub(crate) struct Entry {
    id: String,
    /// Resource type patterns, `*` as a wildcard.
    types: Vec<String>,
    /// Rule ids whose findings it answers.
    rules: Vec<String>,
    /// Target partitions it applies to; empty for any.
    partitions: Vec<String>,
    kind: Kind,
    summary: String,
    tradeoffs: String,
    pub(crate) source: Source,
    validation: Validation,
}

#[derive(Deserialize)]
pub(crate) struct Source {
    pub(crate) url: String,
    #[allow(dead_code, reason = "read by the doc-quote test")]
    pub(crate) quote: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// Another AWS service.
    Substitute,
    /// Open source or own code on AWS compute.
    SelfManaged,
    /// The service in another partition; a sovereignty and compliance decision.
    CrossPartition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Validation {
    /// An AWS page describes it.
    Documented,
    /// Deployed and tested by someone who reported it, in addition.
    FieldProven,
    /// No longer needed or no longer right, kept for the record; never reported.
    Deprecated,
}

/// A mitigation as the report carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct Mitigation {
    pub id: String,
    pub kind: Kind,
    pub summary: String,
    pub tradeoffs: String,
    pub doc: String,
    pub validation: Validation,
}

pub(crate) fn all() -> &'static [Entry] {
    static F: OnceLock<File> = OnceLock::new();
    &F.get_or_init(|| {
        serde_json::from_str(include_str!("../data/mitigations.json"))
            .expect("bundled mitigations are valid")
    })
    .mitigations
}

/// Mitigations for an unavailable `resource_type`, or for the rules in `rule_ids`, in
/// `partition`. Deprecated ones are left out.
pub fn find(resource_type: Option<&str>, rule_ids: &[String], partition: &str) -> Vec<Mitigation> {
    all()
        .iter()
        .filter(|m| m.validation != Validation::Deprecated)
        .filter(|m| m.partitions.is_empty() || m.partitions.iter().any(|p| p == partition))
        .filter(|m| {
            resource_type.is_some_and(|rt| m.types.iter().any(|t| matches(t, rt)))
                || m.rules.iter().any(|r| rule_ids.contains(r))
        })
        .map(|m| Mitigation {
            id: m.id.clone(),
            kind: m.kind,
            summary: m.summary.clone(),
            tradeoffs: m.tradeoffs.clone(),
            doc: m.source.url.clone(),
            validation: m.validation,
        })
        .collect()
}

fn matches(pattern: &str, t: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => t.starts_with(prefix),
        None => pattern == t,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn found_by_type_rule_and_partition() {
        let ids = |v: Vec<Mitigation>| v.into_iter().map(|m| m.id).collect::<Vec<_>>();
        assert_eq!(
            ids(find(Some("AWS::AppSync::GraphQLApi"), &[], "aws-eusc")),
            ["appsync-graphql-on-lambda"]
        );
        assert_eq!(
            ids(find(None, &["eks-fargate".into()], "aws-eusc")),
            ["eks-managed-node-groups"]
        );
        assert!(find(Some("AWS::CloudFront::Distribution"), &[], "aws-eusc").is_empty());
        assert_eq!(
            ids(find(
                Some("AWS::CloudFront::Distribution"),
                &[],
                "aws-us-gov"
            )),
            ["cloudfront-from-the-global-partition"]
        );
        assert!(find(Some("AWS::S3::Bucket"), &[], "aws").is_empty());
    }

    #[test]
    fn ids_are_unique_and_sources_are_aws_pages() {
        let mut seen = std::collections::BTreeSet::new();
        for m in all() {
            assert!(seen.insert(&m.id), "{}", m.id);
            assert!(
                m.source.url.starts_with("https://docs.aws.amazon.com/")
                    || m.source.url.starts_with("https://aws.amazon.com/blogs/"),
                "{}",
                m.id
            );
            assert!(!m.types.is_empty() || !m.rules.is_empty(), "{}", m.id);
            for r in &m.rules {
                assert!(
                    crate::rules::all().iter().any(|x| &x.id == r),
                    "{}: {r}",
                    m.id
                );
            }
        }
    }
}
