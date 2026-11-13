//! Turns mapped resources plus availability data into one verdict per resource.
//!
//! The AWS Knowledge MCP data decides in public mode; live mode overrides it. A resource
//! whose type is available while its product is only planned is disputed: the type
//! exists, the service may not be launched.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::depth::DepthCheck;
use crate::model::Template;
use crate::provider::knowledge::{Knowledge, State};
use crate::provider::terraform::TfMaps;
use crate::type_mapper::{Check, Mapping, TypeMapper};

/// Every not-available finding carries advice.
const NOT_AVAILABLE_NOTE: &str = "Not available in the target region. Remove the resource from the deployment there or replace it with a service the region offers.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "kebab-case")]
pub enum Verdict {
    Available,
    NotAvailable,
    /// The sources disagree, or the type exists while its product is not launched.
    Disputed,
    /// No source knows the resource.
    CannotAssess,
}

/// Result of a service API probe for one SDK service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceStatus {
    Offered,
    /// No endpoint answers in the target region.
    NotOffered,
    /// The service answered access denied although the caller has ReadOnlyAccess.
    Refused,
    Unverified(String),
}

/// What live mode learned. Each part is filled only if the input needed it.
#[derive(Debug, Clone, Default)]
pub struct Live {
    pub registry: Option<BTreeSet<String>>,
    /// By SDK service id.
    pub services: BTreeMap<String, ServiceStatus>,
    pub depth: BTreeMap<String, Vec<DepthCheck>>,
    /// Number of zones the target region offers, when the input's zone spread was checked.
    pub target_zones: Option<usize>,
    /// What the target offers per probed depth kind, for replacement candidates.
    pub offered: crate::depth::Offered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LiveCheckKind {
    TypeRegistry,
    ServiceApi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Listed {
    Available,
    NotAvailable,
    Unknown,
}

/// What each source said about one resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    /// The AWS Knowledge MCP data for the type, operation or service.
    pub knowledge: Listed,
    /// The live check found the resource offered. Absent without live mode or when the
    /// check could not decide.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_check: Option<LiveCheckKind>,
}

/// The product's state in the target region, when it is not available there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Roadmap {
    pub product: String,
    pub status: State,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch: Option<String>,
}

impl Roadmap {
    /// `planned 2027 Q1`, `planning`, `not expanding`.
    pub fn short(&self) -> String {
        match (self.status, &self.launch) {
            (State::Planned, Some(q)) => format!("planned {q}"),
            (State::Planned, None) => "planned".into(),
            (State::Planning, _) => "planning".into(),
            (State::NotExpanding, _) => "not expanding".into(),
            (State::NotAvailable | State::Available, _) => "not available".into(),
        }
    }

    fn sentence(&self) -> String {
        let state = match (self.status, &self.launch) {
            (State::Planned, Some(q)) => format!("is planned for {q}"),
            (State::Planned, None) => "is planned".into(),
            (State::Planning, _) => "is being planned, without a date".into(),
            (State::NotExpanding, _) => "is not expanding to the region".into(),
            (State::NotAvailable | State::Available, _) => "is not available".into(),
        };
        format!("{} {state}", self.product)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub logical_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdk_path: Option<String>,
    pub resource_type: String,
    pub service: Option<String>,
    #[serde(flatten)]
    pub verdict: Verdict,
    pub evidence: Option<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roadmap: Option<Roadmap>,
    pub note: Option<String>,
    /// The live check contradicted the Knowledge MCP data (an AWS data-staleness signal).
    pub divergence: bool,
    /// Property values checked against what the target region offers.
    pub depth: Vec<DepthCheck>,
    /// Not available while other types of the same service are.
    #[serde(skip)]
    pub type_gap: bool,
}

/// One finding per non-pseudo resource, in logical-id order.
pub fn assess(
    template: &Template,
    k: &Knowledge,
    tf: Option<&TfMaps>,
    live: Option<&Live>,
    depth: &BTreeMap<String, Vec<DepthCheck>>,
) -> Vec<Finding> {
    let mapper = TypeMapper::new(tf);
    let mut out = Vec::new();
    for r in template.resources.values() {
        let depth = depth.get(&r.logical_id).cloned().unwrap_or_default();
        let base = |verdict, note: Option<String>| Finding {
            logical_id: r.logical_id.clone(),
            cdk_path: r.cdk_path.clone(),
            resource_type: r.resource_type.clone(),
            service: None,
            verdict,
            evidence: None,
            roadmap: None,
            note,
            divergence: false,
            depth: depth.clone(),
            type_gap: false,
        };
        let (service, check) = match mapper.map(r) {
            Mapping::Pseudo => continue,
            Mapping::Unknown { reason } => {
                out.push(base(Verdict::CannotAssess, Some(reason)));
                continue;
            }
            Mapping::Resource { service, check } => (service, check),
        };
        let listed = knowledge_status(k, &check);
        let product = match &check {
            Check::Type(t) => k.product_of(t),
            Check::Api { service_id, .. } => k.product_of_service(service_id),
        };
        let roadmap = product.and_then(|(name, p)| {
            (p.state != State::Available).then(|| Roadmap {
                product: name.to_string(),
                status: p.state,
                launch: p.launch.clone(),
            })
        });
        let (live_listed, live_check, mut notes, refused) = live_result(live, &check, listed);
        // A listed type of a product that is planned is mid-rollout: disputed. One of a
        // product that is not expanding to the region is not available.
        let listed_verdict = match roadmap.as_ref().map(|r| r.status) {
            None => Verdict::Available,
            Some(State::NotExpanding) => Verdict::NotAvailable,
            Some(_) => Verdict::Disputed,
        };
        let (verdict, divergence) = match live_listed {
            Some(true) => (listed_verdict, listed == Listed::NotAvailable),
            Some(false) => (Verdict::NotAvailable, listed == Listed::Available),
            None if refused => (Verdict::Disputed, false),
            None => match listed {
                Listed::Available => (listed_verdict, false),
                Listed::NotAvailable => (Verdict::NotAvailable, false),
                Listed::Unknown => (Verdict::CannotAssess, false),
            },
        };
        let type_listed =
            live_listed == Some(true) || (live_listed.is_none() && listed == Listed::Available);
        let type_gap = verdict == Verdict::NotAvailable
            && !type_listed
            && match &check {
                Check::Type(t) => sibling_available(t, k, live),
                Check::Api { .. } => false,
            };
        match (verdict, &roadmap) {
            (Verdict::Disputed | Verdict::NotAvailable, Some(rm)) if type_listed => notes.push(format!(
                "{} lists {}, but {} in the target region. Check that the feature works before relying on it.",
                if live_listed == Some(true) {
                    "The CloudFormation registry of the target region"
                } else {
                    "The Knowledge MCP data"
                },
                check_label(&check),
                rm.sentence()
            )),
            (Verdict::NotAvailable, _) if type_gap => notes.push(format!(
                "The service is available in the target region, but CloudFormation does not offer {} there.",
                check_label(&check)
            )),
            (Verdict::NotAvailable, Some(rm)) => {
                notes.push(format!("{}.", rm.sentence()));
                notes.push(NOT_AVAILABLE_NOTE.into());
            }
            (Verdict::NotAvailable, None) => notes.push(NOT_AVAILABLE_NOTE.into()),
            (Verdict::CannotAssess, _) => notes.push(match &check {
                Check::Type(_) => "The Knowledge MCP data does not know this type; it may be retired or newer than the data. Live mode checks it in the target registry.".into(),
                Check::Api { .. } => "The Knowledge MCP data does not know this service.".into(),
            }),
            _ => {}
        }
        out.push(Finding {
            service,
            verdict,
            evidence: Some(Evidence {
                knowledge: listed,
                live: live_listed,
                live_check,
            }),
            roadmap,
            note: join(notes),
            divergence,
            type_gap,
            ..base(verdict, None)
        });
    }
    out
}

fn knowledge_status(k: &Knowledge, check: &Check) -> Listed {
    let listed = |v: Option<&bool>| match v {
        Some(true) => Listed::Available,
        Some(false) => Listed::NotAvailable,
        None => Listed::Unknown,
    };
    match check {
        Check::Type(t) => listed(k.types.get(t)),
        Check::Api {
            service_id,
            operation,
        } => match operation
            .as_ref()
            .and_then(|o| k.operations.get(&format!("{service_id}+{o}")))
        {
            Some(v) => listed(Some(v)),
            None => listed(k.services.get(service_id)),
        },
    }
}

fn check_label(check: &Check) -> String {
    match check {
        Check::Type(t) => format!("the resource type {t}"),
        Check::Api {
            service_id,
            operation: Some(o),
        } => format!("{service_id} {o}"),
        Check::Api { service_id, .. } => service_id.clone(),
    }
}

/// Another type of the same service is available in the target.
fn sibling_available(t: &str, k: &Knowledge, live: Option<&Live>) -> bool {
    let Some(i) = t.rfind("::") else {
        return false;
    };
    let prefix = &t[..i + 2];
    match live.and_then(|l| l.registry.as_ref()) {
        Some(reg) => reg.iter().any(|x| x.starts_with(prefix)),
        None => t
            .split("::")
            .nth(1)
            .is_some_and(|ns| k.namespace_available(ns)),
    }
}

/// The live answer, notes explaining why there is none, and whether an access-denied
/// answer contradicts the Knowledge MCP data.
fn live_result(
    live: Option<&Live>,
    check: &Check,
    listed: Listed,
) -> (Option<bool>, Option<LiveCheckKind>, Vec<String>, bool) {
    let Some(live) = live else {
        return (None, None, Vec::new(), false);
    };
    match check {
        Check::Type(t) => (
            live.registry.as_ref().map(|reg| reg.contains(t)),
            Some(LiveCheckKind::TypeRegistry),
            Vec::new(),
            false,
        ),
        Check::Api { service_id, .. } => {
            let kind = Some(LiveCheckKind::ServiceApi);
            match live.services.get(service_id) {
                Some(ServiceStatus::Offered) => (Some(true), kind, Vec::new(), false),
                Some(ServiceStatus::NotOffered) => (Some(false), kind, Vec::new(), false),
                // Access denied despite ReadOnlyAccess does not override a service the
                // public data lists: something else, such as an account setting, may deny it.
                Some(ServiceStatus::Refused) if listed == Listed::Available => (
                    None,
                    kind,
                    vec!["The service answered access denied although the caller has ReadOnlyAccess, while the Knowledge MCP data lists it. Check account settings and policies that may deny the service.".into()],
                    true,
                ),
                Some(ServiceStatus::Refused) => (Some(false), kind, Vec::new(), false),
                Some(ServiceStatus::Unverified(why)) => (
                    None,
                    kind,
                    vec![format!("Live check unverified: {why}")],
                    false,
                ),
                None => (None, kind, Vec::new(), false),
            }
        }
    }
}

fn join(notes: Vec<String>) -> Option<String> {
    (!notes.is_empty()).then(|| notes.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{knowledge, terraform};
    use crate::reader;

    fn registry(types: &[&str]) -> Live {
        Live {
            registry: Some(types.iter().map(|s| s.to_string()).collect()),
            ..Live::default()
        }
    }

    fn one(resource_type: &str, live: Option<&Live>) -> Finding {
        let t = reader::parse_text(&format!(
            r#"{{"Resources":{{"R":{{"Type":"{resource_type}"}}}}}}"#
        ))
        .unwrap();
        assess(
            &t,
            &knowledge::tests::fixture(),
            None,
            live,
            &BTreeMap::new(),
        )
        .pop()
        .unwrap()
    }

    #[test]
    fn available_type() {
        let f = one("AWS::Lambda::Function", None);
        assert_eq!(f.verdict, Verdict::Available);
        assert_eq!(f.evidence.unwrap().knowledge, Listed::Available);
        assert!(f.roadmap.is_none() && f.note.is_none());
    }

    #[test]
    fn not_available_type_carries_its_roadmap() {
        let f = one("AWS::DynamoDB::GlobalTable", None);
        assert_eq!(f.verdict, Verdict::NotAvailable);
        assert_eq!(f.roadmap.as_ref().unwrap().status, State::NotExpanding);
        let f = one("AWS::QBusiness::Application", None);
        assert_eq!(f.verdict, Verdict::NotAvailable);
        assert_eq!(f.roadmap.unwrap().product, "Amazon Q Business");
        assert!(f.note.unwrap().ends_with(NOT_AVAILABLE_NOTE));
    }

    #[test]
    fn listed_type_of_a_product_not_expanding_is_not_available() {
        // IoT Core types are registered in ESC while the product is not expanding.
        let f = one("AWS::IoT::Thing", Some(&registry(&["AWS::IoT::Thing"])));
        assert_eq!(f.verdict, Verdict::NotAvailable);
        assert!(!f.type_gap);
        assert!(f.note.unwrap().contains("not expanding"));
    }

    #[test]
    fn listed_type_of_an_unlaunched_product_is_disputed() {
        // CloudFront types exist in ESC while the service is planned.
        let f = one("AWS::CloudFront::Distribution", None);
        assert_eq!(f.verdict, Verdict::Disputed);
        assert_eq!(f.roadmap.as_ref().unwrap().status, State::Planned);
        assert!(f.note.unwrap().contains("Amazon CloudFront is planned"));
        let f = one(
            "AWS::CloudFront::Distribution",
            Some(&registry(&["AWS::CloudFront::Distribution"])),
        );
        assert_eq!(f.verdict, Verdict::Disputed);
        assert!(f.note.unwrap().contains("CloudFormation registry"));
    }

    #[test]
    fn unknown_types_are_cannot_assess_unless_live() {
        assert_eq!(
            one("AWS::NotAService::Thing", None).verdict,
            Verdict::CannotAssess
        );
        assert_eq!(
            one(
                "AWS::NotAService::Thing",
                Some(&registry(&["AWS::NotAService::Thing"]))
            )
            .verdict,
            Verdict::Available
        );
    }

    #[test]
    fn custom_resource_without_sdk_call_states_why() {
        let f = one("Custom::Registration", None);
        assert_eq!(f.verdict, Verdict::CannotAssess);
        assert!(f.note.unwrap().contains("own code"));
    }

    #[test]
    fn custom_resource_is_decided_by_its_operation() {
        let t = reader::parse_text(crate::test_inputs::CUSTOM_RESOURCES_TEMPLATE).unwrap();
        let f: BTreeMap<_, _> = assess(
            &t,
            &knowledge::tests::fixture(),
            None,
            None,
            &BTreeMap::new(),
        )
        .into_iter()
        .map(|f| (f.logical_id.clone(), f))
        .collect();
        assert_eq!(f["DescribeClient"].verdict, Verdict::Available);
        // The operation exists while CloudFront is only planned.
        assert_eq!(f["CreateInvalidation"].verdict, Verdict::Disputed);
    }

    #[test]
    fn live_overrides_and_divergence() {
        let f = one("AWS::Lambda::Function", Some(&registry(&[])));
        assert_eq!(f.verdict, Verdict::NotAvailable);
        assert!(f.divergence);
        let f = one(
            "AWS::QBusiness::Application",
            Some(&registry(&["AWS::QBusiness::Application"])),
        );
        assert!(f.divergence);
    }

    #[test]
    fn type_level_gap() {
        let f = one(
            "AWS::DynamoDB::GlobalTable",
            Some(&registry(&["AWS::DynamoDB::Table"])),
        );
        assert_eq!(f.verdict, Verdict::NotAvailable);
        assert!(f.type_gap && !f.divergence);
        assert!(f.note.unwrap().contains("resource type"));
    }

    fn tf_one(ty: &str, l: Option<&Live>) -> Finding {
        let t = format!(
            r#"{{"format_version":"1.2","planned_values":{{"root_module":{{"resources":[{{"address":"{ty}.p","mode":"managed","type":"{ty}","provider_name":"registry.terraform.io/hashicorp/aws","values":{{}}}}]}}}}}}"#
        );
        let tf = terraform::tests::fixture();
        assess(
            &reader::parse_text(&t).unwrap(),
            &knowledge::tests::fixture(),
            Some(&tf),
            l,
            &BTreeMap::new(),
        )
        .pop()
        .unwrap()
    }

    #[test]
    fn terraform_resources_are_decided_by_their_service() {
        assert_eq!(
            tf_one("aws_codebuild_project", None).verdict,
            Verdict::Available
        );
        let live = |s: ServiceStatus| Live {
            services: [("CodeBuild".to_string(), s)].into_iter().collect(),
            ..Live::default()
        };
        let f = tf_one("aws_codebuild_project", Some(&live(ServiceStatus::Refused)));
        assert_eq!(f.verdict, Verdict::Disputed);
        assert!(f.note.unwrap().contains("ReadOnlyAccess"));
        let f = tf_one(
            "aws_codebuild_project",
            Some(&live(ServiceStatus::NotOffered)),
        );
        assert_eq!(f.verdict, Verdict::NotAvailable);
        assert!(f.divergence);
        let f = tf_one(
            "aws_codebuild_project",
            Some(&live(ServiceStatus::Unverified("AccessDenied".into()))),
        );
        assert_eq!(f.verdict, Verdict::Available);
        assert!(f.note.unwrap().contains("unverified"));
    }

    #[test]
    fn pseudo_resources_produce_no_finding() {
        let t = reader::parse_text(r#"{"Resources":{"M":{"Type":"AWS::CDK::Metadata"}}}"#).unwrap();
        assert!(
            assess(
                &t,
                &knowledge::tests::fixture(),
                None,
                None,
                &BTreeMap::new()
            )
            .is_empty()
        );
    }
}
