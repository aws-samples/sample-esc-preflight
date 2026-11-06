//! Turns mapped resources plus source evidence into one verdict per resource.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::depth::DepthCheck;
use crate::model::Template;
use crate::provider::PublicData;
use crate::type_mapper::{LiveCheck, Mapping, TypeMapper};

/// Every not-available finding carries advice.
const NOT_AVAILABLE_NOTE: &str = "Not available in the target region. Remove the resource from the deployment there or replace it with a service the region offers.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "kebab-case")]
pub enum Verdict {
    /// Deployable. `single_source` is true when only one kind of source confirms it:
    /// an offering source (regional table, ESC User Guide) or, where no offering source
    /// covers the target, an endpoint source (botocore, ESC endpoints page).
    Available {
        single_source: bool,
    },
    NotAvailable,
    /// The public sources disagree and no live check settled it. No source wins.
    Disputed,
    /// The resource could not be mapped to a known service.
    CannotAssess,
}

/// Result of a service API probe for one endpoint prefix.
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

/// What each source said about one resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    /// botocore lists an endpoint for the target region. `false` is silence, not absence.
    pub botocore_listed: bool,
    /// `None` when the table has no data for the target region.
    pub regional_table_listed: Option<bool>,
    /// The ESC endpoints page lists the endpoint. `false` is silence, not absence.
    /// `None` when the target is outside the partition the page covers.
    pub endpoints_page_listed: Option<bool>,
    /// The ESC User Guide has a page for the service. `None` outside its partition.
    pub user_guide_listed: Option<bool>,
    /// The live check found the resource offered. `None` without live mode or when the
    /// check could not decide.
    pub live_listed: Option<bool>,
    pub live_check: Option<LiveCheckKind>,
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
    pub note: Option<String>,
    /// The live check disagreed with both public sources (AWS data-staleness signal).
    pub divergence: bool,
    /// Property values checked against what the target region offers.
    pub depth: Vec<DepthCheck>,
}

/// One finding per non-pseudo resource, in logical-id order.
pub fn assess(template: &Template, data: &PublicData, live: Option<&Live>) -> Vec<Finding> {
    let mapper = TypeMapper::new(
        data.botocore.known_services.iter().cloned(),
        data.tf.as_ref(),
    );
    let mut out = Vec::new();
    for r in template.resources.values() {
        let (svc, check, reason) = match mapper.map(r) {
            Mapping::Pseudo => continue,
            Mapping::Service { service, live } => (Some(service), Some(live), None),
            Mapping::Unknown { live, reason } => (None, live, reason),
        };
        let depth = live
            .and_then(|l| l.depth.get(&r.logical_id).cloned())
            .unwrap_or_default();
        let documented = svc
            .as_deref()
            .zip(data.guide.as_ref())
            .is_some_and(|(s, g)| g.documents(s));
        let (live_listed, kind, mut notes_out, contested) =
            live_result(live, check.as_ref(), svc.as_deref(), documented);
        let Some(svc) = svc else {
            // Unmappable types can still be decided by the live registry.
            let verdict = match live_listed {
                Some(true) => Verdict::Available {
                    single_source: false,
                },
                Some(false) => Verdict::NotAvailable,
                None => Verdict::CannotAssess,
            };
            notes_out.extend(reason);
            if verdict == Verdict::NotAvailable {
                notes_out.push(NOT_AVAILABLE_NOTE.into());
            }
            out.push(Finding {
                logical_id: r.logical_id.clone(),
                cdk_path: r.cdk_path.clone(),
                resource_type: r.resource_type.clone(),
                service: None,
                verdict,
                evidence: live_listed.map(|l| Evidence {
                    botocore_listed: false,
                    regional_table_listed: None,
                    endpoints_page_listed: None,
                    user_guide_listed: None,
                    live_listed: Some(l),
                    live_check: kind,
                }),
                note: join(notes_out),
                divergence: false,
                depth,
            });
            continue;
        };
        let ev = Evidence {
            botocore_listed: data.botocore.target_services.contains(&svc),
            regional_table_listed: (!data.regional_table.target_services.is_empty())
                .then(|| data.regional_table.target_services.contains(&svc)),
            endpoints_page_listed: data
                .endpoints_page
                .as_ref()
                .map(|d| d.target_services.contains(&svc)),
            user_guide_listed: data.guide.as_ref().map(|_| documented),
            live_listed,
            live_check: kind,
        };
        let endpoint_listed = ev.botocore_listed || ev.endpoints_page_listed == Some(true);
        // Without any offering source for the target, endpoints decide alone.
        let offering_known = ev.regional_table_listed.is_some() || ev.user_guide_listed.is_some();
        let offered = if offering_known {
            ev.regional_table_listed == Some(true) || documented
        } else {
            endpoint_listed
        };
        let any_public = endpoint_listed || offered;
        let both_public = endpoint_listed && offered;
        let (verdict, divergence) = match (live_listed, &check) {
            (None, _) if contested => (Verdict::Disputed, false),
            (None, _) if !offering_known => (
                if endpoint_listed {
                    Verdict::Available {
                        single_source: true,
                    }
                } else {
                    Verdict::NotAvailable
                },
                false,
            ),
            (None, _) => (public_verdict(endpoint_listed, offered), false),
            // A registered type is necessary but not sufficient. If no public
            // source lists the service, it is not available, and the mismatch is reported.
            (Some(true), Some(LiveCheck::Registry(t))) if !any_public => {
                notes_out.push(format!(
                    "CloudFormation registers {t} in the target region, but no public source lists the service. Treated as not available; the registry entry alone does not prove the service is offered."
                ));
                (Verdict::NotAvailable, true)
            }
            (Some(true), _) => (
                Verdict::Available {
                    single_source: false,
                },
                !any_public,
            ),
            (Some(false), Some(LiveCheck::Registry(t))) => {
                // The service can be present while this one type is not. That is a
                // type-level gap, not stale public data, so it is no divergence.
                let ns = namespace(t);
                let ns_registered = live
                    .and_then(|l| l.registry.as_ref())
                    .is_some_and(|reg| reg.iter().any(|x| x.starts_with(ns)));
                if any_public && ns_registered {
                    notes_out.push(format!(
                        "The service is available in the target region, but the resource type {t} is not registered there. Use a supported type of the same service."
                    ));
                }
                (Verdict::NotAvailable, both_public && !ns_registered)
            }
            (Some(false), _) => (Verdict::NotAvailable, both_public),
        };
        if verdict == Verdict::NotAvailable && notes_out.is_empty() {
            notes_out.push(NOT_AVAILABLE_NOTE.into());
        }
        out.push(Finding {
            logical_id: r.logical_id.clone(),
            cdk_path: r.cdk_path.clone(),
            resource_type: r.resource_type.clone(),
            service: Some(svc),
            note: join(notes_out),
            verdict,
            evidence: Some(ev),
            divergence,
            depth,
        });
    }
    out
}

/// The live answer for one resource, any note explaining why there is none, and
/// whether the live answer contradicts the ESC User Guide.
fn live_result(
    live: Option<&Live>,
    check: Option<&LiveCheck>,
    svc: Option<&str>,
    documented: bool,
) -> (Option<bool>, Option<LiveCheckKind>, Vec<String>, bool) {
    let (Some(live), Some(check)) = (live, check) else {
        return (None, None, Vec::new(), false);
    };
    match check {
        LiveCheck::Registry(t) => (
            live.registry.as_ref().map(|reg| reg.contains(t)),
            Some(LiveCheckKind::TypeRegistry),
            Vec::new(),
            false,
        ),
        LiveCheck::ServiceApi => {
            let kind = Some(LiveCheckKind::ServiceApi);
            match svc.and_then(|s| live.services.get(s)) {
                Some(ServiceStatus::Offered) => (Some(true), kind, Vec::new(), false),
                Some(ServiceStatus::NotOffered) => (Some(false), kind, Vec::new(), false),
                // Access denied despite ReadOnlyAccess does not override a service the
                // guide documents: something else, such as an account setting, may deny it.
                Some(ServiceStatus::Refused) if documented => (
                    None,
                    kind,
                    vec!["The service answered access denied although the caller has ReadOnlyAccess, while the ESC User Guide documents it. Check account settings and policies that may deny the service.".into()],
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

/// `AWS::DynamoDB::GlobalTable` -> `AWS::DynamoDB::`.
fn namespace(resource_type: &str) -> &str {
    match resource_type.rfind("::") {
        Some(i) => &resource_type[..i + 2],
        None => resource_type,
    }
}

/// The public-tier reconciliation table. botocore and the ESC endpoints page are
/// endpoint sources, where a listing is evidence and silence is no claim. The regional
/// table and the ESC User Guide are offering sources.
fn public_verdict(endpoint: bool, offered: bool) -> Verdict {
    match (endpoint, offered) {
        (true, true) => Verdict::Available {
            single_source: false,
        },
        (false, false) => Verdict::NotAvailable,
        (true, false) => Verdict::Disputed,
        (false, true) => Verdict::Available {
            single_source: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{botocore, endpoints_page, guide, regional_table, terraform};
    use crate::reader;

    fn data() -> PublicData {
        PublicData {
            botocore: botocore::tests::fixture(),
            regional_table: regional_table::tests::fixture(),
            endpoints_page: Some(endpoints_page::tests::fixture()),
            guide: Some(guide::tests::fixture()),
            tf: Some(terraform::tests::fixture()),
        }
    }

    fn registry(types: &[&str]) -> Live {
        Live {
            registry: Some(types.iter().map(|s| s.to_string()).collect()),
            ..Live::default()
        }
    }

    fn one(resource_type: &str, live: Option<&Live>) -> Finding {
        let t = reader::parse(&format!(
            r#"{{"Resources":{{"R":{{"Type":"{resource_type}"}}}}}}"#
        ))
        .unwrap();
        assess(&t, &data(), live).pop().unwrap()
    }

    #[test]
    fn table_row_both_listed() {
        assert_eq!(
            one("AWS::Lambda::Function", None).verdict,
            Verdict::Available {
                single_source: false
            }
        );
    }

    #[test]
    fn table_row_both_silent_with_note() {
        let f = one("AWS::CloudFront::Distribution", None);
        assert_eq!(f.verdict, Verdict::NotAvailable);
        assert!(f.note.is_some());
    }

    #[test]
    fn without_offering_sources_endpoints_decide() {
        let mut d = data();
        d.regional_table.target_services.clear();
        d.endpoints_page = None;
        d.guide = None;
        let t = reader::parse(crate::test_inputs::SAMPLE_TEMPLATE).unwrap();
        for f in assess(&t, &d, None) {
            assert_ne!(f.verdict, Verdict::Disputed, "{}", f.logical_id);
            if let Some(ev) = &f.evidence {
                assert_eq!(ev.regional_table_listed, None);
            }
        }
    }

    #[test]
    fn table_row_both_silent_plain() {
        let f = one("AWS::CodeBuild::Project", None);
        assert_eq!(f.verdict, Verdict::NotAvailable);
        assert_eq!(f.note.as_deref(), Some(NOT_AVAILABLE_NOTE));
    }

    #[test]
    fn botocore_silent_endpoints_page_and_table_listed_is_two_sources() {
        // IAM: botocore has no aws-eusc entry; the endpoints page lists it.
        let f = one("AWS::IAM::Role", None);
        assert_eq!(
            f.verdict,
            Verdict::Available {
                single_source: false
            }
        );
        assert_eq!(f.evidence.unwrap().endpoints_page_listed, Some(true));
    }

    #[test]
    fn regional_table_only_is_single_source() {
        let mut d = data();
        d.endpoints_page = None;
        let t = reader::parse(r#"{"Resources":{"R":{"Type":"AWS::IAM::Role"}}}"#).unwrap();
        assert_eq!(
            assess(&t, &d, None).pop().unwrap().verdict,
            Verdict::Available {
                single_source: true
            }
        );
    }

    #[test]
    fn botocore_listed_table_not_is_disputed() {
        let d = data();
        let disputed: Vec<_> = d
            .botocore
            .target_services
            .difference(&d.regional_table.target_services)
            .collect();
        assert!(
            disputed.iter().any(|s| s.as_str() == "qbusiness"),
            "{disputed:?}"
        );
        assert_eq!(
            one("AWS::QBusiness::Application", None).verdict,
            Verdict::Disputed
        );
    }

    #[test]
    fn unmappable_is_cannot_assess_unless_live() {
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
            Verdict::Available {
                single_source: false
            }
        );
    }

    #[test]
    fn custom_resource_without_sdk_call_states_why() {
        let f = one("Custom::Registration", None);
        assert_eq!(f.verdict, Verdict::CannotAssess);
        assert!(f.note.unwrap().contains("own code"));
    }

    #[test]
    fn live_registry_decides_disputes() {
        assert_eq!(
            one("AWS::QBusiness::Application", Some(&registry(&[]))).verdict,
            Verdict::NotAvailable
        );
        let f = one(
            "AWS::QBusiness::Application",
            Some(&registry(&["AWS::QBusiness::Application"])),
        );
        assert_eq!(
            f.verdict,
            Verdict::Available {
                single_source: false
            }
        );
        assert!(!f.divergence);
    }

    #[test]
    fn live_disagreeing_with_both_sources_is_a_divergence() {
        let f = one("AWS::Lambda::Function", Some(&registry(&[])));
        assert_eq!(f.verdict, Verdict::NotAvailable);
        assert!(f.divergence);
    }

    #[test]
    fn registry_only_type_is_not_available() {
        // A registered type that no public source lists, as seen for IoT in ESC.
        let f = one(
            "AWS::CodeBuild::Project",
            Some(&registry(&["AWS::CodeBuild::Project"])),
        );
        assert_eq!(f.verdict, Verdict::NotAvailable);
        assert!(f.divergence);
        assert!(f.note.unwrap().contains("registers"));
    }

    #[test]
    fn a_guide_page_counts_as_offering_source() {
        // CodePipeline: no endpoint source lists it, but the ESC User Guide has a page.
        let f = one("AWS::CodePipeline::Pipeline", None);
        assert_eq!(
            f.verdict,
            Verdict::Available {
                single_source: true
            }
        );
        assert_eq!(f.evidence.unwrap().user_guide_listed, Some(true));
        let f = one(
            "AWS::CodePipeline::Pipeline",
            Some(&registry(&["AWS::CodePipeline::Pipeline"])),
        );
        assert_eq!(
            f.verdict,
            Verdict::Available {
                single_source: false
            }
        );
        assert!(!f.divergence);
    }

    #[test]
    fn refusal_does_not_override_a_documented_service() {
        let status = |s: ServiceStatus| Live {
            services: [
                ("codepipeline".to_string(), s.clone()),
                ("codebuild".to_string(), s),
            ]
            .into_iter()
            .collect(),
            ..Live::default()
        };
        let t = |ty: &str| {
            format!(
                r#"{{"format_version":"1.2","planned_values":{{"root_module":{{"resources":[{{"address":"{ty}.p","mode":"managed","type":"{ty}","provider_name":"registry.terraform.io/hashicorp/aws","values":{{}}}}]}}}}}}"#
            )
        };
        let assess_one = |ty: &str, l: &Live| {
            assess(&reader::parse(&t(ty)).unwrap(), &data(), Some(l))
                .pop()
                .unwrap()
        };
        let f = assess_one("aws_codepipeline", &status(ServiceStatus::Refused));
        assert_eq!(f.verdict, Verdict::Disputed);
        assert!(f.note.unwrap().contains("ReadOnlyAccess"));
        // Without a guide page, a refusal under ReadOnlyAccess is still "not available".
        let f = assess_one("aws_codebuild_project", &status(ServiceStatus::Refused));
        assert_eq!(f.verdict, Verdict::NotAvailable);
    }

    #[test]
    fn type_level_gap_is_not_a_divergence() {
        // As for AWS::DynamoDB::GlobalTable in ESC.
        let f = one(
            "AWS::DynamoDB::GlobalTable",
            Some(&registry(&["AWS::DynamoDB::Table"])),
        );
        assert_eq!(f.verdict, Verdict::NotAvailable);
        assert!(!f.divergence);
        assert!(f.note.unwrap().contains("resource type"));
    }

    #[test]
    fn service_api_decides_terraform_resources() {
        let t = reader::parse(include_str!("../tests/fixtures/tf-plan.json")).unwrap();
        let live = Live {
            services: [
                ("codebuild", ServiceStatus::NotOffered),
                ("dynamodb", ServiceStatus::Offered),
                ("ec2", ServiceStatus::Unverified("AccessDenied".into())),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
            ..Live::default()
        };
        let f: BTreeMap<_, _> = assess(&t, &data(), Some(&live))
            .into_iter()
            .map(|f| (f.logical_id.clone(), f))
            .collect();
        assert_eq!(
            f["aws_codebuild_project.this"].verdict,
            Verdict::NotAvailable
        );
        assert!(!f["aws_codebuild_project.this"].divergence);
        let ddb = &f["aws_dynamodb_table.this"];
        assert_eq!(
            ddb.evidence.as_ref().unwrap().live_check,
            Some(LiveCheckKind::ServiceApi)
        );
        assert!(matches!(ddb.verdict, Verdict::Available { .. }));
        // Unverified falls back to the public verdict and says so.
        let vpc = &f["module.net.aws_vpc.this"];
        assert!(matches!(vpc.verdict, Verdict::Available { .. }));
        assert!(vpc.note.as_ref().unwrap().contains("unverified"));
    }

    #[test]
    fn pseudo_resources_produce_no_finding() {
        let t = reader::parse(r#"{"Resources":{"M":{"Type":"AWS::CDK::Metadata"}}}"#).unwrap();
        assert!(assess(&t, &data(), None).is_empty());
    }
}
