//! Maps resources to SDK endpoint prefixes (service tokens) and picks their live check.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;

use crate::model::{Origin, Resource};
use crate::provider::terraform::TfMaps;
use crate::services;

/// Built-in override table, generated from botocore service metadata.
const OVERRIDES_JSON: &str = include_str!("../data/cfn-service-overrides.json");

#[derive(Debug, Deserialize)]
struct Overrides {
    namespaces: BTreeMap<String, String>,
    types: BTreeMap<String, String>,
}

/// How live mode checks a resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveCheck {
    /// The CloudFormation type registry lists this type.
    Registry(String),
    /// The service answers its probe call.
    ServiceApi,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mapping {
    Service {
        service: String,
        live: LiveCheck,
    },
    /// A CloudFormation or CDK construct that is not an AWS service resource.
    Pseudo,
    /// No known service. Reported as cannot-assess, never guessed.
    Unknown {
        live: Option<LiveCheck>,
        reason: Option<String>,
    },
}

pub struct TypeMapper<'a> {
    overrides: Overrides,
    known: BTreeSet<String>,
    tf: Option<&'a TfMaps>,
}

impl<'a> TypeMapper<'a> {
    /// `known_services` is the set of endpoint prefixes the pulled SDK data knows about,
    /// across all partitions.
    pub fn new(known_services: impl IntoIterator<Item = String>, tf: Option<&'a TfMaps>) -> Self {
        let overrides: Overrides =
            serde_json::from_str(OVERRIDES_JSON).expect("built-in override table is valid JSON");
        let mut known: BTreeSet<String> = known_services.into_iter().collect();
        // Override targets come from SDK service metadata, so they are known even when
        // the service has no entry in endpoints.json (rule-set-only services).
        known.extend(overrides.namespaces.values().cloned());
        known.extend(overrides.types.values().cloned());
        Self {
            overrides,
            known,
            tf,
        }
    }

    pub fn map(&self, r: &Resource) -> Mapping {
        match r.origin {
            Origin::Cfn => self.map_cfn(&r.resource_type, &r.properties),
            Origin::TfAwscc => match self.tf.and_then(|m| m.awscc_cfn_type(&r.resource_type)) {
                Some(cfn) => self.map_cfn_type(cfn),
                None => unknown("Not in the awscc provider's schema list"),
            },
            Origin::TfAws => self
                .tf
                .and_then(|m| m.aws_service_id(&r.resource_type))
                .and_then(|id| services::index().by_service_id(id))
                .map_or_else(
                    || unknown("No service in the aws provider's service data"),
                    |s| Mapping::Service {
                        service: s.endpoint_prefix.clone(),
                        live: LiveCheck::ServiceApi,
                    },
                ),
        }
    }

    fn map_cfn(&self, t: &str, props: &Value) -> Mapping {
        if t.starts_with("Custom::") || t == "AWS::CloudFormation::CustomResource" {
            return custom_resource(t, props);
        }
        self.map_cfn_type(t)
    }

    fn map_cfn_type(&self, t: &str) -> Mapping {
        if t == "AWS::CloudFormation::Stack" {
            return unknown(
                "Nested stack; its resources are in a separate template. Scan that template too, or the whole cdk.out directory.",
            );
        }
        if t.starts_with("AWS::Serverless::") {
            return unknown(
                "AWS SAM resource; only deployable CloudFormation is assessed. Scan the processed template (`aws cloudformation get-template --template-stage Processed`).",
            );
        }
        if is_pseudo(t) {
            return Mapping::Pseudo;
        }
        let registry = LiveCheck::Registry(t.to_string());
        if let Some(s) = self.overrides.types.get(t) {
            return Mapping::Service {
                service: s.clone(),
                live: registry,
            };
        }
        let mut parts = t.split("::");
        let token = match (parts.next(), parts.next(), parts.next()) {
            (Some("AWS"), Some(ns), Some(_)) => self
                .overrides
                .namespaces
                .get(ns)
                .cloned()
                .unwrap_or_else(|| ns.to_ascii_lowercase()),
            _ => String::new(),
        };
        if self.known.contains(&token) {
            Mapping::Service {
                service: token,
                live: registry,
            }
        } else if t.starts_with("AWS::") {
            Mapping::Unknown {
                live: Some(registry),
                reason: Some("No public source knows the service of this type; it may be retired or newer than the data. Live mode checks the type in the target registry.".into()),
            }
        } else {
            // The registry check lists AWS types only; an activated or private
            // extension is per account, so absence there would prove nothing.
            unknown(
                "Not an AWS resource type (a third-party or private registry extension). Check that it is activated in the target account.",
            )
        }
    }
}

fn unknown(reason: &str) -> Mapping {
    Mapping::Unknown {
        live: None,
        reason: Some(reason.into()),
    }
}

/// Custom resources that aws-cdk-lib itself defines, with the service their fixed
/// provider code calls.
const CDK_HELPERS: [(&str, &str); 6] = [
    ("Custom::S3AutoDeleteObjects", "s3"),
    ("Custom::ECRAutoDeleteImages", "api.ecr"),
    ("Custom::VpcRestrictDefaultSG", "ec2"),
    ("Custom::LogRetention", "logs"),
    ("Custom::CDKBucketDeployment", "s3"),
    ("Custom::AWSCDKOpenIdConnectProvider", "iam"),
];

/// A CDK `AwsCustomResource` names its SDK call in `Create`/`Update`/`Delete`, as a
/// JSON string or an `Fn::Join` around tokens. CDK's own helpers call a fixed service.
/// Any other custom resource runs its own code, which the template does not show.
fn custom_resource(t: &str, props: &Value) -> Mapping {
    // `CDKBucketDeployment` carries a hash suffix.
    if let Some((_, svc)) = CDK_HELPERS.iter().find(|(name, _)| t.starts_with(name)) {
        return Mapping::Service {
            service: (*svc).into(),
            live: LiveCheck::ServiceApi,
        };
    }
    let Some(call) = ["Create", "Update", "Delete"]
        .iter()
        .find_map(|k| props.get(*k).map(literal_text))
    else {
        return unknown(
            "Custom resource backed by its own code; the calls it makes cannot be read from the template. Its backing function is assessed separately.",
        );
    };
    let Some(name) = json_string_field(&call, "service") else {
        return unknown("Custom resource call names no service");
    };
    match services::index().by_sdk_name(&name) {
        Some(s) => Mapping::Service {
            service: s.endpoint_prefix.clone(),
            live: LiveCheck::ServiceApi,
        },
        None => unknown(&format!(
            "Custom resource calls unknown SDK service {name:?}"
        )),
    }
}

/// The literal text of a string or of an `Fn::Join` over strings, tokens dropped.
fn literal_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Object(m) => match m.get("Fn::Join").and_then(|j| j.get(1)) {
            Some(Value::Array(parts)) => parts.iter().filter_map(Value::as_str).collect(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

/// `"key":"value"` inside JSON text that may be incomplete because tokens were dropped.
fn json_string_field(text: &str, key: &str) -> Option<String> {
    let start = text.find(&format!("\"{key}\":\""))? + key.len() + 4;
    let len = text[start..].find('"')?;
    Some(text[start..start + len].to_string())
}

fn is_pseudo(t: &str) -> bool {
    t == "AWS::CDK::Metadata" || t.starts_with("AWS::CloudFormation::")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::terraform;

    fn known() -> Vec<String> {
        serde_json::from_str(include_str!("../tests/fixtures/sdk-endpoint-prefixes.json")).unwrap()
    }

    fn cfn(t: &str, props: Value) -> Mapping {
        TypeMapper::new(known(), None).map(&Resource {
            logical_id: "R".into(),
            resource_type: t.into(),
            properties: props,
            origin: Origin::Cfn,
            env: None,
            cdk_path: None,
        })
    }

    fn service(m: Mapping) -> Option<String> {
        match m {
            Mapping::Service { service, .. } => Some(service),
            _ => None,
        }
    }

    #[test]
    fn direct_namespace() {
        assert_eq!(
            service(cfn("AWS::S3::Bucket", Value::Null)).as_deref(),
            Some("s3")
        );
        assert_eq!(
            cfn("AWS::IAM::Role", Value::Null),
            Mapping::Service {
                service: "iam".into(),
                live: LiveCheck::Registry("AWS::IAM::Role".into())
            }
        );
    }

    #[test]
    fn namespace_overrides() {
        for (t, s) in [
            (
                "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "elasticloadbalancing",
            ),
            ("AWS::CloudWatch::Alarm", "monitoring"),
            ("AWS::StepFunctions::StateMachine", "states"),
            ("AWS::ECR::Repository", "api.ecr"),
            ("AWS::SageMaker::Model", "api.sagemaker"),
            ("AWS::OpenSearchService::Domain", "es"),
            ("AWS::EFS::FileSystem", "elasticfilesystem"),
            ("AWS::ImageBuilder::Image", "imagebuilder"),
        ] {
            assert_eq!(service(cfn(t, Value::Null)).as_deref(), Some(s), "{t}");
        }
    }

    #[test]
    fn full_type_override_beats_namespace() {
        assert_eq!(
            service(cfn("AWS::Cognito::IdentityPool", Value::Null)).as_deref(),
            Some("cognito-identity")
        );
        assert_eq!(
            service(cfn("AWS::Cognito::UserPool", Value::Null)).as_deref(),
            Some("cognito-idp")
        );
    }

    #[test]
    fn every_override_target_is_a_known_sdk_prefix() {
        let known: BTreeSet<String> = known().into_iter().collect();
        let o: Overrides = serde_json::from_str(OVERRIDES_JSON).unwrap();
        for (k, v) in o.namespaces.iter().chain(o.types.iter()) {
            assert!(
                known.contains(v),
                "override {k} -> {v} is not an SDK endpoint prefix"
            );
        }
    }

    #[test]
    fn pseudo_resources_are_filtered() {
        for t in ["AWS::CDK::Metadata", "AWS::CloudFormation::WaitCondition"] {
            assert_eq!(cfn(t, Value::Null), Mapping::Pseudo, "{t}");
        }
        for t in ["AWS::Serverless::Function", "AWS::CloudFormation::Stack"] {
            assert!(
                matches!(cfn(t, Value::Null), Mapping::Unknown { live: None, .. }),
                "{t} is not silently skipped"
            );
        }
    }

    #[test]
    fn unknown_types_are_cannot_assess() {
        assert!(matches!(
            cfn("AWS::NotAService::Thing", Value::Null),
            Mapping::Unknown { live: Some(_), .. }
        ));
        assert!(matches!(
            cfn("Vendor::Product::Thing", Value::Null),
            Mapping::Unknown { live: None, .. }
        ));
    }

    #[test]
    fn cdk_helpers_map_to_their_fixed_service() {
        for (t, svc) in [
            ("Custom::S3AutoDeleteObjects", "s3"),
            ("Custom::CDKBucketDeploymentA1B2C3", "s3"),
            ("Custom::VpcRestrictDefaultSG", "ec2"),
        ] {
            assert_eq!(service(cfn(t, Value::Null)).as_deref(), Some(svc), "{t}");
        }
    }

    #[test]
    fn every_cdk_helper_service_is_known() {
        let idx = services::index();
        for (_, svc) in CDK_HELPERS {
            assert!(idx.by_endpoint_prefix(svc).is_some(), "{svc}");
        }
    }

    #[test]
    fn custom_resources() {
        let t = crate::reader::parse(crate::test_inputs::CUSTOM_RESOURCES_TEMPLATE).unwrap();
        let m = TypeMapper::new(known(), None);
        let got: BTreeMap<_, _> = t
            .resources
            .values()
            .map(|r| (r.logical_id.as_str(), m.map(r)))
            .collect();
        assert_eq!(
            service(got["DescribeClient"].clone()).as_deref(),
            Some("cognito-idp")
        );
        assert_eq!(
            service(got["CreateInvalidation"].clone()).as_deref(),
            Some("cloudfront")
        );
        assert!(
            matches!(&got["PortalRegistration"], Mapping::Unknown { reason: Some(r), .. } if r.contains("own code"))
        );
    }

    #[test]
    fn terraform_types() {
        let tf = terraform::tests::fixture();
        let m = TypeMapper::new(known(), Some(&tf));
        let r = |t: &str, origin| Resource {
            logical_id: "r".into(),
            resource_type: t.into(),
            properties: Value::Null,
            origin,
            env: None,
            cdk_path: None,
        };
        assert_eq!(
            m.map(&r("aws_lb", Origin::TfAws)),
            Mapping::Service {
                service: "elasticloadbalancing".into(),
                live: LiveCheck::ServiceApi
            }
        );
        assert_eq!(
            service(m.map(&r("aws_cloudwatch_log_group", Origin::TfAws))).as_deref(),
            Some("logs")
        );
        assert_eq!(
            m.map(&r("awscc_s3_bucket", Origin::TfAwscc)),
            Mapping::Service {
                service: "s3".into(),
                live: LiveCheck::Registry("AWS::S3::Bucket".into())
            }
        );
        assert!(matches!(
            m.map(&r("aws_not_a_service", Origin::TfAws)),
            Mapping::Unknown {
                live: None,
                reason: Some(_)
            }
        ));
        let plan = crate::reader::parse(include_str!("../tests/fixtures/tf-plan.json")).unwrap();
        for res in plan.resources.values() {
            assert!(
                matches!(m.map(res), Mapping::Service { .. }),
                "{} did not map",
                res.resource_type
            );
        }
    }
}
