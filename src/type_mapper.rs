//! Maps resources to what the availability data is keyed by: a CloudFormation type, or an
//! SDK service and operation. Also names the SDK endpoint prefix, which keys the ESC User
//! Guide pages.

use std::collections::BTreeMap;

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

/// What decides whether a resource is available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// A CloudFormation resource type.
    Type(String),
    /// An SDK service (botocore `serviceId`), and the operation when the input names one.
    Api {
        service_id: String,
        operation: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mapping {
    Resource {
        /// SDK endpoint prefix, when known.
        service: Option<String>,
        check: Check,
    },
    /// A CloudFormation or CDK construct that is not an AWS service resource.
    Pseudo,
    /// Nothing to check. Reported as cannot-assess, never guessed.
    Unknown { reason: String },
}

pub struct TypeMapper<'a> {
    overrides: Overrides,
    tf: Option<&'a TfMaps>,
}

impl<'a> TypeMapper<'a> {
    pub fn new(tf: Option<&'a TfMaps>) -> Self {
        let overrides: Overrides =
            serde_json::from_str(OVERRIDES_JSON).expect("built-in override table is valid JSON");
        Self { overrides, tf }
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
                    |s| api(s, None),
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
        let parts: Vec<&str> = t.split("::").collect();
        let ns = match parts.as_slice() {
            ["AWS", ns, _] => *ns,
            // An activated or private extension is per account; no public data knows it.
            _ => {
                return unknown(
                    "Not an AWS resource type (a third-party or private registry extension). Check that it is activated in the target account.",
                );
            }
        };
        let token = self.overrides.types.get(t).cloned().unwrap_or_else(|| {
            self.overrides
                .namespaces
                .get(ns)
                .cloned()
                .unwrap_or_else(|| ns.to_ascii_lowercase())
        });
        Mapping::Resource {
            service: services::index()
                .by_endpoint_prefix(&token)
                .is_some()
                .then_some(token),
            check: Check::Type(t.to_string()),
        }
    }
}

fn unknown(reason: &str) -> Mapping {
    Mapping::Unknown {
        reason: reason.into(),
    }
}

fn api(s: &services::Service, operation: Option<String>) -> Mapping {
    Mapping::Resource {
        service: Some(s.endpoint_prefix.clone()),
        check: Check::Api {
            service_id: s.service_id.clone(),
            operation,
        },
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
    if let Some((_, prefix)) = CDK_HELPERS.iter().find(|(name, _)| t.starts_with(name)) {
        let s = services::index()
            .by_endpoint_prefix(prefix)
            .expect("CDK helper service is in the bundled table");
        return api(s, None);
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
        Some(s) => api(s, json_string_field(&call, "action").map(|a| operation(&a))),
        None => unknown(&format!(
            "Custom resource calls unknown SDK service {name:?}"
        )),
    }
}

/// `describeUserPoolClient` (JS SDK v2) and `GetObjectCommand` (v3) -> the API name.
fn operation(s: &str) -> String {
    let s = s.strip_suffix("Command").unwrap_or(s);
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
        .unwrap_or_default()
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

    fn cfn(t: &str, props: Value) -> Mapping {
        TypeMapper::new(None).map(&Resource {
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
            Mapping::Resource { service, .. } => service,
            _ => None,
        }
    }

    #[test]
    fn direct_namespace() {
        assert_eq!(
            cfn("AWS::IAM::Role", Value::Null),
            Mapping::Resource {
                service: Some("iam".into()),
                check: Check::Type("AWS::IAM::Role".into())
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
            ("AWS::Cognito::IdentityPool", "cognito-identity"),
            ("AWS::Cognito::UserPool", "cognito-idp"),
        ] {
            assert_eq!(service(cfn(t, Value::Null)).as_deref(), Some(s), "{t}");
        }
    }

    #[test]
    fn every_override_target_is_a_known_sdk_prefix() {
        let idx = services::index();
        let o: Overrides = serde_json::from_str(OVERRIDES_JSON).unwrap();
        for (k, v) in o.namespaces.iter().chain(o.types.iter()) {
            assert!(
                idx.by_endpoint_prefix(v).is_some(),
                "override {k} -> {v} is not an SDK endpoint prefix"
            );
        }
    }

    #[test]
    fn pseudo_and_unassessable_types() {
        for t in ["AWS::CDK::Metadata", "AWS::CloudFormation::WaitCondition"] {
            assert_eq!(cfn(t, Value::Null), Mapping::Pseudo, "{t}");
        }
        for t in [
            "AWS::Serverless::Function",
            "AWS::CloudFormation::Stack",
            "Vendor::Product::Thing",
        ] {
            assert!(
                matches!(cfn(t, Value::Null), Mapping::Unknown { .. }),
                "{t} is not silently skipped"
            );
        }
        // An AWS type of an unknown service is still checked by its type.
        assert_eq!(
            cfn("AWS::NotAService::Thing", Value::Null),
            Mapping::Resource {
                service: None,
                check: Check::Type("AWS::NotAService::Thing".into())
            }
        );
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
        for (_, svc) in CDK_HELPERS {
            assert!(services::index().by_endpoint_prefix(svc).is_some(), "{svc}");
        }
    }

    #[test]
    fn custom_resources_name_their_call() {
        let t = crate::reader::parse_text(crate::test_inputs::CUSTOM_RESOURCES_TEMPLATE).unwrap();
        let m = TypeMapper::new(None);
        let got: BTreeMap<_, _> = t
            .resources
            .values()
            .map(|r| (r.logical_id.as_str(), m.map(r)))
            .collect();
        assert_eq!(
            got["DescribeClient"],
            Mapping::Resource {
                service: Some("cognito-idp".into()),
                check: Check::Api {
                    service_id: "Cognito Identity Provider".into(),
                    operation: Some("DescribeUserPoolClient".into())
                }
            }
        );
        assert_eq!(
            service(got["CreateInvalidation"].clone()).as_deref(),
            Some("cloudfront")
        );
        assert!(
            matches!(&got["PortalRegistration"], Mapping::Unknown { reason } if reason.contains("own code"))
        );
    }

    #[test]
    fn sdk_actions_name_the_api_operation() {
        for a in ["getObject", "GetObject", "GetObjectCommand"] {
            assert_eq!(operation(a), "GetObject", "{a}");
        }
    }

    #[test]
    fn terraform_types() {
        let tf = terraform::tests::fixture();
        let m = TypeMapper::new(Some(&tf));
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
            Mapping::Resource {
                service: Some("elasticloadbalancing".into()),
                check: Check::Api {
                    service_id: "Elastic Load Balancing v2".into(),
                    operation: None
                }
            }
        );
        assert_eq!(
            m.map(&r("awscc_s3_bucket", Origin::TfAwscc)),
            Mapping::Resource {
                service: Some("s3".into()),
                check: Check::Type("AWS::S3::Bucket".into())
            }
        );
        assert!(matches!(
            m.map(&r("aws_not_a_service", Origin::TfAws)),
            Mapping::Unknown { .. }
        ));
        let plan =
            crate::reader::parse_text(include_str!("../tests/fixtures/tf-plan.json")).unwrap();
        for res in plan.resources.values() {
            assert!(
                matches!(m.map(res), Mapping::Resource { .. }),
                "{} did not map",
                res.resource_type
            );
        }
    }
}
