//! The parsed input model shared by all stages. Only the readers know the input format.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceFormat {
    #[default]
    Cloudformation,
    TerraformPlan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Cfn,
    /// A resource of the hashicorp/aws provider.
    TfAws,
    /// A resource of the hashicorp/awscc provider (Cloud Control, one CFN type each).
    TfAwscc,
}

/// Where the input was synthesized (CDK) or planned (Terraform). Values written for
/// this environment are not hardcoded by hand; they change when the input is
/// produced for the target instead.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DeployEnv {
    pub region: Option<String>,
    pub account: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Resource {
    /// CFN logical id, or the Terraform resource address.
    pub logical_id: String,
    pub resource_type: String,
    /// CFN `Properties` or Terraform planned values; `Value::Null` when absent.
    pub properties: Value,
    pub origin: Origin,
    pub env: Option<DeployEnv>,
    /// The construct path CDK writes into `Metadata`, so the source can be found.
    pub cdk_path: Option<String>,
}

/// A Terraform resource of a provider other than aws or awscc.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct OutOfScope {
    pub address: String,
    pub resource_type: String,
    pub provider: String,
}

/// `resource_type` of a CloudFormation output in [`Template::outputs`].
pub const OUTPUT_TYPE: &str = "Output";

/// Keyed by logical id; `BTreeMap` keeps iteration order deterministic.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Template {
    pub resources: BTreeMap<String, Resource>,
    /// CloudFormation outputs, keyed `Outputs/<name>`, with the value as `properties`.
    pub outputs: BTreeMap<String, Resource>,
    pub format: SourceFormat,
    pub out_of_scope: Vec<OutOfScope>,
    /// Terraform only: every string written as a constant in the configuration. A
    /// literal found here was typed by hand, even when the plan's environment matches.
    pub constants: std::collections::BTreeSet<String>,
}

impl Template {
    /// The distinct environments the input was produced for.
    pub fn envs(&self) -> Vec<DeployEnv> {
        let set: std::collections::BTreeSet<_> = self
            .resources
            .values()
            .filter_map(|r| r.env.clone())
            .collect();
        set.into_iter().collect()
    }
}
