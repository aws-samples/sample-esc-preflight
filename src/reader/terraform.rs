//! Terraform plan JSON (`terraform show -json <plan>`), format version 1.x.
//!
//! Planned values already have modules, `count` and `for_each` resolved. Values known
//! only after apply are absent, so they can never produce a hazard.

use serde_json::Value;

use crate::error::{Result, ScanError};
use crate::model::{DeployEnv, OUTPUT_TYPE, Origin, OutOfScope, Resource, SourceFormat, Template};

pub fn is_plan(doc: &Value) -> bool {
    doc.get("format_version").is_some() && doc.get("planned_values").is_some()
}

pub fn from_value(doc: &Value) -> Result<Template> {
    let version = doc["format_version"].as_str().unwrap_or_default();
    if version.split('.').next() != Some("1") {
        return Err(ScanError::Input(format!(
            "unsupported Terraform plan format_version {version:?}"
        )));
    }
    let mut t = Template {
        format: SourceFormat::TerraformPlan,
        ..Template::default()
    };
    let env = DeployEnv {
        region: plan_region(doc).or_else(|| main_region(doc)),
        account: doc
            .pointer("/prior_state/values/root_module")
            .and_then(caller_account),
    };
    if let Some(root) = doc.pointer("/planned_values/root_module") {
        walk(root, &env, &mut t);
    }
    // Root outputs are read by other configurations (`terraform_remote_state`) and
    // scripts. Sensitive outputs are skipped so their values never reach the report.
    for (name, o) in doc
        .pointer("/planned_values/outputs")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(_, o)| o["sensitive"] != true)
    {
        let id = format!("Outputs/{name}");
        t.outputs.insert(
            id.clone(),
            Resource {
                logical_id: id,
                resource_type: OUTPUT_TYPE.into(),
                properties: o.get("value").cloned().unwrap_or(Value::Null),
                origin: Origin::TfAws,
                env: (env != DeployEnv::default()).then(|| env.clone()),
                cdk_path: None,
            },
        );
    }
    constants(&doc["configuration"], false, &mut t.constants);
    t.out_of_scope.sort();
    Ok(t)
}

/// The aws provider writes its region into every resource, which also covers aliased
/// providers and regions set from expressions the plan does not evaluate.
fn walk(module: &Value, base: &DeployEnv, t: &mut Template) {
    for r in module["resources"].as_array().into_iter().flatten() {
        if r["mode"] != "managed" {
            continue;
        }
        let address = r["address"].as_str().unwrap_or_default().to_string();
        let resource_type = r["type"].as_str().unwrap_or_default().to_string();
        let provider = r["provider_name"].as_str().unwrap_or_default();
        let origin = match provider.strip_prefix("registry.terraform.io/") {
            Some("hashicorp/aws") => Origin::TfAws,
            Some("hashicorp/awscc") => Origin::TfAwscc,
            _ => {
                t.out_of_scope.push(OutOfScope {
                    address,
                    resource_type,
                    provider: provider.to_string(),
                });
                continue;
            }
        };
        let env = DeployEnv {
            region: r["values"]["region"]
                .as_str()
                .map(str::to_string)
                .or_else(|| base.region.clone()),
            account: base.account.clone(),
        };
        t.resources.insert(
            address.clone(),
            Resource {
                logical_id: address,
                resource_type,
                properties: redact(&r["values"], &r["sensitive_values"]),
                origin,
                env: (env != DeployEnv::default()).then_some(env),
                cdk_path: None,
            },
        );
    }
    for child in module["child_modules"].as_array().into_iter().flatten() {
        walk(child, base, t);
    }
}

/// `values` with every attribute that `sensitive_values` marks `true` replaced by
/// null, so secrets are never scanned and never reach the report. The mask mirrors
/// the shape of `values`.
fn redact(values: &Value, mask: &Value) -> Value {
    match (values, mask) {
        (_, Value::Bool(true)) => Value::Null,
        (Value::Object(v), Value::Object(m)) => Value::Object(
            v.iter()
                .map(|(k, x)| {
                    (
                        k.clone(),
                        m.get(k).map_or_else(|| x.clone(), |mk| redact(x, mk)),
                    )
                })
                .collect(),
        ),
        (Value::Array(v), Value::Array(m)) => Value::Array(
            v.iter()
                .enumerate()
                .map(|(i, x)| m.get(i).map_or_else(|| x.clone(), |mk| redact(x, mk)))
                .collect(),
        ),
        _ => values.clone(),
    }
}

fn constants(v: &Value, inside: bool, out: &mut std::collections::BTreeSet<String>) {
    match v {
        Value::String(s) if inside => {
            out.insert(s.clone());
        }
        Value::Array(a) => a.iter().for_each(|x| constants(x, inside, out)),
        Value::Object(m) => {
            for (k, x) in m {
                constants(x, inside || k == "constant_value", out);
            }
        }
        _ => {}
    }
}

/// The most common resource region, for resources of global services, which carry none.
fn main_region(doc: &Value) -> Option<String> {
    fn count<'a>(m: &'a Value, out: &mut std::collections::BTreeMap<&'a str, usize>) {
        for r in m["resources"].as_array().into_iter().flatten() {
            if let Some(region) = r["values"]["region"].as_str() {
                *out.entry(region).or_default() += 1;
            }
        }
        for c in m["child_modules"].as_array().into_iter().flatten() {
            count(c, out);
        }
    }
    let mut regions = std::collections::BTreeMap::new();
    count(doc.pointer("/planned_values/root_module")?, &mut regions);
    // Ties go to the first region by name, so the result is deterministic.
    let max = *regions.values().max()?;
    regions
        .into_iter()
        .find(|(_, n)| *n == max)
        .map(|(r, _)| r.to_string())
}

/// The planning account, from an `aws_caller_identity` data source if the plan read one.
fn caller_account(module: &Value) -> Option<String> {
    let own = module["resources"]
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|r| {
            (r["type"] == "aws_caller_identity")
                .then(|| r["values"]["account_id"].as_str().map(str::to_string))
                .flatten()
        });
    own.or_else(|| {
        module["child_modules"]
            .as_array()
            .into_iter()
            .flatten()
            .find_map(caller_account)
    })
}

/// The default aws provider's region, as a constant or a root variable reference.
fn plan_region(doc: &Value) -> Option<String> {
    let expr = doc.pointer("/configuration/provider_config/aws/expressions/region")?;
    if let Some(c) = expr["constant_value"].as_str() {
        return Some(c.to_string());
    }
    let var = expr["references"][0].as_str()?.strip_prefix("var.")?;
    doc["variables"][var]["value"].as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Template {
        crate::reader::parse_text(include_str!("../../tests/fixtures/tf-plan.json")).unwrap()
    }

    #[test]
    fn reads_managed_resources_across_modules() {
        let t = fixture();
        assert_eq!(t.format, SourceFormat::TerraformPlan);
        let env = t.resources["aws_lb.this"].env.clone().unwrap();
        assert_eq!(env.region.as_deref(), Some("eusc-de-east-1"));
        assert_eq!(t.resources.len(), 15);
        assert!(t.resources.contains_key("module.net.aws_subnet.private[2]"));
        assert!(!t.resources.keys().any(|k| k.contains(".data.")));
        assert_eq!(t.resources["aws_lb.this"].origin, Origin::TfAws);
    }

    #[test]
    fn other_providers_are_out_of_scope() {
        let t = fixture();
        assert_eq!(t.out_of_scope.len(), 1);
        assert_eq!(t.out_of_scope[0].resource_type, "random_id");
    }

    #[test]
    fn reads_root_outputs_but_not_sensitive_ones() {
        let doc = json!({
            "format_version": "1.2",
            "planned_values": {"outputs": {
                "role_arn": {"sensitive": false, "value": "arn:aws:iam::444455556666:role/app"},
                "token": {"sensitive": true, "value": "arn:aws:secret"},
                "later": {"sensitive": false}
            }}
        });
        let t = from_value(&doc).unwrap();
        assert_eq!(
            t.outputs.keys().collect::<Vec<_>>(),
            ["Outputs/later", "Outputs/role_arn"]
        );
        assert_eq!(t.outputs["Outputs/later"].properties, Value::Null);
        assert!(t.resources.is_empty(), "outputs are not resources");
    }

    #[test]
    fn sensitive_attributes_are_not_scanned() {
        let doc = json!({
            "format_version": "1.2",
            "planned_values": {"root_module": {"resources": [{
                "address": "aws_db_instance.db", "mode": "managed", "type": "aws_db_instance",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "values": {"password": "x:123456789012:y", "tags": {"k": "v", "s": "a:210987654321:b"},
                           "arn": "arn:aws:rds:eu-central-1:111122223333:db:x"},
                "sensitive_values": {"password": true, "tags": {"s": true}}
            }]}}
        });
        let r = &from_value(&doc).unwrap().resources["aws_db_instance.db"];
        assert_eq!(r.properties["password"], Value::Null);
        assert_eq!(r.properties["tags"], json!({"k": "v", "s": null}));
        assert!(r.properties["arn"].is_string(), "non-sensitive values stay");
    }

    #[test]
    fn unknown_after_apply_values_are_absent() {
        let lb = &fixture().resources["aws_lb.this"].properties;
        assert!(lb.get("arn").is_none());
        assert_eq!(lb["load_balancer_type"], "application");
    }

    #[test]
    fn region_from_variable_reference() {
        let doc = json!({
            "format_version": "1.2",
            "planned_values": {},
            "variables": {"region": {"value": "eusc-de-east-1"}},
            "configuration": {"provider_config": {"aws": {"expressions": {
                "region": {"references": ["var.region"]}}}}}
        });
        assert_eq!(plan_region(&doc).as_deref(), Some("eusc-de-east-1"));
    }

    #[test]
    fn each_resource_keeps_its_own_region() {
        let r = |a: &str, region: &str| {
            json!({"address": a, "mode": "managed", "type": "aws_s3_bucket",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "values": {"region": region}})
        };
        let doc = json!({"format_version": "1.2", "planned_values": {"root_module": {
            "resources": [r("a", "eu-west-1"), r("b", "eu-central-1"), r("c", "eu-west-1"),
                json!({"address": "g", "mode": "managed", "type": "aws_iam_role",
                    "provider_name": "registry.terraform.io/hashicorp/aws", "values": {}})]}}});
        let t = from_value(&doc).unwrap();
        let region = |a: &str| t.resources[a].env.clone().unwrap().region.unwrap();
        // A global resource takes the plan's main region.
        assert_eq!(region("g"), "eu-west-1");
        assert_eq!(
            (region("a"), region("b")),
            ("eu-west-1".into(), "eu-central-1".into())
        );
    }

    #[test]
    fn configuration_constants_are_collected() {
        let doc = json!({"configuration": {"root_module": {"resources": [{"expressions": {
            "policy_arn": {"constant_value": "arn:aws:iam::aws:policy/P"},
            "name": {"references": ["var.name"]}}}]}}});
        let mut c = std::collections::BTreeSet::new();
        constants(&doc["configuration"], false, &mut c);
        assert_eq!(
            c.into_iter().collect::<Vec<_>>(),
            ["arn:aws:iam::aws:policy/P"]
        );
    }

    #[test]
    fn account_from_caller_identity_in_a_module() {
        let state = json!({"child_modules": [{"resources": [
            {"type": "aws_caller_identity", "values": {"account_id": "111122223333"}}]}]});
        assert_eq!(caller_account(&state).as_deref(), Some("111122223333"));
    }

    #[test]
    fn rejects_unknown_major_version() {
        let doc = json!({"format_version": "2.0", "planned_values": {}});
        assert_eq!(from_value(&doc).unwrap_err().exit_code(), 1);
    }
}
