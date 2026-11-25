//! Terraform plan JSON (`terraform show -json <plan>`), format version 1.x.
//!
//! Planned values already have modules, `count` and `for_each` resolved. Values known
//! only after apply are absent, so they can never produce a hazard.

use std::collections::{BTreeMap, BTreeSet};

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
                deployed: None,
            },
        );
    }
    // Not `provider_config`: its region is the plan's environment, which every
    // resolved value of that Region would otherwise match as typed by hand.
    constants(
        &doc["configuration"]["root_module"],
        false,
        &mut t.constants,
    );
    t.out_of_scope.sort();
    references(&doc["configuration"]["root_module"], &mut t);
    policy_documents(doc, &mut t);
    Ok(t)
}

/// A policy argument set from an `aws_iam_policy_document` data source is unknown in
/// the plan when the data source is read at apply time. The data source's own
/// statements are known then, so they take the argument's place for the checks.
fn policy_documents(doc: &Value, t: &mut Template) {
    let mut docs: std::collections::BTreeMap<String, String> = Default::default();
    fn read(module: &Value, docs: &mut std::collections::BTreeMap<String, String>) {
        for r in module["resources"].as_array().into_iter().flatten() {
            if r["mode"] == "data"
                && r["type"] == "aws_iam_policy_document"
                && let Some(address) = r["address"].as_str()
            {
                docs.insert(base(address), document(&r["values"]));
            }
        }
        for child in module["child_modules"].as_array().into_iter().flatten() {
            read(child, docs);
        }
    }
    read(&doc["prior_state"]["values"]["root_module"], &mut docs);
    for c in doc["resource_changes"].as_array().into_iter().flatten() {
        if c["mode"] == "data"
            && c["type"] == "aws_iam_policy_document"
            && let Some(address) = c["address"].as_str()
        {
            docs.entry(base(address))
                .or_insert_with(|| document(&c["change"]["after"]));
        }
    }
    if docs.is_empty() {
        return;
    }
    let mut uses: Vec<(String, String, String)> = Vec::new();
    fn walk_config(module: &Value, prefix: &str, out: &mut Vec<(String, String, String)>) {
        for r in module["resources"].as_array().into_iter().flatten() {
            let Some(address) = r["address"].as_str() else {
                continue;
            };
            for (arg, e) in r["expressions"].as_object().into_iter().flatten() {
                for reference in e["references"].as_array().into_iter().flatten() {
                    if let Some(d) = reference
                        .as_str()
                        .and_then(|s| s.strip_suffix(".json"))
                        .filter(|s| s.starts_with("data.aws_iam_policy_document."))
                    {
                        out.push((
                            format!("{prefix}{address}"),
                            arg.clone(),
                            format!("{prefix}{}", strip_index(d)),
                        ));
                    }
                }
            }
        }
        for (name, call) in module["module_calls"].as_object().into_iter().flatten() {
            walk_config(&call["module"], &format!("{prefix}module.{name}."), out);
        }
    }
    walk_config(&doc["configuration"]["root_module"], "", &mut uses);
    for r in t.resources.values_mut() {
        let b = base(&r.logical_id);
        for (_, arg, d) in uses.iter().filter(|(a, ..)| *a == b) {
            let (Some(text), Some(props)) = (docs.get(d), r.properties.as_object_mut()) else {
                continue;
            };
            if props.get(arg).is_none_or(Value::is_null) {
                props.insert(arg.clone(), Value::String(text.clone()));
            }
        }
    }
}

/// The rendered JSON when the plan has it, else the statements as written.
fn document(values: &Value) -> String {
    match values["json"].as_str() {
        Some(json) => json.to_string(),
        None => serde_json::json!({"statement": values["statement"]}).to_string(),
    }
}

/// Each resource's dependencies, from the references in the configuration's
/// expressions and `depends_on`, followed through data sources, module inputs and
/// outputs, and a module's `depends_on`. Also records the arguments each resource sets.
fn references(root: &Value, t: &mut Template) {
    let mut deps: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut set: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    config(root, "", &BTreeMap::new(), &[], &mut deps, &mut set);
    let planned: Vec<(String, String)> = t.resources.keys().map(|a| (a.clone(), base(a))).collect();
    for (address, b) in &planned {
        if let Some(args) = set.get(b) {
            t.configured.insert(address.clone(), args.clone());
        }
        let mut targets = BTreeSet::new();
        resolve(b, &deps, &mut BTreeSet::new(), &mut targets);
        let found: Vec<String> = planned
            .iter()
            .filter(|(other, ob)| {
                other != address
                    && targets
                        .iter()
                        .any(|d| ob == d || (d.ends_with('.') && ob.starts_with(d.as_str())))
            })
            .map(|(other, _)| other.clone())
            .collect();
        if !found.is_empty() {
            t.depends_on.insert(address.clone(), found);
        }
    }
}

/// What `key` depends on, with data sources replaced by what they depend on.
fn resolve(
    key: &str,
    deps: &BTreeMap<String, Vec<String>>,
    seen: &mut BTreeSet<String>,
    out: &mut BTreeSet<String>,
) {
    for d in deps.get(key).into_iter().flatten() {
        if is_data(d) || d.contains("out:") {
            if seen.insert(d.clone()) {
                resolve(d, deps, seen, out);
            }
        } else {
            out.insert(d.clone());
        }
    }
}

fn is_data(address: &str) -> bool {
    address.starts_with("data.") || address.contains(".data.")
}

/// Walks one module of the configuration. `inputs` maps the module's variables to
/// what the calling expressions depend on; `after` is the module call's `depends_on`.
fn config(
    module: &Value,
    prefix: &str,
    inputs: &BTreeMap<String, Vec<String>>,
    after: &[String],
    out: &mut BTreeMap<String, Vec<String>>,
    set: &mut BTreeMap<String, BTreeSet<String>>,
) {
    let targets_of = |refs: &[String]| -> Vec<String> {
        let mut t: Vec<String> = Vec::new();
        // `module.x.out` comes with a bare `module.x`; the output is the precise one.
        let module_of = |r: &str| -> Option<(String, usize)> {
            let p: Vec<&str> = r.split('.').collect();
            (p[0] == "module" && p.len() >= 2).then(|| (strip_index(p[1]).to_string(), p.len()))
        };
        let outputs: BTreeSet<String> = refs
            .iter()
            .filter_map(|r| module_of(r).filter(|(_, n)| *n >= 3).map(|(m, _)| m))
            .collect();
        let bare = |r: &str| module_of(r).is_some_and(|(m, n)| n == 2 && outputs.contains(&m));
        for reference in refs.iter().filter(|r| !bare(r)) {
            match reference.strip_prefix("var.") {
                Some(rest) => {
                    let name = rest.split('.').next().unwrap_or(rest);
                    t.extend(inputs.get(name).into_iter().flatten().cloned());
                }
                None => t.extend(target(reference, prefix)),
            }
        }
        t.sort();
        t.dedup();
        t
    };
    for r in module["resources"].as_array().into_iter().flatten() {
        let Some(address) = r["address"].as_str() else {
            continue;
        };
        let mut refs = Vec::new();
        collect(&r["expressions"], &mut refs);
        let mut targets = targets_of(&refs);
        // `depends_on = [module.m]` means the whole module, beside any output of it.
        for d in strings(&r["depends_on"]) {
            targets.extend(target(&d, prefix));
        }
        targets.extend(after.iter().cloned());
        let key = format!("{prefix}{address}");
        if r["mode"] == "managed" {
            set.insert(
                key.clone(),
                r["expressions"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .map(|(k, _)| k.clone())
                    .collect(),
            );
        }
        if !targets.is_empty() {
            out.entry(key).or_default().extend(targets);
        }
    }
    for (name, call) in module["module_calls"].as_object().into_iter().flatten() {
        let mut inner = BTreeMap::new();
        for (var, e) in call["expressions"].as_object().into_iter().flatten() {
            let mut refs = Vec::new();
            collect(e, &mut refs);
            inner.insert(var.clone(), targets_of(&refs));
        }
        let mut later = targets_of(&strings(&call["depends_on"]));
        later.extend(after.iter().cloned());
        config(
            &call["module"],
            &format!("{prefix}module.{name}."),
            &inner,
            &later,
            out,
            set,
        );
    }
    // A module output depends on what its expression references. Locals are not in
    // the plan, so an output that goes through one depends on the whole module.
    for (name, o) in module["outputs"].as_object().into_iter().flatten() {
        let mut refs = Vec::new();
        collect(&o["expression"], &mut refs);
        let mut targets = targets_of(&refs);
        if refs.iter().any(|r| r.starts_with("local.")) && !prefix.is_empty() {
            targets.push(prefix.to_string());
        }
        if !targets.is_empty() {
            out.insert(format!("{prefix}out:{name}"), targets);
        }
    }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(String::from)
        .collect()
}

/// `aws_vpc.main.id` -> `aws_vpc.main`; `data.aws_iam_policy_document.d.json` ->
/// `data.aws_iam_policy_document.d`; `module.net.subnet_ids` -> the output
/// `module.net.out:subnet_ids`, resolved to what it references; `module.net` -> every
/// resource of the module.
/// Locals and meta references name no resource.
fn target(reference: &str, prefix: &str) -> Option<String> {
    let parts: Vec<&str> = reference.split('.').collect();
    match parts.as_slice() {
        ["module", name, output, ..] => Some(format!(
            "{prefix}module.{}.out:{}",
            strip_index(name),
            strip_index(output)
        )),
        ["module", name] => Some(format!("{prefix}module.{}.", strip_index(name))),
        ["data", ty, name, ..] => Some(format!("{prefix}data.{ty}.{}", strip_index(name))),
        [first, ..]
            if ["var", "local", "path", "count", "each", "self", "terraform"].contains(first) =>
        {
            None
        }
        [ty, name, ..] => Some(format!("{prefix}{ty}.{}", strip_index(name))),
        _ => None,
    }
}

fn collect(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if k == "references" {
                    out.extend(
                        x.as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .map(String::from),
                    );
                } else {
                    collect(x, out);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect(x, out)),
        _ => {}
    }
}

fn strip_index(s: &str) -> &str {
    s.split('[').next().unwrap_or(s)
}

/// A planned address without `count` and `for_each` indexes:
/// `module.net[0].aws_subnet.a["x"]` -> `module.net.aws_subnet.a`.
fn base(address: &str) -> String {
    let mut out = String::new();
    let mut depth = 0;
    for c in address.chars() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
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
                deployed: None,
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
    fn the_provider_region_is_the_environment_not_a_constant() {
        let t = crate::reader::parse_text(
            r#"{"format_version":"1.2","planned_values":{"root_module":{"resources":[]}},
            "configuration":{"provider_config":{"aws":{"expressions":{"region":{"constant_value":"eu-central-1"}}}},
            "root_module":{"resources":[{"expressions":{"name":{"constant_value":"q-eu-central-1"}}}]}}}"#,
        )
        .unwrap();
        assert_eq!(
            t.constants.into_iter().collect::<Vec<_>>(),
            ["q-eu-central-1"]
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
