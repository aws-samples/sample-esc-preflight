//! AWS SAM resources as the CloudFormation resources they deploy as. The AWS SAM
//! specification states for each property whether SAM passes it directly to a
//! property of the generated resource; `data/sam.json` holds those statements, so
//! availability, property and rule checks read a SAM resource as its base type.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Deserialize)]
struct File {
    types: BTreeMap<String, SamType>,
    /// Globals section name (`Function`) to the properties it may set.
    globals: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize)]
pub(crate) struct SamType {
    pub cfn_type: String,
    #[allow(dead_code, reason = "read by the doc-quote test")]
    pub doc: String,
    pub pass_through: BTreeMap<String, PassThrough>,
}

#[derive(Deserialize)]
pub(crate) struct PassThrough {
    pub property: String,
    #[allow(dead_code, reason = "read by the doc-quote test")]
    pub quote: String,
}

fn file() -> &'static File {
    static F: OnceLock<File> = OnceLock::new();
    F.get_or_init(|| {
        serde_json::from_str(include_str!("../data/sam.json")).expect("bundled SAM map is valid")
    })
}

pub(crate) fn types() -> &'static BTreeMap<String, SamType> {
    &file().types
}

/// The CloudFormation type a SAM type deploys as.
pub fn base_type(resource_type: &str) -> Option<&'static str> {
    types().get(resource_type).map(|t| t.cfn_type.as_str())
}

/// The template uses the AWS SAM transform.
pub fn is_sam(transform: Option<&Value>) -> bool {
    match transform {
        Some(Value::String(s)) => s.starts_with("AWS::Serverless-"),
        Some(Value::Array(a)) => a.iter().any(|t| is_sam(Some(t))),
        _ => false,
    }
}

/// Merges the template's `Globals` into a SAM resource's properties, as SAM does:
/// the resource's own value wins for a scalar, maps are merged, lists are joined.
pub fn merge_globals(resource_type: &str, props: &mut Value, globals: Option<&Value>) {
    let Some(section) = resource_type.strip_prefix("AWS::Serverless::") else {
        return;
    };
    let (Some(g), Some(allowed)) = (
        globals
            .and_then(|g| g.get(section))
            .and_then(Value::as_object),
        file().globals.get(section),
    ) else {
        return;
    };
    if props.is_null() {
        *props = Value::Object(Map::new());
    }
    let Some(own) = props.as_object_mut() else {
        return;
    };
    for (k, v) in g.iter().filter(|(k, _)| allowed.contains(k)) {
        merge(own.entry(k.clone()).or_insert(Value::Null), v);
    }
}

fn merge(own: &mut Value, global: &Value) {
    match (own, global) {
        (own @ Value::Null, g) => *own = g.clone(),
        (Value::Object(o), Value::Object(g)) => {
            for (k, v) in g {
                merge(o.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (Value::Array(o), Value::Array(g)) => {
            let mut joined = g.clone();
            joined.append(o);
            *o = joined;
        }
        _ => {}
    }
}

/// The CloudFormation resource a SAM resource deploys as, with the properties SAM
/// passes through unchanged. `None` for other types and SAM types without a base.
pub fn deployed(resource_type: &str, props: &Value) -> Option<Box<(String, Value)>> {
    let t = types().get(resource_type)?;
    let out: Map<String, Value> = props
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| {
            t.pass_through
                .get(k)
                .map(|p| (p.property.clone(), v.clone()))
        })
        .collect();
    Some(Box::new((t.cfn_type.clone(), Value::Object(out))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn globals_merge_like_sam() {
        let globals = json!({"Function": {
            "Runtime": "python3.9",
            "Environment": {"Variables": {"A": "1", "B": "2"}},
            "Layers": ["g"],
            "Events": {"Not": "allowed"}
        }});
        let mut p = json!({
            "Runtime": "python3.13",
            "Environment": {"Variables": {"B": "own"}},
            "Layers": ["own"]
        });
        merge_globals("AWS::Serverless::Function", &mut p, Some(&globals));
        assert_eq!(p["Runtime"], "python3.13");
        assert_eq!(p["Environment"]["Variables"], json!({"A": "1", "B": "own"}));
        assert_eq!(p["Layers"], json!(["g", "own"]));
        assert!(p.get("Events").is_none());
        let mut empty = Value::Null;
        merge_globals("AWS::Serverless::Function", &mut empty, Some(&globals));
        assert_eq!(empty["Runtime"], "python3.9");
        let mut other = json!({});
        merge_globals("AWS::Lambda::Function", &mut other, Some(&globals));
        assert_eq!(other, json!({}));
    }

    #[test]
    fn deploys_as_the_base_type_with_pass_through_properties() {
        let d = deployed(
            "AWS::Serverless::Function",
            &json!({"Runtime": "nodejs22.x", "CodeUri": "src/", "SnapStart": {}, "Events": {}}),
        )
        .unwrap();
        assert_eq!(d.0, "AWS::Lambda::Function");
        assert_eq!(d.1, json!({"Runtime": "nodejs22.x", "SnapStart": {}}));
        assert!(deployed("AWS::Lambda::Function", &json!({})).is_none());
        assert!(deployed("AWS::Serverless::Connector", &json!({})).is_none());
    }

    #[test]
    fn sam_transform() {
        assert!(is_sam(Some(&json!("AWS::Serverless-2016-10-31"))));
        assert!(is_sam(Some(&json!([
            "AWS::LanguageExtensions",
            "AWS::Serverless-2016-10-31"
        ]))));
        assert!(!is_sam(Some(&json!("AWS::LanguageExtensions"))));
        assert!(!is_sam(None));
    }
}
