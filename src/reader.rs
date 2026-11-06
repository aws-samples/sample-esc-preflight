//! Reads a CloudFormation template (JSON or YAML), a CDK cloud assembly directory, or a
//! Terraform plan (`terraform show -json`) into the [`Template`] model. The format is
//! detected from the input.
//!
//! YAML short-form intrinsics (`!Ref`, `!Sub`, `!GetAtt`, ...) are rewritten to their
//! long JSON form so later stages see a single representation.

mod cdk;
mod terraform;

use std::io::Read;
use std::path::Path;

use saphyr::{LoadableYamlNode, Scalar, Yaml};
use serde_json::{Map, Number, Value};

use crate::error::{Result, ScanError};
use crate::model::{DeployEnv, OUTPUT_TYPE, Origin, Resource, Template};

/// Reads a file, a cloud assembly directory, or stdin (`-`).
pub fn read(path: &str) -> Result<Template> {
    if path == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| ScanError::Input(format!("stdin: {e}")))?;
        return parse_with_env(&s, None);
    }
    let p = Path::new(path);
    if p.is_dir() {
        return cdk::read_assembly(p);
    }
    let text = std::fs::read_to_string(p).map_err(|e| ScanError::Input(format!("{path}: {e}")))?;
    parse_with_env(&text, cdk::env_of(p))
}

/// Parses input text. JSON is tried first, then YAML.
#[cfg(test)]
pub fn parse(text: &str) -> Result<Template> {
    parse_with_env(text, None)
}

fn parse_with_env(text: &str, env: Option<DeployEnv>) -> Result<Template> {
    let doc = match serde_json::from_str::<Value>(text) {
        Ok(v) if terraform::is_plan(&v) => return terraform::from_value(&v),
        Ok(v) => v,
        Err(_) => yaml_document(text)?,
    };
    from_value(&doc, env)
}

fn yaml_document(text: &str) -> Result<Value> {
    let docs = Yaml::load_from_str(text)
        .map_err(|e| ScanError::Input(format!("not valid JSON or YAML: {e}")))?;
    let first = docs
        .into_iter()
        .next()
        .ok_or_else(|| ScanError::Input("empty template".into()))?;
    yaml_to_json(&first)
}

fn yaml_to_json(node: &Yaml) -> Result<Value> {
    Ok(match node {
        Yaml::Value(s) => scalar(s),
        Yaml::Representation(raw, _, _) => Value::String(raw.to_string()),
        Yaml::Sequence(seq) => Value::Array(seq.iter().map(yaml_to_json).collect::<Result<_>>()?),
        Yaml::Mapping(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                let key = match k {
                    Yaml::Value(s) => scalar_key(s),
                    Yaml::Representation(raw, _, _) => raw.to_string(),
                    _ => return Err(ScanError::Input("unsupported complex mapping key".into())),
                };
                out.insert(key, yaml_to_json(v)?);
            }
            Value::Object(out)
        }
        Yaml::Tagged(tag, inner) => {
            if tag.handle != "!" {
                return yaml_to_json(inner);
            }
            short_form(&tag.suffix, yaml_to_json(inner)?)
        }
        Yaml::Alias(_) => {
            return Err(ScanError::Input(
                "YAML aliases are not supported in CloudFormation".into(),
            ));
        }
        Yaml::BadValue => return Err(ScanError::Input("invalid YAML value".into())),
    })
}

/// Rewrites a CloudFormation short-form tag to its long form.
fn short_form(suffix: &str, inner: Value) -> Value {
    let (key, value) = match suffix {
        "Ref" => ("Ref".to_string(), inner),
        "Condition" => ("Condition".to_string(), inner),
        "GetAtt" => {
            let v = match inner {
                Value::String(s) => match s.split_once('.') {
                    Some((res, attr)) => Value::Array(vec![res.into(), attr.into()]),
                    None => Value::String(s),
                },
                other => other,
            };
            ("Fn::GetAtt".to_string(), v)
        }
        other => (format!("Fn::{other}"), inner),
    };
    let mut m = Map::new();
    m.insert(key, value);
    Value::Object(m)
}

fn scalar(s: &Scalar) -> Value {
    match s {
        Scalar::Null => Value::Null,
        Scalar::Boolean(b) => Value::Bool(*b),
        Scalar::Integer(i) => Value::Number((*i).into()),
        Scalar::FloatingPoint(f) => {
            Number::from_f64(f.into_inner()).map_or(Value::Null, Value::Number)
        }
        Scalar::String(s) => Value::String(s.to_string()),
    }
}

fn scalar_key(s: &Scalar) -> String {
    match scalar(s) {
        Value::String(s) => s,
        other => other.to_string(),
    }
}

fn from_value(doc: &Value, env: Option<DeployEnv>) -> Result<Template> {
    let resources = doc
        .get("Resources")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ScanError::Input(
                "neither a CloudFormation template (no Resources) nor a Terraform plan".into(),
            )
        })?;
    let mut flat = Map::new();
    expand_for_each(resources, &mut flat)?;
    let mut template = Template::default();
    for (id, body) in flat {
        let resource_type = match body.get("Type") {
            Some(Value::String(t)) => t.clone(),
            Some(_) => {
                return Err(ScanError::Input(format!(
                    "resource {id}: Type is not a string; package the template first if it uses modules"
                )));
            }
            None => return Err(ScanError::Input(format!("resource {id} has no Type"))),
        };
        template.resources.insert(
            id.clone(),
            Resource {
                logical_id: id,
                resource_type,
                properties: body.get("Properties").cloned().unwrap_or(Value::Null),
                origin: Origin::Cfn,
                env: env.clone(),
                cdk_path: body["Metadata"]["aws:cdk:path"].as_str().map(String::from),
            },
        );
    }
    // Output values are scanned for hardcoded values only: an exported ARN is
    // imported elsewhere, so a wrong partition there breaks the consumer.
    for (name, o) in doc
        .get("Outputs")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let id = format!("Outputs/{name}");
        template.outputs.insert(
            id.clone(),
            Resource {
                logical_id: id,
                resource_type: OUTPUT_TYPE.into(),
                properties: o.get("Value").cloned().unwrap_or(Value::Null),
                origin: Origin::Cfn,
                env: env.clone(),
                cdk_path: None,
            },
        );
    }
    Ok(template)
}

/// Expands `Fn::ForEach` (the `AWS::LanguageExtensions` transform). A literal collection
/// is expanded per item; one given by a parameter keeps the unexpanded template once,
/// which still has the resource types.
fn expand_for_each(resources: &Map<String, Value>, out: &mut Map<String, Value>) -> Result<()> {
    for (id, body) in resources {
        if !id.starts_with("Fn::ForEach::") {
            out.insert(id.clone(), body.clone());
            continue;
        }
        let bad = || ScanError::Input(format!("{id}: expected [identifier, collection, template]"));
        let (Some(ident), Some(collection), Some(inner)) = (
            body.get(0).and_then(Value::as_str),
            body.get(1),
            body.get(2).and_then(Value::as_object),
        ) else {
            return Err(bad());
        };
        let items: Vec<&str> = match collection.as_array() {
            Some(a) => a.iter().filter_map(Value::as_str).collect(),
            None => Vec::new(),
        };
        if items.is_empty() {
            expand_for_each(inner, out)?;
            continue;
        }
        for item in items {
            let mut expanded = Map::new();
            for (k, v) in inner {
                expanded.insert(substitute(k, ident, item), substitute_all(v, ident, item));
            }
            expand_for_each(&expanded, out)?;
        }
    }
    Ok(())
}

/// `${Id}` becomes the item, `&{Id}` the item without non-alphanumeric characters.
fn substitute(s: &str, ident: &str, item: &str) -> String {
    let clean: String = item.chars().filter(char::is_ascii_alphanumeric).collect();
    s.replace(&format!("${{{ident}}}"), item)
        .replace(&format!("&{{{ident}}}"), &clean)
}

fn substitute_all(v: &Value, ident: &str, item: &str) -> Value {
    match v {
        Value::String(s) => Value::String(substitute(s, ident, item)),
        Value::Array(a) => Value::Array(a.iter().map(|x| substitute_all(x, ident, item)).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| (substitute(k, ident, item), substitute_all(x, ident, item)))
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_the_cdk_construct_path() {
        let t = parse(
            r#"{"Resources":{"B":{"Type":"AWS::S3::Bucket","Metadata":{"aws:cdk:path":"App/Data/Bucket/Resource"}},"C":{"Type":"AWS::S3::Bucket"}}}"#,
        )
        .unwrap();
        assert_eq!(
            t.resources["B"].cdk_path.as_deref(),
            Some("App/Data/Bucket/Resource")
        );
        assert!(t.resources["C"].cdk_path.is_none());
    }

    #[test]
    fn parses_json() {
        let t = parse(
            r#"{"Resources":{"B":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"x"}}}}"#,
        )
        .unwrap();
        let r = &t.resources["B"];
        assert_eq!(r.resource_type, "AWS::S3::Bucket");
        assert_eq!(r.properties, json!({"BucketName": "x"}));
    }

    #[test]
    fn parses_yaml_short_form_intrinsics() {
        let yaml = r#"
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      Role: !GetAtt Role.Arn
      Name: !Ref Prefix
      Arn: !Sub "arn:${AWS::Partition}:s3:::b"
      List: !Join [",", [a, b]]
      Port: 443
"#;
        let t = parse(yaml).unwrap();
        let p = &t.resources["Fn"].properties;
        assert_eq!(p["Role"], json!({"Fn::GetAtt": ["Role", "Arn"]}));
        assert_eq!(p["Name"], json!({"Ref": "Prefix"}));
        assert_eq!(p["Arn"], json!({"Fn::Sub": "arn:${AWS::Partition}:s3:::b"}));
        assert_eq!(p["List"], json!({"Fn::Join": [",", ["a", "b"]]}));
        assert_eq!(p["Port"], json!(443));
    }

    #[test]
    fn rejects_malformed_input() {
        let err = parse("{not: [valid").unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn expands_for_each() {
        let t = parse(
            r#"{"Transform":"AWS::LanguageExtensions","Resources":{
            "Fn::ForEach::Tables":["Name",["Points","Score-v2"],
              {"${Name}Table":{"Type":"AWS::DynamoDB::Table","Properties":{"TableName":"&{Name}"}}}],
            "Fn::ForEach::Queues":["Q",{"Ref":"Names"},
              {"${Q}Queue":{"Type":"AWS::SQS::Queue"}}]}}"#,
        )
        .unwrap();
        let ids: Vec<_> = t.resources.keys().cloned().collect();
        assert_eq!(ids, ["${Q}Queue", "PointsTable", "Score-v2Table"]);
        assert_eq!(
            t.resources["Score-v2Table"].properties["TableName"],
            "Scorev2"
        );
    }

    #[test]
    fn unpackaged_module_type_is_explained() {
        let err = parse("Resources:\n  M:\n    Type: !Rain::Module ./m.yml\n").unwrap_err();
        assert!(err.to_string().contains("package the template"), "{err}");
    }

    #[test]
    fn rejects_template_without_resources() {
        assert_eq!(parse(r#"{"Parameters":{}}"#).unwrap_err().exit_code(), 1);
    }

    #[test]
    fn rejects_resource_without_type() {
        assert_eq!(
            parse(r#"{"Resources":{"A":{}}}"#).unwrap_err().exit_code(),
            1
        );
    }
}
