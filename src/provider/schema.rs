//! CloudFormation resource schemas of the target: which top-level properties each
//! resource type accepts there. Public mode reads the Region's schema bundle, which
//! exists for the global partition, GovCloud and China; live mode calls `DescribeType`
//! in the target account, ESC included.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use super::aws_call::{Call, Caller, Outcome, xml_values};
use super::http::Client;
use crate::depth::{DepthCheck, DepthKind, DepthSource};
use crate::error::{Result, ScanError};
use crate::extractor::PartitionFacts;
use crate::model::{Origin, Template};

/// The most a bundle may inflate to; the biggest is about 40 MB unpacked.
const MAX_INFLATED: usize = 256 << 20;

/// `DescribeType` calls in flight at once. The API throttles four.
const LIVE_PARALLEL: usize = 2;
/// Waits after the caller's own retries are spent on throttling, 5 s each.
const THROTTLE_WAITS: u32 = 4;

/// Partitions that publish a schema bundle per Region.
const BUNDLE_PARTITIONS: &[&str] = &["aws", "aws-us-gov", "aws-cn"];

/// Top-level properties per resource type, for the types the input uses that the
/// target has a schema for.
pub type Schemas = BTreeMap<String, BTreeSet<String>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SchemaSource {
    /// The Region's public schema bundle.
    Bundle,
    /// `cloudformation:DescribeType` in the target account.
    Live,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct SchemaProvenance {
    pub source: SchemaSource,
    /// The bundle read, for `bundle`.
    pub url: Option<String>,
    /// Resource types whose schema was read.
    pub types: usize,
}

impl SchemaProvenance {
    pub fn new(source: SchemaSource, url: Option<String>, s: &Schemas) -> Self {
        Self {
            source,
            url,
            types: s.len(),
        }
    }
}

/// The schema bundle of the target Region, where its partition publishes one. The
/// host stays written as `schema.cloudformation.{}`: `tests/guards.rs` allows exactly
/// that prefix, which `http::is_schema_host` narrows to Region-shaped hosts.
pub fn bundle_url(facts: &PartitionFacts) -> Option<String> {
    BUNDLE_PARTITIONS
        .contains(&facts.target_partition.as_str())
        .then(|| {
            format!(
                "https://schema.cloudformation.{}.{}/CloudformationSchema.zip",
                facts.target_region, facts.target_dns_suffix
            )
        })
}

/// CloudFormation resource types the input sets properties on.
pub fn types(template: &Template) -> BTreeSet<String> {
    // A macro rewrites resources at deployment, so what the template sets is not what
    // reaches the registry.
    if !template.macros.is_empty() {
        return BTreeSet::new();
    }
    template
        .resources
        .values()
        .filter(|r| checked(&r.resource_type, r.origin))
        .map(|r| r.resource_type.clone())
        .collect()
}

/// AWS resource types with a registry schema. SAM types are transformed before they
/// reach the registry; custom resources take any property.
fn checked(resource_type: &str, origin: Origin) -> bool {
    origin == Origin::Cfn
        && resource_type.starts_with("AWS::")
        && !resource_type.starts_with("AWS::Serverless::")
        && resource_type != "AWS::CloudFormation::CustomResource"
}

/// Reads the schemas of `want` from the bundle at `url`.
pub fn fetch_bundle(
    client: &Client,
    url: &str,
    want: &BTreeSet<String>,
    settable_only: bool,
) -> Result<Schemas> {
    let zip = client.get_bytes(url)?;
    let files: BTreeSet<String> = want.iter().map(|t| file_name(t)).collect();
    let mut out = Schemas::new();
    for (name, data) in unzip(&zip, |n| files.contains(n))
        .map_err(|e| ScanError::DataSource(format!("{url}: {e}")))?
    {
        let unreadable =
            || ScanError::DataSource(format!("{url}: {name} is not a resource schema"));
        let text = String::from_utf8(data).map_err(|_| unreadable())?;
        let (t, props) = properties(&text, settable_only).ok_or_else(unreadable)?;
        if want.contains(&t) {
            out.insert(t, props);
        }
    }
    Ok(out)
}

/// `AWS::Lambda::Function` -> `aws-lambda-function.json`, the bundle's file name.
fn file_name(resource_type: &str) -> String {
    format!("{}.json", resource_type.to_lowercase().replace("::", "-"))
}

/// Reads each type's schema with `DescribeType`. A type the registry does not know is
/// left out: availability is decided elsewhere.
pub fn fetch_live(
    caller: &Caller,
    want: &BTreeSet<String>,
    settable_only: bool,
) -> Result<Schemas> {
    let failed = std::sync::atomic::AtomicBool::new(false);
    let cfn = crate::services::service("cloudformation");
    let one = |t: &String| -> Result<Option<(String, BTreeSet<String>)>> {
        let call = || {
            caller.call(
                cfn,
                "DescribeType",
                "POST",
                "/",
                &[("Type", "RESOURCE"), ("TypeName", t)],
            )
        };
        let mut outcome = call();
        for _ in 0..THROTTLE_WAITS {
            if !outcome.is_throttled() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
            outcome = call();
        }
        let body = match outcome {
            Outcome::Error(code) if code.starts_with("TypeNotFound") => return Ok(None),
            o => o.body("DescribeType")?,
        };
        // A schema that does not parse would hide missing properties, so it fails.
        xml_values(&body, "Schema")
            .first()
            .and_then(|s| properties(s, settable_only))
            .map(Some)
            .ok_or_else(|| ScanError::DataSource(format!("DescribeType {t}: no readable schema")))
    };
    let want: Vec<&String> = want.iter().collect();
    let chunk = want.len().div_ceil(LIVE_PARALLEL).max(1);
    let parts: Vec<Result<Vec<_>>> = std::thread::scope(|s| {
        let handles: Vec<_> = want
            .chunks(chunk)
            .map(|c| {
                let (one, failed) = (&one, &failed);
                s.spawn(move || {
                    let mut out = Vec::new();
                    for t in c {
                        // A failed worker stops the others.
                        if failed.load(std::sync::atomic::Ordering::Relaxed) {
                            break;
                        }
                        match one(t) {
                            Ok(v) => out.push(v),
                            Err(e) => {
                                failed.store(true, std::sync::atomic::Ordering::Relaxed);
                                return Err(e);
                            }
                        }
                    }
                    Ok(out)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("DescribeType worker does not panic"))
            .collect()
    });
    let mut out = Schemas::new();
    for part in parts {
        out.extend(part?.into_iter().flatten());
    }
    Ok(out)
}

/// The type name and top-level property names of one schema document. With
/// `settable_only`, without the read-only ones: attributes CloudFormation returns,
/// which no input sets. A scan keeps them, so an input that sets one is not told the
/// target lacks it.
pub fn properties(schema: &str, settable_only: bool) -> Option<(String, BTreeSet<String>)> {
    let v: Value = serde_json::from_str(schema).ok()?;
    let name = v["typeName"].as_str()?.to_string();
    let read_only: BTreeSet<&str> = v["readOnlyProperties"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p.as_str()?.strip_prefix("/properties/"))
        .filter(|p| !p.contains('/'))
        .collect();
    let props = v["properties"]
        .as_object()?
        .keys()
        .filter(|k| !settable_only || !read_only.contains(k.as_str()))
        .cloned()
        .collect();
    Some((name, props))
}

/// A depth check for every top-level property the input sets that the target schema
/// of its type lacks. Types without a target schema are not checked.
pub fn checks(template: &Template, schemas: &Schemas) -> BTreeMap<String, Vec<DepthCheck>> {
    let mut out: BTreeMap<String, Vec<DepthCheck>> = BTreeMap::new();
    if !template.macros.is_empty() {
        return out;
    }
    for r in template
        .resources
        .values()
        .filter(|r| checked(&r.resource_type, r.origin))
    {
        let (Some(known), Some(props)) = (schemas.get(&r.resource_type), r.properties.as_object())
        else {
            continue;
        };
        for (key, value) in props {
            // `AWS::NoValue` removes the property; `Fn::Transform` (`AWS::Include`)
            // replaces the properties.
            if known.contains(key)
                || key.starts_with("Fn::")
                || value.get("Ref") == Some(&Value::from("AWS::NoValue"))
            {
                continue;
            }
            out.entry(r.logical_id.clone())
                .or_default()
                .push(DepthCheck {
                    kind: DepthKind::Property,
                    path: format!("Properties.{key}"),
                    value: key.clone(),
                    offered: Some(false),
                    source: Some(DepthSource::Schema),
                });
        }
    }
    out
}

/// The entries of a zip archive whose names `want` accepts. Reads the central
/// directory, then each entry's data, stored or deflated.
fn unzip(
    zip: &[u8],
    want: impl Fn(&str) -> bool,
) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
    let u16_at = |i: usize| -> std::result::Result<usize, String> {
        zip.get(i..i + 2)
            .map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])))
            .ok_or_else(|| "truncated archive".to_string())
    };
    let u32_at = |i: usize| -> std::result::Result<usize, String> {
        zip.get(i..i + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
            .ok_or_else(|| "truncated archive".to_string())
    };
    // End of central directory: the last `PK\x05\x06` record.
    let eocd = (0..zip.len().saturating_sub(21))
        .rev()
        .find(|&i| zip[i..].starts_with(b"PK\x05\x06"))
        .ok_or("no end of central directory")?;
    let entries = u16_at(eocd + 10)?;
    let mut at = u32_at(eocd + 16)?;
    let mut out = Vec::new();
    let mut inflated = 0usize;
    for _ in 0..entries {
        if !zip.get(at..).is_some_and(|z| z.starts_with(b"PK\x01\x02")) {
            return Err("bad central directory entry".into());
        }
        let method = u16_at(at + 10)?;
        // Sizes from the central directory: a local header followed by a data
        // descriptor carries zeros.
        let (csize, size) = (u32_at(at + 20)?, u32_at(at + 24)?);
        let (name_len, extra_len, comment_len) =
            (u16_at(at + 28)?, u16_at(at + 30)?, u16_at(at + 32)?);
        let local = u32_at(at + 42)?;
        let name = zip
            .get(at + 46..at + 46 + name_len)
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .ok_or("truncated archive")?;
        at += 46 + name_len + extra_len + comment_len;
        if !want(&name) {
            continue;
        }
        if !zip
            .get(local..)
            .is_some_and(|z| z.starts_with(b"PK\x03\x04"))
        {
            return Err(format!("{name}: bad local header"));
        }
        inflated += size;
        if inflated > MAX_INFLATED {
            return Err(format!("more than {MAX_INFLATED} bytes unpacked"));
        }
        let start = local + 30 + u16_at(local + 26)? + u16_at(local + 28)?;
        let raw = zip
            .get(start..start + csize)
            .ok_or_else(|| format!("{name}: truncated"))?;
        let data = match method {
            0 => raw.to_vec(),
            8 => miniz_oxide::inflate::decompress_to_vec_with_limit(raw, size)
                .map_err(|e| format!("{name}: {e:?}"))?,
            m => return Err(format!("{name}: compression method {m}")),
        };
        out.push((name, data));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::partition;
    use crate::reader;

    #[test]
    fn bundles_exist_outside_esc_and_iso() {
        let url = |r: &str| bundle_url(&partition::facts(r).unwrap());
        assert_eq!(
            url("eu-west-1").as_deref(),
            Some("https://schema.cloudformation.eu-west-1.amazonaws.com/CloudformationSchema.zip")
        );
        assert_eq!(
            url("cn-north-1").as_deref(),
            Some(
                "https://schema.cloudformation.cn-north-1.amazonaws.com.cn/CloudformationSchema.zip"
            )
        );
        assert!(url("us-gov-west-1").is_some());
        assert!(url("eusc-de-east-1").is_none());
        assert!(url("eu-isoe-west-1").is_none());
    }

    #[test]
    fn properties_the_target_lacks_are_checks() {
        let t = reader::parse_text(
            r#"{"Resources":{
            "F":{"Type":"AWS::Lambda::Function","Properties":{"Runtime":"python3.13",
                "AcceleratorConfig":{},"RuntimeConfig":{"Ref":"AWS::NoValue"}}},
            "S":{"Type":"AWS::Serverless::Function","Properties":{"Anything":1}},
            "C":{"Type":"AWS::CloudFormation::CustomResource","Properties":{"ServiceToken":"x","Any":1}},
            "U":{"Type":"AWS::Unknown::Thing","Properties":{"X":1}}}}"#,
        )
        .unwrap();
        assert_eq!(
            types(&t),
            ["AWS::Lambda::Function", "AWS::Unknown::Thing"]
                .map(String::from)
                .into()
        );
        let schemas = Schemas::from([(
            "AWS::Lambda::Function".to_string(),
            ["Runtime".to_string()].into(),
        )]);
        let c = checks(&t, &schemas);
        assert_eq!(c.len(), 1, "{c:?}");
        let f = &c["F"];
        assert_eq!(f.len(), 1, "AWS::NoValue sets nothing");
        let mut m = t.clone();
        m.macros = vec!["MyMacro".into()];
        assert!(types(&m).is_empty() && checks(&m, &schemas).is_empty());
        assert_eq!(
            (f[0].kind, f[0].path.as_str(), f[0].offered, f[0].source),
            (
                DepthKind::Property,
                "Properties.AcceleratorConfig",
                Some(false),
                Some(DepthSource::Schema)
            )
        );
    }

    #[test]
    fn reads_a_schema_document() {
        let doc = r#"{"typeName":"AWS::S3::Bucket","properties":{"BucketName":{},"Tags":{},"Arn":{},"Nested":{}},
                "readOnlyProperties":["/properties/Arn","/properties/Nested/Id"]}"#;
        assert!(
            properties(doc, false).unwrap().1.contains("Arn"),
            "a scan keeps them"
        );
        let (t, p) = properties(doc, true).unwrap();
        assert_eq!(t, "AWS::S3::Bucket");
        assert_eq!(
            p,
            ["BucketName", "Nested", "Tags"].map(String::from).into(),
            "read-only attributes are not properties an input sets"
        );
        assert!(properties("{}", false).is_none());
    }

    /// A stored and a deflated entry, as written by Python's zipfile.
    #[test]
    fn unzips_stored_and_deflated_entries() {
        let zip = include_bytes!("../../tests/fixtures/schemas.zip");
        let all = unzip(zip, |_| true).unwrap();
        let names: Vec<&str> = all.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["aws-lambda-function.json", "aws-s3-bucket.json"]);
        for (_, data) in &all {
            assert!(properties(std::str::from_utf8(data).unwrap(), false).is_some());
        }
        assert_eq!(unzip(zip, |n| n.starts_with("aws-s3")).unwrap().len(), 1);
        assert!(unzip(b"not a zip", |_| true).is_err());
        assert!(unzip(&zip[..zip.len() / 2], |_| true).is_err());
    }

    /// `DescribeType` against a real ESC account, whose Lambda schema lacks
    /// `AcceleratorConfig`. Run with
    /// `ESC_PREFLIGHT_PROFILE=<profile> cargo test -- --ignored live_esc`.
    #[test]
    #[ignore = "network and credentials"]
    fn live_esc_schemas() {
        let profile = std::env::var("ESC_PREFLIGHT_PROFILE").unwrap();
        let caller = Caller::new(
            "eusc-de-east-1",
            "amazonaws.eu",
            Some(&profile),
            None,
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let want = ["AWS::Lambda::Function", "AWS::Unknown::Thing"]
            .map(String::from)
            .into();
        let s = fetch_live(&caller, &want, false).unwrap();
        assert_eq!(s.len(), 1, "an unknown type is left out");
        let lambda = &s["AWS::Lambda::Function"];
        assert!(lambda.contains("Runtime") && !lambda.contains("AcceleratorConfig"));
    }

    /// The real bundle of eu-west-1. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn live_bundle() {
        let client = Client::new(std::time::Duration::from_secs(60)).unwrap();
        let facts = partition::facts("eu-west-1").unwrap();
        let want = ["AWS::Lambda::Function", "AWS::S3::Bucket"]
            .map(String::from)
            .into();
        let s = fetch_bundle(&client, &bundle_url(&facts).unwrap(), &want, false).unwrap();
        assert!(s["AWS::Lambda::Function"].contains("AcceleratorConfig"));
        assert!(s["AWS::S3::Bucket"].contains("BucketName"));
    }
}
