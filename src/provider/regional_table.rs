//! The public "AWS Services by Region" table, joined to SDK endpoint prefixes by a curated
//! name map.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;

use super::http::Client;
use crate::error::{Result, ScanError};

pub const URL: &str = "https://api.regional-table.region-services.aws.a2z.com/index.json";
const NAME_MAP_JSON: &str = include_str!("../../data/regional-table-names.json");

#[derive(Debug, Deserialize)]
struct NameMap {
    names: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct RegionalTableData {
    pub source_version: String,
    /// Endpoint prefixes the table lists in the target region.
    pub target_services: BTreeSet<String>,
    /// Target-region service names with no entry in the name map. They do not affect
    /// verdicts but are reported so the map can be extended.
    pub unmapped_names: Vec<String>,
}

pub fn fetch(client: &Client, target_region: &str) -> Result<RegionalTableData> {
    parse(&client.get_text(URL)?, target_region)
}

pub fn parse(body: &str, target_region: &str) -> Result<RegionalTableData> {
    let bad = |what: String| ScanError::DataSource(format!("regional table: {what}"));
    let doc: Value = serde_json::from_str(body).map_err(|e| bad(e.to_string()))?;
    let rows = doc["prices"]
        .as_array()
        .ok_or_else(|| bad("no prices array".into()))?;
    let map: NameMap =
        serde_json::from_str(NAME_MAP_JSON).expect("built-in name map is valid JSON");

    let mut target = BTreeSet::new();
    let mut unmapped = BTreeSet::new();
    for row in rows {
        let (Some(region), Some(name)) = (
            row["attributes"]["aws:region"].as_str(),
            row["attributes"]["aws:serviceName"].as_str(),
        ) else {
            continue;
        };
        if region != target_region {
            continue;
        }
        match map.names.get(name) {
            Some(tokens) => target.extend(tokens.iter().cloned()),
            None => {
                unmapped.insert(name.to_string());
            }
        }
    }
    Ok(RegionalTableData {
        source_version: doc["metadata"]["source:version"]
            .as_str()
            .unwrap_or("unknown")
            .to_string(),
        target_services: target,
        unmapped_names: unmapped.into_iter().collect(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn fixture() -> RegionalTableData {
        parse(
            include_str!("../../tests/fixtures/regional-table.json"),
            "eusc-de-east-1",
        )
        .unwrap()
    }

    #[test]
    fn every_captured_service_name_is_mapped() {
        let d = parse(
            include_str!("../../tests/fixtures/regional-table.json"),
            "eu-central-1",
        )
        .unwrap();
        assert!(
            d.unmapped_names.is_empty(),
            "unmapped: {:?}",
            d.unmapped_names
        );
        assert!(fixture().unmapped_names.is_empty());
    }

    #[test]
    fn reads_esc_services() {
        let d = fixture();
        assert_eq!(d.source_version, "20251113063700");
        for s in [
            "iam",
            "organizations",
            "route53",
            "eks",
            "api.sagemaker",
            "lambda",
        ] {
            assert!(d.target_services.contains(s), "{s}");
        }
        for s in ["cloudfront", "codebuild", "codepipeline"] {
            assert!(!d.target_services.contains(s), "{s}");
        }
    }
}
