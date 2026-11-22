//! Partition facts from the bundled botocore `partitions.json`. A new partition or
//! Region needs a new release; regenerate with `scripts/gen-botocore-services.py`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::error::{Result, ScanError};
use crate::extractor::PartitionFacts;

const PARTITIONS_JSON: &str = include_str!("../../data/partitions.json");
/// botocore release the bundled partition data comes from.
pub const VERSION: &str = "botocore 1.44.2";

pub fn facts(target_region: &str) -> Result<PartitionFacts> {
    let doc: Value =
        serde_json::from_str(PARTITIONS_JSON).expect("bundled partitions are valid JSON");
    let parts = doc["partitions"]
        .as_array()
        .expect("bundled partitions list");
    let target = parts
        .iter()
        .find(|p| p["regions"].get(target_region).is_some())
        .ok_or_else(|| {
            ScanError::Input(format!(
                "unknown region {target_region}; a Region newer than this release needs a newer esc-preflight"
            ))
        })?;
    let target_id = target["id"].as_str().unwrap_or_default().to_string();
    let mut partitions = Vec::new();
    let mut dns_suffixes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut dual_stack = BTreeSet::new();
    let mut region_partition = BTreeMap::new();
    for p in parts {
        let id = p["id"].as_str().unwrap_or_default();
        partitions.push(id.to_string());
        for key in ["dnsSuffix", "dualStackDnsSuffix"] {
            if let Some(s) = p["outputs"][key].as_str() {
                dns_suffixes
                    .entry(s.to_string())
                    .or_default()
                    .insert(id.to_string());
                if key == "dualStackDnsSuffix" {
                    dual_stack.insert(s.to_string());
                }
            }
        }
        for r in regions(p) {
            region_partition.insert(r.to_string(), id.to_string());
        }
    }
    partitions.sort();
    Ok(PartitionFacts {
        target_region: target_region.to_string(),
        target_dns_suffix: target["outputs"]["dnsSuffix"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        target_regions: regions(target).count(),
        target_partition: target_id,
        target_account: None,
        source_partition: None,
        partitions,
        dns_suffixes,
        dual_stack,
        region_partition,
    })
}

/// Region ids of a partition, without its `-global` pseudo-region.
fn regions(p: &Value) -> impl Iterator<Item = &String> {
    p["regions"]
        .as_object()
        .into_iter()
        .flat_map(|rs| rs.keys())
        .filter(|r| !r.ends_with("-global"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_esc_partition_facts() {
        let p = facts("eusc-de-east-1").unwrap();
        assert_eq!(p.target_partition, "aws-eusc");
        assert_eq!(p.target_dns_suffix, "amazonaws.eu");
        assert_eq!(p.target_regions, 1);
        assert!(p.is_target_suffix("amazonaws.eu"));
        assert!(!p.is_target_suffix("amazonaws.com"));
        assert_eq!(
            p.dns_suffixes["amazonaws.com"].len(),
            2,
            "aws and aws-us-gov"
        );
        assert_eq!(p.region_partition["eu-central-1"], "aws");
        assert_eq!(p.region_partition["eusc-de-east-1"], "aws-eusc");
        assert!(!p.region_partition.contains_key("aws-global"));
    }

    #[test]
    fn version_matches_the_bundled_file() {
        let v: Value = serde_json::from_str(PARTITIONS_JSON).unwrap();
        assert_eq!(
            VERSION,
            format!("botocore {}", v["botocore_version"].as_str().unwrap())
        );
    }

    #[test]
    fn unknown_target_region_is_an_input_error() {
        assert_eq!(facts("xx-nowhere-1").unwrap_err().exit_code(), 1);
    }
}
