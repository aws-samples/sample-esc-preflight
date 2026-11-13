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
    let target_suffixes = [
        &target["outputs"]["dnsSuffix"],
        &target["outputs"]["dualStackDnsSuffix"],
    ];
    let mut foreign_partitions = Vec::new();
    let mut foreign_dns = BTreeSet::new();
    let mut foreign_regions = BTreeSet::new();
    let mut region_partition = BTreeMap::new();
    let mut partition_dns: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for p in parts {
        let id = p["id"].as_str().unwrap_or_default();
        if id == target_id {
            continue;
        }
        foreign_partitions.push(id.to_string());
        for key in ["dnsSuffix", "dualStackDnsSuffix"] {
            if let Some(s) = p["outputs"][key].as_str()
                && !target_suffixes.iter().any(|t| t.as_str() == Some(s))
            {
                foreign_dns.insert(s.to_string());
                partition_dns
                    .entry(id.to_string())
                    .or_default()
                    .push(s.to_string());
            }
        }
        if let Some(rs) = p["regions"].as_object() {
            for r in rs.keys().filter(|r| !r.ends_with("-global")) {
                foreign_regions.insert(r.clone());
                region_partition.insert(r.clone(), id.to_string());
            }
        }
    }
    // Longest first so `arn:aws-cn:` is matched before `arn:aws:` would be.
    foreign_partitions.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
    Ok(PartitionFacts {
        target_partition: target_id,
        target_dns_suffix: target["outputs"]["dnsSuffix"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        foreign_partitions,
        foreign_dns_suffixes: foreign_dns.into_iter().collect(),
        foreign_regions: foreign_regions.into_iter().collect(),
        region_partition,
        partition_dns,
        target_regions: target["regions"].as_object().map_or(0, |rs| {
            rs.keys().filter(|r| !r.ends_with("-global")).count()
        }),
    })
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
        assert!(
            p.foreign_dns_suffixes
                .contains(&"amazonaws.com".to_string())
        );
        assert!(!p.foreign_dns_suffixes.contains(&"amazonaws.eu".to_string()));
        assert!(p.foreign_regions.contains(&"eu-central-1".to_string()));
        assert_eq!(p.foreign_partitions.last().map(String::as_str), Some("aws"));
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
