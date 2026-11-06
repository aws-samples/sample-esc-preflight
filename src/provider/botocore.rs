//! botocore `endpoints.json` + `partitions.json`, fetched at the latest PyPI release.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::http::Client;
use crate::error::{Result, ScanError};
use crate::extractor::PartitionFacts;

const PYPI_URL: &str = "https://pypi.org/pypi/botocore/json";

#[derive(Debug, Clone)]
pub struct BotocoreData {
    pub botocore_version: String,
    pub urls: Vec<String>,
    /// Endpoint prefixes with an entry for the target region. Absence is no claim.
    pub target_services: BTreeSet<String>,
    /// Every endpoint prefix in any partition, for type-mapper validation.
    pub known_services: BTreeSet<String>,
    pub partition: PartitionFacts,
}

pub fn fetch(client: &Client, target_region: &str) -> Result<BotocoreData> {
    let version = latest_version(&client.get_text(PYPI_URL)?)?;
    let base = format!("https://raw.githubusercontent.com/boto/botocore/{version}/botocore/data");
    let endpoints_url = format!("{base}/endpoints.json");
    let partitions_url = format!("{base}/partitions.json");
    let endpoints = client.get_text(&endpoints_url)?;
    let partitions = client.get_text(&partitions_url)?;
    let mut data = parse(&version, &endpoints, &partitions, target_region)?;
    data.urls = vec![PYPI_URL.into(), endpoints_url, partitions_url];
    Ok(data)
}

pub fn latest_version(pypi_json: &str) -> Result<String> {
    let v: Value = serde_json::from_str(pypi_json)
        .map_err(|e| ScanError::DataSource(format!("PyPI response: {e}")))?;
    v.pointer("/info/version")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| ScanError::DataSource("PyPI response has no info.version".into()))
}

pub fn parse(
    version: &str,
    endpoints: &str,
    partitions: &str,
    target_region: &str,
) -> Result<BotocoreData> {
    let bad = |what: &str| ScanError::DataSource(format!("botocore {version}: {what}"));
    let endpoints: Value =
        serde_json::from_str(endpoints).map_err(|e| bad(&format!("endpoints.json: {e}")))?;
    let partitions: Value =
        serde_json::from_str(partitions).map_err(|e| bad(&format!("partitions.json: {e}")))?;
    let ep_parts = endpoints["partitions"]
        .as_array()
        .ok_or_else(|| bad("endpoints.json has no partitions"))?;
    let pt_parts = partitions["partitions"]
        .as_array()
        .ok_or_else(|| bad("partitions.json has no partitions"))?;

    let partition_of = |region: &str| -> Option<&Value> {
        pt_parts.iter().find(|p| p["regions"].get(region).is_some())
    };
    let target = partition_of(target_region)
        .ok_or_else(|| bad(&format!("unknown region {target_region}")))?;
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
    for p in pt_parts {
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

    let services_in = |region: &str| -> BTreeSet<String> {
        let Some(part) = partition_of(region).and_then(|p| p["id"].as_str()) else {
            return BTreeSet::new();
        };
        ep_parts
            .iter()
            .filter(|p| p["partition"] == part)
            .filter_map(|p| p["services"].as_object())
            .flat_map(|svcs| svcs.iter())
            .filter(|(_, s)| {
                let eps = &s["endpoints"];
                eps.get(region).is_some()
                    || (s["isRegionalized"] == false
                        && eps.as_object().is_some_and(|m| !m.is_empty()))
            })
            .map(|(name, _)| name.clone())
            .collect()
    };
    let known_services = ep_parts
        .iter()
        .filter_map(|p| p["services"].as_object())
        .flat_map(|s| s.keys().cloned())
        .collect();

    Ok(BotocoreData {
        botocore_version: version.to_string(),
        urls: Vec::new(),
        target_services: services_in(target_region),
        known_services,
        partition: PartitionFacts {
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
        },
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn fixture() -> BotocoreData {
        parse(
            crate::test_inputs::BOTOCORE_VERSION.trim(),
            include_str!("../../tests/fixtures/botocore-endpoints.json"),
            include_str!("../../tests/fixtures/botocore-partitions.json"),
            "eusc-de-east-1",
        )
        .unwrap()
    }

    #[test]
    fn reads_esc_services_and_partition_facts() {
        let d = fixture();
        assert_eq!(d.partition.target_partition, "aws-eusc");
        assert_eq!(d.partition.target_dns_suffix, "amazonaws.eu");
        assert!(d.target_services.contains("lambda"));
        assert!(d.target_services.contains("eks"));
        assert!(!d.target_services.contains("cloudfront"));
        // IAM has no aws-eusc entry: silence, not absence.
        assert!(!d.target_services.contains("iam"));
        assert!(
            d.partition
                .foreign_dns_suffixes
                .contains(&"amazonaws.com".to_string())
        );
        assert!(
            !d.partition
                .foreign_dns_suffixes
                .contains(&"amazonaws.eu".to_string())
        );
        assert!(
            d.partition
                .foreign_regions
                .contains(&"eu-central-1".to_string())
        );
        assert_eq!(
            d.partition.foreign_partitions.last().map(String::as_str),
            Some("aws")
        );
    }

    #[test]
    fn unknown_target_region_is_a_data_error() {
        let e = parse(
            "x",
            include_str!("../../tests/fixtures/botocore-endpoints.json"),
            include_str!("../../tests/fixtures/botocore-partitions.json"),
            "xx-nowhere-1",
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), 3);
    }

    #[test]
    fn pypi_version_is_read() {
        assert_eq!(
            latest_version(r#"{"info":{"version":"1.2.3"}}"#).unwrap(),
            "1.2.3"
        );
        assert_eq!(latest_version("{}").unwrap_err().exit_code(), 3);
    }
}
