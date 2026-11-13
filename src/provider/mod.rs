//! Data sources.
//!
//! The public tier asks the AWS Knowledge MCP server for what the input needs, and for
//! ESC targets reads the ESC User Guide, both live on every run; Terraform input also
//! fetches the providers' type maps. Partition facts are bundled. Parsing is separated
//! from fetching so tests run offline against fixtures.

pub mod aws_call;
pub mod guide;
pub mod http;
pub mod knowledge;
pub mod live;
pub mod partition;
pub mod terraform;

use crate::error::Result;
use crate::extractor::PartitionFacts;

/// Everything the public tier knows after one fetch.
#[derive(Debug, Clone)]
pub struct PublicData {
    pub partition: PartitionFacts,
    pub knowledge: knowledge::Knowledge,
    /// The ESC User Guide service pages; `None` outside its partition.
    pub guide: Option<guide::GuideData>,
    /// `None` unless the input is a Terraform plan.
    pub tf: Option<terraform::TfMaps>,
}

/// Fetches the Knowledge MCP data and, in the ESC partition, the guide, in parallel.
/// Any failure is a data-source failure (exit 3), never a fallback.
pub fn fetch_public(
    client: &http::Client,
    target_region: &str,
    partition: PartitionFacts,
    tf: Option<terraform::TfMaps>,
    needs: &knowledge::Needs,
) -> Result<PublicData> {
    let esc = partition.target_partition == guide::PARTITION;
    let (knowledge, guide) = std::thread::scope(|s| {
        let g = s.spawn(|| esc.then(|| guide::fetch(client)).transpose());
        let k = knowledge::fetch(client, target_region, needs);
        (k, g.join().expect("guide fetch does not panic"))
    });
    Ok(PublicData {
        partition,
        knowledge: knowledge?,
        guide: guide?,
        tf,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hits the real public sources. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn live_public_fetch() {
        let client = http::Client::new(std::time::Duration::from_secs(60)).unwrap();
        let tf = terraform::fetch(&client).unwrap();
        assert_eq!(
            tf.aws_service_id("aws_lb"),
            Some("Elastic Load Balancing v2")
        );
        let needs = knowledge::Needs {
            types: ["AWS::Lambda::Function".to_string()].into(),
            ..knowledge::Needs::default()
        };
        let d = fetch_public(
            &client,
            "eusc-de-east-1",
            partition::facts("eusc-de-east-1").unwrap(),
            Some(tf),
            &needs,
        )
        .unwrap();
        assert_eq!(d.knowledge.types.get("AWS::Lambda::Function"), Some(&true));
        let g = d.guide.as_ref().unwrap();
        assert!(g.unmapped.is_empty(), "{:?}", g.unmapped);
    }
}
