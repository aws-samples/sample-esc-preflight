//! Data sources.
//!
//! The public tier fetches botocore's endpoint data (latest PyPI release) and the
//! regional table, for ESC targets also the ESC endpoints page and the ESC User Guide,
//! and for Terraform input the providers' type maps, live on every run. Parsing is
//! separated from fetching so tests run offline against fixtures.

pub mod aws_call;
pub mod botocore;
pub mod endpoints_page;
pub mod guide;
pub mod http;
pub mod live;
pub mod regional_table;
pub mod terraform;

use crate::error::Result;

/// Everything the public tier knows after one fetch.
#[derive(Debug, Clone)]
pub struct PublicData {
    pub botocore: botocore::BotocoreData,
    pub regional_table: regional_table::RegionalTableData,
    /// `None` when the target is outside the partition the endpoints page covers.
    pub endpoints_page: Option<endpoints_page::EndpointsPageData>,
    /// The ESC User Guide service pages; `None` outside its partition.
    pub guide: Option<guide::GuideData>,
    /// `None` unless the input is a Terraform plan.
    pub tf: Option<terraform::TfMaps>,
}

/// Fetches every source the input needs. Any failure is a data-source failure (exit 3),
/// never a fallback.
pub fn fetch_public(
    client: &http::Client,
    target_region: &str,
    terraform: bool,
) -> Result<PublicData> {
    let botocore = botocore::fetch(client, target_region)?;
    let regional_table = regional_table::fetch(client, target_region)?;
    let esc = botocore.partition.target_partition == endpoints_page::PARTITION;
    Ok(PublicData {
        endpoints_page: esc
            .then(|| endpoints_page::fetch(client, target_region))
            .transpose()?,
        guide: esc.then(|| guide::fetch(client)).transpose()?,
        tf: terraform.then(|| terraform::fetch(client)).transpose()?,
        botocore,
        regional_table,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hits the real public sources. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn live_public_fetch() {
        let client = http::Client::new(std::time::Duration::from_secs(30)).unwrap();
        let d = fetch_public(&client, "eusc-de-east-1", true).unwrap();
        assert_eq!(d.botocore.partition.target_partition, "aws-eusc");
        assert!(d.botocore.target_services.len() > 50);
        assert!(d.regional_table.target_services.len() > 50);
        assert!(d.endpoints_page.as_ref().unwrap().target_services.len() > 100);
        assert!(
            d.regional_table.unmapped_names.is_empty(),
            "{:?}",
            d.regional_table.unmapped_names
        );
        let g = d.guide.as_ref().unwrap();
        assert!(g.documents("lambda") && !g.documents("cloudfront"));
        assert!(g.unmapped.is_empty(), "{:?}", g.unmapped);
        let tf = d.tf.as_ref().unwrap();
        assert_eq!(
            tf.aws_service_id("aws_lb"),
            Some("Elastic Load Balancing v2")
        );
    }
}
