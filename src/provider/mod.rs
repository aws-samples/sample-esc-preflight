//! Data sources.
//!
//! The public tier reads CloudFormation availability from the Builder Center
//! capabilities API, asks the AWS Knowledge MCP server for products and APIs (and for
//! CloudFormation when the API fails), and for ESC targets reads the ESC User Guide.
//! China, which neither covers, reads the Region's schema bundle and the AWS SDK
//! endpoint data. All are fetched on every run; Terraform input also fetches the
//! providers' type maps. Partition facts are bundled. Parsing is separated from
//! fetching so tests run offline against fixtures.

pub mod aws_call;
pub mod capabilities;
pub mod china;
pub mod guide;
pub mod http;
pub mod knowledge;
pub mod live;
pub mod partition;
pub mod schema;
pub mod terraform;

use crate::error::Result;
use crate::extractor::PartitionFacts;

/// Everything the public tier knows after one fetch.
#[derive(Debug, Clone)]
pub struct PublicData {
    pub partition: PartitionFacts,
    pub knowledge: knowledge::Knowledge,
    /// Where services and APIs, CloudFormation types and config values, and products
    /// came from (none for China); `None` without availability data.
    pub urls: Option<(String, String, Option<String>)>,
    /// China: the Region's schema bundle as downloaded, for property checks.
    pub bundle: Option<(String, Vec<u8>)>,
    /// The ESC User Guide service pages; `None` outside its partition.
    pub guide: Option<guide::GuideData>,
    /// `None` unless the input is a Terraform plan.
    pub tf: Option<terraform::TfMaps>,
}

/// Fetches the availability data (without `needs`, none: the sources have no data for
/// the target) and, in the ESC partition, the guide, in parallel. Any failure other
/// than the capabilities API's is a data-source failure (exit 3).
pub fn fetch_public(
    client: &http::Client,
    target_region: &str,
    partition: PartitionFacts,
    tf: Option<terraform::TfMaps>,
    needs: Option<&knowledge::Needs>,
) -> Result<PublicData> {
    let esc = partition.target_partition == guide::PARTITION;
    let china = partition.target_partition == china::PARTITION;
    let (fetched, guide) = std::thread::scope(|s| {
        let g = s.spawn(|| esc.then(|| guide::fetch(client)).transpose());
        let k = needs
            .map(|n| -> Result<_> {
                if china {
                    let c = china::fetch(client, &partition, Some(n))?;
                    return Ok((
                        c.knowledge,
                        (china::ENDPOINTS_URL.to_string(), c.bundle_url.clone(), None),
                        c.bundle.map(|b| (c.bundle_url, b)),
                    ));
                }
                let Availability {
                    mut regions,
                    cfn_url,
                    products_url,
                } = availability(client, &[target_region], n)?;
                Ok((
                    regions.remove(0),
                    (
                        knowledge::URL.to_string(),
                        cfn_url.to_string(),
                        Some(products_url.to_string()),
                    ),
                    None,
                ))
            })
            .transpose();
        (k, g.join().expect("guide fetch does not panic"))
    });
    let (knowledge, urls, bundle) = match fetched? {
        Some((k, urls, bundle)) => (k, Some(urls), bundle),
        None => (knowledge::Knowledge::default(), None, None),
    };
    Ok(PublicData {
        partition,
        knowledge,
        urls,
        bundle,
        guide: guide?,
        tf,
    })
}

/// Availability data for several Regions.
#[derive(Debug)]
pub struct Availability {
    /// In the order the Regions were asked for.
    pub regions: Vec<knowledge::Knowledge>,
    /// Where the CloudFormation types and config values came from.
    pub cfn_url: &'static str,
    /// Where the product states came from: the capabilities API with the Knowledge
    /// MCP server, or the Knowledge MCP server alone.
    pub products_url: &'static str,
}

/// CloudFormation types, config values and products from the capabilities API, one
/// download each for all `regions`; APIs, the not-expanding state and products only it
/// lists from the Knowledge MCP server; all in parallel. When the API fails, the
/// Knowledge MCP server answers alone.
pub fn availability(
    client: &http::Client,
    regions: &[&str],
    needs: &knowledge::Needs,
) -> Result<Availability> {
    use knowledge::Parts;
    let (cfn, products, rest) = std::thread::scope(|s| {
        let cfn = s.spawn(|| capabilities::fetch_cfn(client, regions));
        let products = s.spawn(|| capabilities::fetch_products(client, regions));
        let rest: Vec<_> = regions
            .iter()
            .map(|r| s.spawn(move || knowledge::fetch(client, r, needs, Parts::Lean)))
            .collect();
        let rest: Vec<_> = rest
            .into_iter()
            .map(|h| h.join().expect("Knowledge MCP fetch does not panic"))
            .collect();
        let join = "capabilities fetch does not panic";
        (cfn.join().expect(join), products.join().expect(join), rest)
    });
    let mut out = rest.into_iter().collect::<Result<Vec<_>>>()?;
    let products_url = match products {
        Ok(mut p) => {
            for (k, r) in out.iter_mut().zip(regions) {
                k.add_products_from(p.remove(*r).unwrap_or_default());
            }
            capabilities::URL
        }
        Err(e) => {
            crate::tui::note(&format!(
                "esc-preflight: {e}; reading products from the AWS Knowledge MCP server only"
            ));
            knowledge::URL
        }
    };
    match cfn {
        Ok(mut cfn) => {
            for (k, r) in out.iter_mut().zip(regions) {
                k.add_cfn(cfn.remove(*r).unwrap_or_default(), needs);
            }
            Ok(Availability {
                regions: out,
                cfn_url: capabilities::URL,
                products_url,
            })
        }
        Err(e) => {
            crate::tui::note(&format!(
                "esc-preflight: {e}; reading CloudFormation availability from the AWS Knowledge MCP server"
            ));
            for (k, r) in out.iter_mut().zip(regions) {
                let c = knowledge::fetch(client, r, needs, Parts::CfnOnly)?;
                k.types.extend(c.types);
                k.config = c.config;
                k.mark_unknown_types(needs);
            }
            Ok(Availability {
                regions: out,
                cfn_url: knowledge::URL,
                products_url,
            })
        }
    }
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
            Some(&needs),
        )
        .unwrap();
        assert_eq!(d.knowledge.types.get("AWS::Lambda::Function"), Some(&true));
        let g = d.guide.as_ref().unwrap();
        let unmapped = guide::unmapped(g);
        assert!(unmapped.is_empty(), "{unmapped:?}");
    }
}
