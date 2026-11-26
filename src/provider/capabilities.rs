//! CloudFormation availability from the AWS Builder Center capabilities API, the data
//! behind builder.aws.com/build/capabilities. Public, no credentials. One page holds
//! every resource type and config value for several Regions at once, which the
//! Knowledge MCP server needs about 24 pages per Region for.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use super::http::Client;
use crate::error::{Result, ScanError};

pub const URL: &str = "https://prod.capabilities.builder.aws.com";
const CFN_ROUTE: &str = "/cloudformation-availability";
const SERVICES_ROUTE: &str = "/services-availability";
/// The largest page the API serves with a `regions` filter (2026-11-24: 5,482 items).
const PAGE: usize = 10_000;
/// More pages than this means the paging changed.
const MAX_PAGES: usize = 20;
/// Fewer available types than this for a listed Region: the response shape changed.
const MIN_TYPES: usize = 300;

/// CloudFormation types and config values for one Region.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cfn {
    /// Resource type -> available. A type without an entry for the Region is absent.
    pub types: BTreeMap<String, bool>,
    /// Available config values by parent key such as `AWS::EC2::Instance::InstanceType`.
    pub config: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    items: Vec<Item>,
    next_token: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    name: String,
    parent_id: Option<String>,
    #[serde(default)]
    available: Vec<Named>,
    #[serde(default)]
    not_available: Vec<Named>,
    #[serde(default)]
    planned: Vec<Named>,
    #[serde(default)]
    planning: Vec<Named>,
}

#[derive(Clone, Deserialize)]
struct Named {
    name: String,
    #[serde(rename = "plannedDate")]
    planned_date: Option<String>,
}

/// A product's or feature's state in one Region, with the planned quarter.
pub type ProductState = (super::knowledge::State, Option<String>);

/// The products and features of one Region.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Products {
    /// By name. A feature name several services list with different states, in any
    /// of the Regions fetched together, is also listed per service as
    /// `<service>: <feature>`, since each service's state is right for that service.
    pub products: BTreeMap<String, ProductState>,
    /// Every feature by its service and name.
    pub features: BTreeMap<(String, String), ProductState>,
    /// Bare names that stand for such features of several services, with the most
    /// available state: a lookup by name finds the feature where some service
    /// offers it, and `compare` reads the per-service entries instead.
    pub merged: BTreeSet<String>,
}

/// Products and features for each of `regions`.
pub fn fetch_products(client: &Client, regions: &[&str]) -> Result<BTreeMap<String, Products>> {
    products_of(&items_at(client, SERVICES_ROUTE, regions)?, regions)
}

/// One listing of a name: its parent service, whether it is a service, its state.
type Listing<'a> = (Option<&'a str>, bool, ProductState);

fn rank(s: super::knowledge::State) -> u8 {
    use super::knowledge::State;
    match s {
        State::Available => 0,
        State::Planned => 1,
        State::Planning => 2,
        State::NotExpanding => 3,
        State::NotAvailable => 4,
    }
}

/// Keeps the more available of two states, so the result does not depend on order.
fn keep_best(map: &mut BTreeMap<String, ProductState>, key: String, state: ProductState) {
    match map.get(&key) {
        Some(old) if rank(old.0) <= rank(state.0) => {}
        _ => {
            map.insert(key, state);
        }
    }
}

fn products_of(items: &[Item], regions: &[&str]) -> Result<BTreeMap<String, Products>> {
    use super::knowledge::State;
    let names: BTreeMap<&str, &str> = items
        .iter()
        .map(|i| (i.id.as_str(), i.name.trim()))
        .collect();
    let listings = |region: &str| {
        let state_of = |item: &Item| -> Option<ProductState> {
            let find = |l: &[Named]| {
                l.iter()
                    .find(|n| n.name == region)
                    .map(|n| n.planned_date.clone())
            };
            if find(&item.available).is_some() {
                Some((State::Available, None))
            } else if let Some(d) = find(&item.planned) {
                Some((State::Planned, d))
            } else if find(&item.planning).is_some() {
                Some((State::Planning, None))
            } else {
                find(&item.not_available).map(|_| (State::NotAvailable, None))
            }
        };
        let mut by_name: BTreeMap<&str, Vec<Listing>> = BTreeMap::new();
        for item in items {
            if let Some(state) = state_of(item) {
                let parent = item
                    .parent_id
                    .as_deref()
                    .and_then(|id| names.get(id).copied());
                by_name.entry(item.name.trim()).or_default().push((
                    parent,
                    item.kind == "SERVICE",
                    state,
                ));
            }
        }
        by_name
    };
    let by_region: Vec<_> = regions.iter().map(|r| (*r, listings(r))).collect();
    // One decision for all Regions, so `compare` matches names across them.
    let split: BTreeSet<&str> = by_region
        .iter()
        .flat_map(|(_, by_name)| by_name.iter())
        .filter(|(_, l)| l.iter().any(|(.., s)| s.0 != l[0].2.0))
        .map(|(name, _)| *name)
        .collect();
    let mut out = BTreeMap::new();
    for (region, by_name) in by_region {
        let mut p = Products::default();
        for (name, entries) in by_name {
            let has_service = entries.iter().any(|(_, service, _)| *service);
            if split.contains(name) && !has_service {
                p.merged.insert(name.to_string());
            }
            for (parent, service, state) in entries {
                if let (false, Some(parent)) = (service, parent) {
                    p.features
                        .insert((parent.to_string(), name.to_string()), state.clone());
                    if split.contains(name) {
                        keep_best(&mut p.products, format!("{parent}: {name}"), state.clone());
                    }
                }
                // A service of the name decides the bare name.
                if service || !has_service {
                    keep_best(&mut p.products, name.to_string(), state);
                }
            }
        }
        if p.products.len() < 100 {
            return Err(ScanError::DataSource(format!(
                "{URL}{SERVICES_ROUTE}: {} products for {region}; the response shape may have changed",
                p.products.len()
            )));
        }
        out.insert(region.to_string(), p);
    }
    Ok(out)
}

/// One dump for `regions`, split by Region. Any failure or an unexpected shape is an
/// error; the caller falls back to the Knowledge MCP server.
pub fn fetch_cfn(client: &Client, regions: &[&str]) -> Result<BTreeMap<String, Cfn>> {
    split(items(client, regions)?.into_iter(), regions)
}

/// Every resource type the API knows, in any Region. The availability lists are
/// read for one Region only, to keep the download small.
pub fn known_types(client: &Client) -> Result<BTreeSet<String>> {
    let out: BTreeSet<String> = items(client, &["us-east-1"])?
        .into_iter()
        .filter(|i| i.kind == "type")
        .map(|i| i.id)
        .collect();
    if out.len() < MIN_TYPES {
        return Err(ScanError::DataSource(format!(
            "{URL}{CFN_ROUTE}: {} types; the response shape may have changed",
            out.len()
        )));
    }
    Ok(out)
}

fn items(client: &Client, regions: &[&str]) -> Result<Vec<Item>> {
    items_at(client, CFN_ROUTE, regions)
}

fn items_at(client: &Client, route: &str, regions: &[&str]) -> Result<Vec<Item>> {
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let body = client.get_text(&page_url(route, regions, token.as_deref()))?;
        let page: Page = serde_json::from_str(&body)
            .map_err(|e| ScanError::DataSource(format!("{URL}{route}: {e}")))?;
        token = page.next_token.filter(|t| !t.is_empty());
        out.extend(page.items);
        if token.is_none() {
            return Ok(out);
        }
    }
    Err(ScanError::DataSource(format!(
        "{URL}{route}: more than {MAX_PAGES} pages"
    )))
}

/// Several Regions are repeated `regions` parameters; a comma list matches none.
fn page_url(route: &str, regions: &[&str], token: Option<&str>) -> String {
    let page = PAGE.to_string();
    let mut q = vec![("maxResults", page.as_str()), ("sortOrder", "asc")];
    q.extend(regions.iter().map(|r| ("regions", *r)));
    q.extend(token.map(|t| ("nextToken", t)));
    reqwest::Url::parse_with_params(&format!("{URL}{route}"), q)
        .expect("constant base URL")
        .into()
}

fn split(items: impl Iterator<Item = Item>, regions: &[&str]) -> Result<BTreeMap<String, Cfn>> {
    let mut out: BTreeMap<String, Cfn> = regions
        .iter()
        .map(|r| ((*r).to_string(), Cfn::default()))
        .collect();
    for item in items {
        let has = |list: &[Named], r: &str| list.iter().any(|n| n.name == r);
        for (region, cfn) in &mut out {
            let ok = has(&item.available, region);
            let known = ok
                || has(&item.not_available, region)
                || has(&item.planned, region)
                || has(&item.planning, region);
            if !known {
                continue;
            }
            match item.kind.as_str() {
                "type" => {
                    cfn.types.insert(item.id.clone(), ok);
                }
                "config" if ok => {
                    if let Some((parent, value)) = config_value(&item) {
                        cfn.config.entry(parent).or_default().insert(value);
                    }
                }
                _ => {}
            }
        }
    }
    for (region, cfn) in &out {
        let available = cfn.types.values().filter(|ok| **ok).count();
        if available < MIN_TYPES {
            return Err(ScanError::DataSource(format!(
                "{URL}{CFN_ROUTE}: {available} available types for {region}; the response shape may have changed"
            )));
        }
    }
    Ok(out)
}

/// `AWS::EC2::Instance::InstanceType::m7i.large` under parent
/// `AWS::EC2::Instance::InstanceType` -> (parent, `m7i.large`).
fn config_value(item: &Item) -> Option<(String, String)> {
    let parent = item.parent_id.as_deref()?;
    let value = item.id.strip_prefix(parent)?.strip_prefix("::")?;
    (!value.is_empty()).then(|| (parent.to_string(), value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, kind: &str, parent: Option<&str>, available: &[&str], not: &[&str]) -> Item {
        let named = |l: &[&str]| {
            l.iter()
                .map(|n| Named {
                    name: (*n).to_string(),
                    planned_date: None,
                })
                .collect()
        };
        Item {
            id: id.into(),
            kind: kind.into(),
            name: String::new(),
            parent_id: parent.map(str::to_string),
            available: named(available),
            not_available: named(not),
            planned: Vec::new(),
            planning: Vec::new(),
        }
    }

    fn filler(region: &str) -> impl Iterator<Item = Item> {
        (0..MIN_TYPES).map(move |i| item(&format!("AWS::F::T{i}"), "type", None, &[region], &[]))
    }

    #[test]
    fn splits_types_and_config_by_region() {
        let items = vec![
            item("AWS::S3::Bucket", "type", Some("AWS::S3"), &["a", "b"], &[]),
            item("AWS::Q::App", "type", Some("AWS::Q"), &["a"], &["b"]),
            item("AWS::X::Y", "type", Some("AWS::X"), &["a"], &[]),
            item("AWS::S3", "Service", None, &[], &[]),
            item(
                "AWS::EC2::Instance::InstanceType::m7i.large",
                "config",
                Some("AWS::EC2::Instance::InstanceType"),
                &["a"],
                &["b"],
            ),
            item(
                "AWS::EC2::Instance::InstanceType",
                "property",
                Some("AWS::EC2::Instance"),
                &["a", "b"],
                &[],
            ),
        ];
        let all = items.into_iter().chain(filler("a")).chain(filler("b"));
        let out = split(all, &["a", "b"]).unwrap();
        let (a, b) = (&out["a"], &out["b"]);
        assert_eq!(a.types.get("AWS::Q::App"), Some(&true));
        assert_eq!(b.types.get("AWS::Q::App"), Some(&false));
        // No entry for the Region: absent, not unavailable.
        assert_eq!(b.types.get("AWS::X::Y"), None);
        assert!(!a.types.contains_key("AWS::S3"));
        assert!(a.config["AWS::EC2::Instance::InstanceType"].contains("m7i.large"));
        assert!(!b.config.contains_key("AWS::EC2::Instance::InstanceType"));
        assert!(!a.types.contains_key("AWS::EC2::Instance::InstanceType"));
    }

    #[test]
    fn products_by_name_with_quarter_and_conflicts() {
        use super::super::knowledge::State;
        let named = |n: &str, d: Option<&str>| Named {
            name: n.into(),
            planned_date: d.map(String::from),
        };
        let mut items: Vec<Item> = (0..100)
            .map(|i| Item {
                name: format!("P{i}"),
                ..item(&format!("p{i}"), "SERVICE", None, &["a"], &[])
            })
            .collect();
        let mut planned = item("x", "FEATURE", Some("p0"), &[], &[]);
        planned.name = " Edge ".into();
        planned.planned = vec![named("a", Some("2027 Q1"))];
        // One feature under two services, with different states.
        let mut dup1 = item("d1", "FEATURE", Some("p1"), &[], &["a"]);
        dup1.name = "Dup".into();
        let mut dup2 = item("d2", "FEATURE", Some("p2"), &["a"], &[]);
        dup2.name = "Dup".into();
        // A service and a feature of the same name: the service keeps the bare name.
        let mut svc = item("s", "SERVICE", None, &["a"], &[]);
        svc.name = "Both".into();
        let mut feat = item("f", "FEATURE", Some("p3"), &[], &["a"]);
        feat.name = "Both".into();
        // Equal states stay one bare entry.
        let mut same1 = item("e1", "FEATURE", Some("p1"), &["a"], &[]);
        same1.name = "Same".into();
        let mut same2 = item("e2", "FEATURE", Some("p2"), &["a"], &[]);
        same2.name = "Same".into();
        items.extend([planned, dup1, dup2, feat, svc, same1, same2]);
        let out = &products_of(&items, &["a"]).unwrap()["a"];
        let p = &out.products;
        assert_eq!(p["Edge"], (State::Planned, Some("2027 Q1".to_string())));
        assert_eq!(p["Dup"], (State::Available, None), "the most available");
        assert_eq!(p["P1: Dup"], (State::NotAvailable, None));
        assert_eq!(p["P2: Dup"], (State::Available, None));
        assert_eq!(p["Both"], (State::Available, None));
        assert_eq!(p["P3: Both"], (State::NotAvailable, None));
        assert_eq!(p["Same"], (State::Available, None));
        assert!(!p.contains_key("P1: Same"));
        assert_eq!(out.merged, ["Dup".to_string()].into());
        assert_eq!(
            out.features[&("P0".to_string(), "Edge".to_string())].0,
            State::Planned
        );
        // A name split in one Region is split in every Region fetched with it.
        let mut two = items.clone();
        for i in two.iter_mut() {
            i.available.push(Named {
                name: "b".into(),
                planned_date: None,
            });
        }
        let both = products_of(&two, &["a", "b"]).unwrap();
        assert!(both["b"].products.contains_key("P1: Dup"));
        assert_eq!(both["b"].merged, ["Dup".to_string()].into());
        assert!(products_of(&items[..5], &["a"]).is_err());
    }

    #[test]
    fn too_few_types_is_a_shape_change() {
        let items = vec![item("AWS::S3::Bucket", "type", None, &["a"], &[])];
        assert!(split(items.into_iter(), &["a"]).is_err());
    }

    #[test]
    fn repeats_the_regions_parameter() {
        assert_eq!(
            page_url(CFN_ROUTE, &["eu-west-1", "eusc-de-east-1"], Some("a+b/=")),
            format!(
                "{URL}{CFN_ROUTE}?maxResults=10000&sortOrder=asc&regions=eu-west-1&regions=eusc-de-east-1&nextToken=a%2Bb%2F%3D"
            )
        );
    }

    #[test]
    fn parses_a_page() {
        let body = r#"{"items":[{"available":[{"name":"r"}],"id":"AWS::A::B","name":"B","notAvailable":[],"parentId":"AWS::A","planned":[],"planning":[],"type":"type"}],"nextToken":null,"totalCount":1}"#;
        let p: Page = serde_json::from_str(body).unwrap();
        assert_eq!(p.items.len(), 1);
        assert!(p.next_token.is_none());
    }

    /// Hits the real API. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn live_dump_two_regions() {
        let client = Client::new(std::time::Duration::from_secs(60)).unwrap();
        let out = fetch_cfn(&client, &["eusc-de-east-1", "eu-west-1"]).unwrap();
        assert_eq!(
            out["eusc-de-east-1"].types.get("AWS::Lambda::Function"),
            Some(&true)
        );
        assert!(out["eu-west-1"].config["AWS::EC2::Instance::InstanceType"].contains("m7i.large"));
    }
}
