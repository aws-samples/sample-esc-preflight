//! Regional availability from the AWS Knowledge MCP server (`get_regional_availability`),
//! the data behind AWS Capabilities by Region. Public, no credentials, fetched on every
//! run. Each scan asks only for what its input needs.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::http::Client;
use crate::error::{Result, ScanError};

pub const URL: &str = "https://knowledge-mcp.global.api.aws";
const TOOL: &str = "aws___get_regional_availability";
/// The server rejects more filter values per call.
const MAX_FILTERS: usize = 9;
/// Calls in flight at once. The server is rate-limited (not published; about ten calls
/// a second drew HTTP 429 on 2026-11-13), so two scans may run side by side.
const PARALLEL: usize = 2;
/// Filtered CloudFormation calls beyond this many cost more than one full dump
/// (23 pages for eusc-de-east-1 on 2026-11-13).
const FULL_CFN_PAGES: usize = 23;
const PRODUCTS_JSON: &str = include_str!("../../data/cfn-products.json");

/// What the input needs from the server.
#[derive(Debug, Default)]
pub struct Needs {
    pub types: BTreeSet<String>,
    /// SDK service ids (botocore `serviceId`), for service-level resources.
    pub services: BTreeSet<String>,
    /// `Service+Operation` keys, for SDK calls the input makes.
    pub operations: BTreeSet<String>,
    /// Config values (instance types, engine versions, node types) are needed.
    pub config: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Available,
    Planned,
    Planning,
    NotExpanding,
    NotAvailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Product {
    pub state: State,
    /// Quarter of a planned launch, e.g. `2027 Q1`.
    pub launch: Option<String>,
}

/// Everything learned from the server for one region.
#[derive(Debug, Clone, Default)]
pub struct Knowledge {
    /// CloudFormation type -> available. A type the server does not know is absent.
    pub types: BTreeMap<String, bool>,
    /// `Service+Operation` -> available.
    pub operations: BTreeMap<String, bool>,
    /// SDK service id -> any operation available.
    pub services: BTreeMap<String, bool>,
    /// Products and features by name.
    pub products: BTreeMap<String, Product>,
    /// Config values the region offers, by parent key such as
    /// `AWS::EC2::Instance::InstanceType`. Empty unless config values were needed.
    pub config: BTreeMap<String, BTreeSet<String>>,
    pub calls: usize,
    /// Filter values the server does not know.
    pub unknown: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Product,
    Api,
    Cfn,
}

impl Kind {
    fn arg(self) -> &'static str {
        match self {
            Kind::Product => "product",
            Kind::Api => "api",
            Kind::Cfn => "cfn",
        }
    }
    fn key(self) -> &'static str {
        match self {
            Kind::Product => "products",
            Kind::Api => "service_apis",
            Kind::Cfn => "cfn_resources",
        }
    }
}

/// One unit of work: a full single-region dump (no filters) or one filtered call.
struct Job {
    kind: Kind,
    filters: Vec<String>,
}

/// A finished job: the entries returned and the filter values the server did not know.
struct Done {
    job: Job,
    entries: Map,
    unknown: BTreeSet<String>,
}

/// Fetches what `needs` asks for, plus the product list, which every scan uses for
/// roadmap states. Any failure ends the scan (exit 3).
pub fn fetch(client: &Client, region: &str, needs: &Needs) -> Result<Knowledge> {
    let mut jobs = vec![Job {
        kind: Kind::Product,
        filters: Vec::new(),
    }];
    let types: Vec<String> = needs.types.iter().cloned().collect();
    if needs.config || types.len().div_ceil(MAX_FILTERS) > FULL_CFN_PAGES {
        jobs.push(Job {
            kind: Kind::Cfn,
            filters: Vec::new(),
        });
    } else {
        jobs.extend(types.chunks(MAX_FILTERS).map(|c| Job {
            kind: Kind::Cfn,
            filters: c.to_vec(),
        }));
    }
    let api: Vec<String> = needs
        .services
        .iter()
        .chain(&needs.operations)
        .cloned()
        .collect();
    jobs.extend(api.chunks(MAX_FILTERS).map(|c| Job {
        kind: Kind::Api,
        filters: c.to_vec(),
    }));

    let calls = AtomicUsize::new(0);
    let queue = Mutex::new(jobs);
    let results: Mutex<Vec<Result<Done>>> = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..PARALLEL {
            s.spawn(|| {
                loop {
                    let Some(job) = queue.lock().expect("queue lock").pop() else {
                        return;
                    };
                    let r = run(client, region, &job, &calls).map(|(entries, unknown)| Done {
                        job,
                        entries,
                        unknown,
                    });
                    let failed = r.is_err();
                    results.lock().expect("results lock").push(r);
                    if failed {
                        queue.lock().expect("queue lock").clear();
                    }
                }
            });
        }
    });

    let mut k = Knowledge {
        calls: calls.into_inner(),
        ..Knowledge::default()
    };
    for r in results.into_inner().expect("results lock") {
        let Done {
            job: Job { kind, filters },
            entries: map,
            unknown,
        } = r?;
        match kind {
            Kind::Product => k.add_products(&map),
            Kind::Cfn => k.add_types(&map),
            Kind::Api => {
                let services = filters
                    .iter()
                    .filter(|f| !f.contains('+') && !unknown.contains(*f));
                k.add_operations(&map, services);
            }
        }
        k.unknown.extend(unknown);
    }
    if k.products.len() < 100 {
        return Err(ScanError::DataSource(format!(
            "{URL}: {} products for {region}; the response shape may have changed",
            k.products.len()
        )));
    }
    Ok(k)
}

type Map = serde_json::Map<String, Value>;

/// Runs one job: a dump follows `next_token`; a filtered call drops filter values the
/// server does not know and asks again once.
fn run(
    client: &Client,
    region: &str,
    job: &Job,
    calls: &AtomicUsize,
) -> Result<(Map, BTreeSet<String>)> {
    let mut out = Map::new();
    let mut unknown = BTreeSet::new();
    let mut filters = job.filters.clone();
    let mut token: Option<String> = None;
    loop {
        let mut args = json!({"regions": [region], "resource_type": job.kind.arg()});
        if !filters.is_empty() {
            args["filters"] = json!(filters);
        }
        if let Some(t) = &token {
            args["next_token"] = json!(t);
        }
        calls.fetch_add(1, Ordering::Relaxed);
        match parse(&call(client, &args)?, job.kind)? {
            Reply::Page { entries, next } => {
                out.extend(entries);
                match next {
                    Some(t) => token = Some(t),
                    None => return Ok((out, unknown)),
                }
            }
            Reply::Unknown(values) if !values.is_empty() && unknown.is_empty() => {
                filters.retain(|f| !values.contains(f));
                unknown.extend(values);
                if filters.is_empty() {
                    return Ok((out, unknown));
                }
            }
            Reply::Unknown(values) => {
                return Err(ScanError::DataSource(format!(
                    "{URL}: unknown filter values {values:?}"
                )));
            }
            Reply::Error(m) => return Err(ScanError::DataSource(format!("{URL}: {m}"))),
        }
    }
}

fn call(client: &Client, args: &Value) -> Result<String> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": TOOL, "arguments": args},
    });
    client.post_json(URL, &body)
}

#[derive(Debug, PartialEq)]
enum Reply {
    Page {
        entries: Map,
        next: Option<String>,
    },
    /// Filter values the server does not know.
    Unknown(Vec<String>),
    Error(String),
}

fn parse(body: &str, kind: Kind) -> Result<Reply> {
    let bad = |w: String| ScanError::DataSource(format!("{URL}: {w}"));
    // A streamable-HTTP server may answer as an event stream with one data line.
    let json_text = body
        .lines()
        .find_map(|l| l.strip_prefix("data:"))
        .unwrap_or(body);
    let v: Value = serde_json::from_str(json_text.trim()).map_err(|e| bad(e.to_string()))?;
    if let Some(e) = v.get("error") {
        return Ok(Reply::Error(
            e["message"].as_str().unwrap_or("error").to_string(),
        ));
    }
    let text = v
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("no result content".into()))?;
    let inner: Value = serde_json::from_str(text).map_err(|e| bad(e.to_string()))?;
    if let Some(m) = inner["errorMessage"].as_str() {
        return Ok(match m.split_once("do not exist:") {
            Some((_, rest)) => {
                let rest = rest.split(" (did you mean").next().unwrap_or(rest);
                Reply::Unknown(
                    rest.split('\'')
                        .skip(1)
                        .step_by(2)
                        .map(str::to_string)
                        .collect(),
                )
            }
            None => Reply::Error(m.to_string()),
        });
    }
    let result = &inner["content"]["result"];
    let entries = result[kind.key()]
        .as_object()
        .cloned()
        .ok_or_else(|| bad(format!("no {} in the result", kind.key())))?;
    Ok(Reply::Page {
        entries,
        next: result["next_token"].as_str().map(str::to_string),
    })
}

fn product(v: &Value) -> Product {
    let state = match v["status"].as_str() {
        Some("isAvailableIn") => State::Available,
        Some("isPlannedIn") => State::Planned,
        Some("isBeingPlannedIn") => State::Planning,
        Some("isNotExpandingIn") => State::NotExpanding,
        _ => State::NotAvailable,
    };
    Product {
        state,
        launch: v["launch_date"].as_str().map(str::to_string),
    }
}

/// `AWS::EC2::Instance::InstanceType::m7i.large` -> (`AWS::EC2::Instance::InstanceType`,
/// `m7i.large`). A plain resource type has no parent.
fn config_parent(key: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = key.splitn(5, "::").collect();
    (parts.len() == 5).then(|| (parts[..4].join("::"), parts[4].to_string()))
}

#[derive(Deserialize)]
struct ProductMap {
    /// CloudFormation namespace -> product name, where the name does not follow from
    /// the namespace. `None`: no reliable product entry.
    namespaces: BTreeMap<String, Option<String>>,
    /// Full resource type -> product or feature name, where the feature is the precise
    /// answer.
    types: BTreeMap<String, String>,
}

fn product_map() -> &'static ProductMap {
    static MAP: std::sync::OnceLock<ProductMap> = std::sync::OnceLock::new();
    MAP.get_or_init(|| serde_json::from_str(PRODUCTS_JSON).expect("bundled product map is valid"))
}

fn norm(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

impl Knowledge {
    fn add_products(&mut self, map: &Map) {
        for (name, v) in map {
            self.products.insert(name.clone(), product(v));
        }
    }

    /// Resource types, and config values under their parent key.
    fn add_types(&mut self, map: &Map) {
        for (key, v) in map {
            let ok = v.as_str() == Some("isAvailableIn");
            match config_parent(key) {
                Some((parent, value)) if ok => {
                    self.config.entry(parent).or_default().insert(value);
                }
                Some(_) => {}
                None => {
                    self.types.insert(key.clone(), ok);
                }
            }
        }
    }

    /// `Service+Operation` entries; a service asked for is available if any of its
    /// operations is.
    fn add_operations<'a>(&mut self, map: &Map, services: impl Iterator<Item = &'a String>) {
        for id in services {
            self.services.entry(id.clone()).or_insert(false);
        }
        for (key, v) in map {
            let ok = v.as_str() == Some("isAvailableIn");
            if let Some((svc, _)) = key.split_once('+')
                && let Some(e) = self.services.get_mut(svc)
            {
                *e |= ok;
            }
            self.operations.insert(key.clone(), ok);
        }
    }

    /// The product or feature a CloudFormation type belongs to, if the server lists it.
    pub fn product_of(&self, resource_type: &str) -> Option<(&str, &Product)> {
        if let Some(name) = product_map().types.get(resource_type) {
            return self.product(name);
        }
        self.product_of_namespace(resource_type.split("::").nth(1)?)
    }

    /// The product of a CloudFormation namespace is available in the region.
    pub fn namespace_available(&self, ns: &str) -> bool {
        self.product_of_namespace(ns)
            .is_some_and(|(_, p)| p.state == State::Available)
    }

    /// The product of an SDK service, by its botocore `serviceId`.
    pub fn product_of_service(&self, service_id: &str) -> Option<(&str, &Product)> {
        self.product_of_namespace(service_id)
    }

    /// `ns` is a CloudFormation namespace or an SDK service id; both are compared
    /// without case and punctuation.
    fn product_of_namespace(&self, ns: &str) -> Option<(&str, &Product)> {
        let want = norm(ns);
        if let Some((_, name)) = product_map()
            .namespaces
            .iter()
            .find(|(k, _)| norm(k) == want)
        {
            return name.as_deref().and_then(|n| self.product(n));
        }
        self.products
            .iter()
            .find(|(name, _)| {
                let n = norm(name);
                n == want || n == format!("amazon{want}") || n == format!("aws{want}")
            })
            .map(|(k, v)| (k.as_str(), v))
    }

    fn product(&self, name: &str) -> Option<(&str, &Product)> {
        self.products
            .get_key_value(name)
            .map(|(k, v)| (k.as_str(), v))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn page(kind: Kind, entries: &str, next: Option<&str>) -> String {
        let inner = json!({"content": {"result": {
            kind.key(): serde_json::from_str::<Value>(entries).unwrap(),
            "next_token": next,
            "failed_regions": null,
        }}});
        json!({"jsonrpc": "2.0", "id": 1, "result": {"isError": false, "content": [
            {"type": "text", "text": inner.to_string()}
        ]}})
        .to_string()
    }

    /// A fixture recorded from the live server for eusc-de-east-1 on 2026-11-13.
    pub fn fixture() -> Knowledge {
        let raw: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/knowledge.json")).unwrap();
        let map = |key: &str| raw[key].as_object().unwrap().clone();
        let mut k = Knowledge::default();
        k.add_products(&map("products"));
        k.add_types(&map("cfn"));
        let services: BTreeSet<String> = map("api")
            .keys()
            .filter_map(|op| Some(op.split_once('+')?.0.to_string()))
            .collect();
        k.add_operations(&map("api"), services.iter());
        k
    }

    #[test]
    fn reads_pages_tokens_and_errors() {
        let body = page(
            Kind::Cfn,
            r#"{"AWS::Lambda::Url":"isNotAvailableIn"}"#,
            Some("t"),
        );
        let Reply::Page { entries, next } = parse(&body, Kind::Cfn).unwrap() else {
            panic!()
        };
        assert_eq!(entries["AWS::Lambda::Url"], "isNotAvailableIn");
        assert_eq!(next.as_deref(), Some("t"));
        let err = |m: &str| {
            let inner = json!({"errorMessage": m}).to_string();
            json!({"result": {"content": [{"type": "text", "text": inner}]}}).to_string()
        };
        assert_eq!(
            parse(
                &err("Error executing tool get_regional_availability: The following values in filter parameter do not exist: 'AWS::Nope::Thing', 'AWS::No::Too'"),
                Kind::Cfn
            )
            .unwrap(),
            Reply::Unknown(vec!["AWS::Nope::Thing".into(), "AWS::No::Too".into()])
        );
        assert_eq!(
            parse(
                &err("values in filter parameter do not exist: 'Bedrock' (did you mean: 'Amazon Bedrock')"),
                Kind::Product
            )
            .unwrap(),
            Reply::Unknown(vec!["Bedrock".into()])
        );
        assert!(matches!(
            parse(
                &err("Invalid filter format, too many values to filter."),
                Kind::Cfn
            )
            .unwrap(),
            Reply::Error(_)
        ));
        assert!(parse("<html>", Kind::Cfn).is_err());
        let sse = format!("event: message\ndata: {body}\n\n");
        assert!(matches!(
            parse(&sse, Kind::Cfn).unwrap(),
            Reply::Page { .. }
        ));
    }

    #[test]
    fn config_keys_and_states() {
        assert_eq!(
            config_parent("AWS::RDS::DBInstance::EngineVersion::postgres-16.4"),
            Some((
                "AWS::RDS::DBInstance::EngineVersion".into(),
                "postgres-16.4".into()
            ))
        );
        assert_eq!(config_parent("AWS::S3::Bucket"), None);
        let p = product(&json!({"status": "isPlannedIn", "launch_date": "2027 Q1"}));
        assert_eq!(p.state, State::Planned);
        assert_eq!(p.launch.as_deref(), Some("2027 Q1"));
        assert_eq!(
            product(&json!({"status": "isBeingPlannedIn"})).state,
            State::Planning
        );
    }

    #[test]
    fn maps_types_to_products() {
        let k = fixture();
        let name = |t: &str| k.product_of(t).map(|(n, _)| n.to_string());
        assert_eq!(
            name("AWS::CloudFront::Distribution").as_deref(),
            Some("Amazon CloudFront")
        );
        assert_eq!(name("AWS::Lambda::Function").as_deref(), Some("AWS Lambda"));
        assert_eq!(
            k.product_of_service("Auto Scaling").map(|(n, _)| n),
            Some("Amazon EC2 Auto Scaling")
        );
        assert_eq!(
            k.product_of_service("CloudFront").map(|(n, _)| n),
            Some("Amazon CloudFront")
        );
        assert_eq!(
            name("AWS::DynamoDB::GlobalTable").as_deref(),
            Some("Global Tables - Multi-Region Eventual Consistency")
        );
        // Every name in the bundled map exists in the recorded product list.
        let m = product_map();
        for n in m.namespaces.values().flatten().chain(m.types.values()) {
            assert!(k.products.contains_key(n), "{n} is not a product");
        }
    }

    #[test]
    fn fixture_matches_the_live_shape() {
        let k = fixture();
        assert_eq!(k.types.get("AWS::Lambda::Url"), Some(&false));
        assert_eq!(k.types.get("AWS::S3::Bucket"), Some(&true));
        assert!(
            k.config
                .get("AWS::EC2::Instance::InstanceType")
                .unwrap()
                .contains("m7i.large")
        );
        assert_eq!(k.services.get("QBusiness"), None);
        assert_eq!(k.operations.get("Lambda+CreateFunction"), Some(&true));
    }

    /// Against the real server. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn live_knowledge() {
        let client = Client::new(std::time::Duration::from_secs(60)).unwrap();
        let needs = Needs {
            types: ["AWS::S3::Bucket", "AWS::Lambda::Url", "AWS::Nope::Thing"]
                .map(String::from)
                .into(),
            services: ["Lambda", "QBusiness", "NotAService"]
                .map(String::from)
                .into(),
            operations: ["Lambda+CreateFunctionUrlConfig"].map(String::from).into(),
            config: false,
        };
        let k = fetch(&client, "eusc-de-east-1", &needs).unwrap();
        assert_eq!(k.types.get("AWS::S3::Bucket"), Some(&true));
        assert_eq!(k.types.get("AWS::Lambda::Url"), Some(&false));
        assert!(k.unknown.contains("AWS::Nope::Thing"));
        assert_eq!(k.services.get("Lambda"), Some(&true));
        assert_eq!(k.services.get("QBusiness"), Some(&false));
        assert!(k.unknown.contains("NotAService") && !k.services.contains_key("NotAService"));
        assert_eq!(
            k.operations.get("Lambda+CreateFunctionUrlConfig"),
            Some(&false)
        );
        let m = product_map();
        for n in m.namespaces.values().flatten().chain(m.types.values()) {
            assert!(k.products.contains_key(n), "{n} is no longer a product");
        }
    }
}
