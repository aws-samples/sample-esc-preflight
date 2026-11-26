//! Regional availability from the AWS Knowledge MCP server (`get_regional_availability`),
//! the data behind AWS Capabilities by Region. Public, no credentials, fetched on every
//! run. Each scan asks only for what its input needs.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::http::Client;
use crate::error::{Result, ScanError};

pub const URL: &str = "https://knowledge-mcp.global.api.aws";
const TOOL: &str = "aws___get_regional_availability";
/// The server answers `get_regional_availability` for any region id, with every
/// CloudFormation type `Not Found` where it has no data; only this list tells.
const REGIONS_TOOL: &str = "aws___list_regions";
/// The server rejects more filter values per call.
const MAX_FILTERS: usize = 9;
/// Calls in flight at most. The server is rate-limited (not published): on 2026-11-24
/// eight calls at once were answered, sixteen drew HTTP 429.
const PARALLEL: usize = 8;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
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
    /// Features by their service and name, from the capabilities API; empty when it
    /// failed and for AWS China.
    pub features: BTreeMap<(String, String), Product>,
    /// Names that stand for one feature of several services with different states;
    /// `compare` reads their `<service>: <feature>` entries instead.
    pub merged: BTreeSet<String>,
    /// Config values the region offers, by parent key such as
    /// `AWS::EC2::Instance::InstanceType`. Empty unless config values were needed.
    pub config: BTreeMap<String, BTreeSet<String>>,
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

/// What one [`fetch`] asks the server for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parts {
    /// Products, APIs, and the input's types in filtered calls where few enough; the
    /// rest of CloudFormation comes from the capabilities API.
    Lean,
    /// The full CloudFormation dump where `Lean` does not cover the input (config
    /// values, or too many types), when the capabilities API failed.
    CfnOnly,
}

/// Fetches the `parts` of what `needs` asks for; products are the full list, which
/// every scan uses for roadmap states. Any failure ends the scan (exit 3).
pub fn fetch(client: &Client, region: &str, needs: &Needs, parts: Parts) -> Result<Knowledge> {
    run_jobs(client, region, jobs(needs, parts), parts)
}

/// The calls a [`fetch`] makes.
fn jobs(needs: &Needs, parts: Parts) -> Vec<Job> {
    let mut jobs = Vec::new();
    if parts != Parts::CfnOnly {
        jobs.push(Job {
            kind: Kind::Product,
            filters: Vec::new(),
        });
    }
    let types: Vec<String> = needs.types.iter().cloned().collect();
    let many = types.len().div_ceil(MAX_FILTERS) > FULL_CFN_PAGES;
    match parts {
        Parts::Lean if !many => jobs.extend(types.chunks(MAX_FILTERS).map(|c| Job {
            kind: Kind::Cfn,
            filters: c.to_vec(),
        })),
        Parts::CfnOnly if needs.config || many => jobs.push(Job {
            kind: Kind::Cfn,
            filters: Vec::new(),
        }),
        _ => {}
    }
    if parts != Parts::CfnOnly {
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
    }
    jobs
}

/// Runs `jobs`, up to [`PARALLEL`] at once.
fn run_jobs(client: &Client, region: &str, jobs: Vec<Job>, parts: Parts) -> Result<Knowledge> {
    let queue = Mutex::new(jobs);
    let results: Mutex<Vec<Result<Done>>> = Mutex::new(Vec::new());
    let (q, done) = (&queue, &results);
    std::thread::scope(|s| {
        for worker in 0..PARALLEL {
            s.spawn(move || {
                loop {
                    if worker >= in_flight(client.throttled()) {
                        return;
                    }
                    let Some(job) = q.lock().expect("queue lock").pop() else {
                        return;
                    };
                    let r = run(client, region, &job).map(|(entries, unknown)| Done {
                        job,
                        entries,
                        unknown,
                    });
                    let failed = r.is_err();
                    done.lock().expect("results lock").push(r);
                    if failed {
                        q.lock().expect("queue lock").clear();
                    }
                }
            });
        }
    });

    let mut k = Knowledge::default();
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
    if parts != Parts::CfnOnly && k.products.len() < 100 {
        return Err(ScanError::DataSource(format!(
            "{URL}: {} products for {region}; the response shape may have changed",
            k.products.len()
        )));
    }
    Ok(k)
}

/// Calls in flight after `throttled` HTTP 429 answers: halved for each, at least one.
fn in_flight(throttled: u32) -> usize {
    (PARALLEL >> throttled.min(usize::BITS - 1)).max(1)
}

type Map = serde_json::Map<String, Value>;

/// Runs one job: a dump follows `next_token`; a filtered call drops filter values the
/// server does not know and asks again once.
fn run(client: &Client, region: &str, job: &Job) -> Result<(Map, BTreeSet<String>)> {
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
        match parse(&call_tool(client, TOOL, &args)?, job.kind)? {
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

fn call_tool(client: &Client, tool: &str, args: &Value) -> Result<String> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    });
    client.post_json(URL, &body)
}

/// The error for a Region the server has no data for, without live mode.
pub fn unlisted(region: &str) -> String {
    format!(
        "no public availability data covers {region}; run in live mode with --profile <name> or --role-arn <arn>"
    )
}

/// The region ids the server has data for.
pub fn regions(client: &Client) -> Result<BTreeSet<String>> {
    parse_regions(&call_tool(client, REGIONS_TOOL, &json!({}))?)
}

fn parse_regions(body: &str) -> Result<BTreeSet<String>> {
    let inner = tool_text(body)?;
    let out: BTreeSet<String> = inner["content"]["result"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["region_id"].as_str().map(str::to_string))
        .collect();
    if out.is_empty() {
        return Err(ScanError::DataSource(format!(
            "{URL}: no regions listed; the response shape may have changed"
        )));
    }
    Ok(out)
}

/// The JSON a tool returned as text, from a JSON or event-stream reply.
fn tool_text(body: &str) -> Result<Value> {
    envelope(body)?.map_err(|m| ScanError::DataSource(format!("{URL}: {m}")))
}

/// The JSON a tool returned as text, or the message of a JSON-RPC error.
fn envelope(body: &str) -> Result<std::result::Result<Value, String>> {
    let bad = |w: String| ScanError::DataSource(format!("{URL}: {w}"));
    // A streamable-HTTP server may answer as an event stream with one data line.
    let json_text = body
        .lines()
        .find_map(|l| l.strip_prefix("data:"))
        .unwrap_or(body);
    let v: Value = serde_json::from_str(json_text.trim()).map_err(|e| bad(e.to_string()))?;
    if let Some(e) = v.get("error") {
        return Ok(Err(e["message"].as_str().unwrap_or("error").to_string()));
    }
    let text = v
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("no result content".into()))?;
    serde_json::from_str(text)
        .map(Ok)
        .map_err(|e| bad(e.to_string()))
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
    let inner = match envelope(body)? {
        Ok(v) => v,
        Err(m) => return Ok(Reply::Error(m)),
    };
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
        .ok_or_else(|| ScanError::DataSource(format!("{URL}: no {} in the result", kind.key())))?;
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
    /// Takes product states from the capabilities API, which lists more products. Its
    /// `notAvailable` does not say whether the product is expanding, so this server's
    /// not-expanding state stays, as do products only this server lists.
    pub fn add_products_from(&mut self, p: super::capabilities::Products) {
        for (name, (state, launch)) in p.products {
            let keep = self.products.get(&name).is_some_and(|own| {
                state == State::NotAvailable && own.state == State::NotExpanding
            });
            if !keep {
                self.products.insert(name, Product { state, launch });
            }
        }
        self.features = p
            .features
            .into_iter()
            .map(|(k, (state, launch))| (k, Product { state, launch }))
            .collect();
        self.merged = p.merged;
    }

    /// Adds CloudFormation types and config values from the capabilities API; config
    /// values only where `needs` asks for them. A type is available where either source
    /// says so: on 2026-11-24 the API listed five FSx types as unavailable in
    /// eusc-de-east-1 that the Region's registry has and this server lists.
    pub fn add_cfn(&mut self, cfn: super::capabilities::Cfn, needs: &Needs) {
        self.unknown.retain(|u| !cfn.types.contains_key(u));
        for (t, ok) in cfn.types {
            *self.types.entry(t).or_insert(ok) |= ok;
        }
        self.mark_unknown_types(needs);
        if needs.config {
            self.config = cfn.config;
        }
    }

    /// Needed types that no source lists are unknown.
    pub fn mark_unknown_types(&mut self, needs: &Needs) {
        self.unknown.extend(
            needs
                .types
                .iter()
                .filter(|t| !self.types.contains_key(*t))
                .cloned(),
        );
    }

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
    fn reads_the_region_list() {
        let inner = json!({"content": {"result": [
            {"region_id": "eu-west-1", "region_long_name": "Europe (Ireland)"},
            {"region_id": "eusc-de-east-1", "region_long_name": "AWS European Sovereign Cloud"}
        ]}});
        let body = json!({"jsonrpc": "2.0", "id": 1, "result": {"isError": false, "content": [
            {"type": "text", "text": inner.to_string()}
        ]}});
        let r = parse_regions(&body.to_string()).unwrap();
        assert_eq!(r.len(), 2);
        assert!(r.contains("eusc-de-east-1"));
        let empty = json!({"jsonrpc": "2.0", "id": 1, "result": {"content": [
            {"type": "text", "text": "{\"content\":{\"result\":[]}}"}
        ]}});
        assert_eq!(
            parse_regions(&empty.to_string()).unwrap_err().exit_code(),
            3
        );
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
    fn lean_and_cfn_only_split_the_calls() {
        let kinds = |needs: &Needs, parts| {
            jobs(needs, parts)
                .iter()
                .map(|j| (j.kind, j.filters.len()))
                .collect::<Vec<_>>()
        };
        let few = Needs {
            types: (0..10).map(|i| format!("AWS::A::T{i}")).collect(),
            services: ["Lambda".to_string()].into(),
            ..Needs::default()
        };
        assert_eq!(
            kinds(&few, Parts::Lean),
            [
                (Kind::Product, 0),
                (Kind::Cfn, 9),
                (Kind::Cfn, 1),
                (Kind::Api, 1)
            ]
        );
        assert!(kinds(&few, Parts::CfnOnly).is_empty());
        let config = Needs {
            config: true,
            ..few
        };
        assert_eq!(kinds(&config, Parts::CfnOnly), [(Kind::Cfn, 0)]);
        let many = Needs {
            types: (0..MAX_FILTERS * FULL_CFN_PAGES + 1)
                .map(|i| format!("AWS::A::T{i}"))
                .collect(),
            ..Needs::default()
        };
        assert_eq!(kinds(&many, Parts::Lean), [(Kind::Product, 0)]);
        let most = Needs {
            types: (0..MAX_FILTERS * FULL_CFN_PAGES)
                .map(|i| format!("AWS::A::T{i}"))
                .collect(),
            ..Needs::default()
        };
        assert_eq!(kinds(&most, Parts::Lean).len(), 1 + FULL_CFN_PAGES);
        assert!(kinds(&most, Parts::CfnOnly).is_empty());
        assert_eq!(kinds(&many, Parts::CfnOnly), [(Kind::Cfn, 0)]);
    }

    #[test]
    fn product_states_merge() {
        let p = |s: State| Product {
            state: s,
            launch: None,
        };
        let mut k = Knowledge {
            products: [
                ("Gone", p(State::NotExpanding)),
                ("Dup", p(State::NotAvailable)),
                ("Old", p(State::Planned)),
                ("Only here", p(State::Planning)),
            ]
            .map(|(n, p)| (n.to_string(), p))
            .into(),
            ..Knowledge::default()
        };
        k.add_products_from(super::super::capabilities::Products {
            products: [
                ("Gone", (State::NotAvailable, None)),
                ("Dup", (State::Available, None)),
                ("Svc: Dup", (State::Available, None)),
                ("Old", (State::Available, None)),
                ("New", (State::Planned, Some("2027 Q1".to_string()))),
            ]
            .map(|(n, s)| (n.to_string(), s))
            .into(),
            features: [(
                ("AWS Lambda".to_string(), "X".to_string()),
                (State::Available, None),
            )]
            .into(),
            merged: ["Dup".to_string()].into(),
        });
        let st = |n: &str| k.products[n].state;
        assert_eq!(st("Gone"), State::NotExpanding);
        assert_eq!(st("Dup"), State::Available);
        assert_eq!(st("Svc: Dup"), State::Available);
        assert_eq!(k.features.len(), 1);
        assert!(k.merged.contains("Dup"));
        assert_eq!(st("Old"), State::Available);
        assert_eq!(st("Only here"), State::Planning);
        assert_eq!(k.products["New"].launch.as_deref(), Some("2027 Q1"));
    }

    #[test]
    fn halves_calls_in_flight_per_throttle() {
        assert_eq!(
            [0, 1, 2, 3, 4, 40].map(in_flight),
            [PARALLEL, PARALLEL / 2, PARALLEL / 4, 1, 1, 1]
        );
    }

    #[test]
    fn merges_capabilities_types() {
        let mut k = Knowledge {
            types: [("AWS::FSx::ClusterPeer", true), ("AWS::Q::App", false)]
                .map(|(t, ok)| (t.to_string(), ok))
                .into(),
            unknown: ["AWS::New::Type".to_string(), "NotAService".to_string()].into(),
            ..Knowledge::default()
        };
        let cfn = super::super::capabilities::Cfn {
            types: [
                ("AWS::FSx::ClusterPeer", false),
                ("AWS::Q::App", true),
                ("AWS::New::Type", false),
            ]
            .map(|(t, ok)| (t.to_string(), ok))
            .into(),
            config: [(
                "AWS::EC2::Instance::InstanceType".to_string(),
                ["m7i.large".to_string()].into(),
            )]
            .into(),
        };
        let needs = Needs {
            types: ["AWS::FSx::ClusterPeer", "AWS::Gone::Type"]
                .map(String::from)
                .into(),
            ..Needs::default()
        };
        k.add_cfn(cfn, &needs);
        // Available where either source says so.
        assert!(k.types["AWS::FSx::ClusterPeer"]);
        assert!(k.types["AWS::Q::App"]);
        assert!(!k.types["AWS::New::Type"]);
        let unknown: Vec<&str> = k.unknown.iter().map(String::as_str).collect();
        assert_eq!(unknown, ["AWS::Gone::Type", "NotAService"]);
        // Config values only where needed.
        assert!(k.config.is_empty());
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
        let regions = regions(&client).unwrap();
        assert!(regions.contains("eusc-de-east-1") && regions.contains("us-gov-west-1"));
        let k = fetch(&client, "eusc-de-east-1", &needs, Parts::Lean).unwrap();
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
        let all = super::super::availability(&client, &["eusc-de-east-1"], &Needs::default())
            .unwrap()
            .regions
            .remove(0);
        let m = product_map();
        for n in m.namespaces.values().flatten().chain(m.types.values()) {
            assert!(all.products.contains_key(n), "{n} is no longer a product");
        }
    }
}
