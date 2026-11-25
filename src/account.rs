//! Account checks, live mode only: whether the target Region is enabled for the
//! account, whether the input fits the account's quotas there, whether a service
//! control policy denies the Region, and whether the AWS public SSM parameters the
//! input resolves exist there. A check the role cannot read is skipped with the reason.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use crate::model::Template;
use crate::provider::aws_call::{Call, Outcome, xml_first, xml_values};
use crate::rules::{self, Kind};
use crate::services::service;

#[derive(Debug, Clone, Default, PartialEq, Serialize, schemars::JsonSchema)]
pub struct AccountChecks {
    /// `opt-in-not-required`, `opted-in` or `not-opted-in`, as EC2 reports it.
    pub region_opt_in: Option<String>,
    /// One entry per quota the input counts against.
    pub quotas: Vec<QuotaCheck>,
    pub scp: Option<ScpCheck>,
    /// AWS public SSM parameters the input resolves.
    pub ssm_parameters: Vec<SsmParameterCheck>,
    pub skipped: Vec<Skipped>,
}

impl AccountChecks {
    /// Checks that block deployment.
    pub fn blockers(&self) -> usize {
        usize::from(self.region_opt_in.as_deref() == Some("not-opted-in"))
            + self.quotas.iter().filter(|q| q.exceeded).count()
            + self.scp.as_ref().map_or(0, |s| {
                s.policies
                    .iter()
                    .filter(|p| p.verdict == ScpVerdict::DeniesTarget)
                    .count()
                    + s.services_denied.len()
            })
            + self
                .ssm_parameters
                .iter()
                .filter(|p| !p.exists)
                .map(|p| p.used_by.len().max(1))
                .sum::<usize>()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, schemars::JsonSchema)]
pub struct QuotaCheck {
    pub rule: String,
    pub service_code: String,
    pub quota_code: String,
    pub name: String,
    /// What the input alone needs.
    pub needed: u64,
    /// What the account already uses in the target; null when it could not be read.
    pub used: Option<u64>,
    /// Values the input sets with a reference or function, so they are not counted.
    /// Negative values (Terraform's `-1`, no reservation) count as zero.
    pub uncounted: usize,
    pub quota: f64,
    /// `applied` for the account's own value, `default` when none is applied.
    pub value_source: QuotaSource,
    pub exceeded: bool,
    pub doc: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum QuotaSource {
    Applied,
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct ScpCheck {
    pub status: ScpStatus,
    /// Service control policies that apply to the account, through its OUs and root.
    pub policies: Vec<ScpPolicy>,
    /// Services the input uses that the SCPs deny in any Region: an allow list at one
    /// level of the organization that does not name them, or a `Deny` of all their
    /// actions without conditions.
    pub services_denied: Vec<ScpServiceDenial>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct ScpServiceDenial {
    /// The IAM service prefix, such as `lambda`.
    pub service: String,
    /// The account, OU or root whose policies deny it.
    pub target: String,
    /// The denying policy; null when no policy at the target allows the service.
    pub policy: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ScpStatus {
    Evaluated,
    /// The account is in no organization, so no SCP applies.
    NotInOrganization,
    /// SCPs do not affect the management account.
    ManagementAccount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct ScpPolicy {
    pub id: String,
    pub name: String,
    pub verdict: ScpVerdict,
    /// The denying statement has further conditions, such as exempted principals, or
    /// denies only some actions.
    pub conditional: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ScpVerdict {
    /// A Deny statement's `aws:RequestedRegion` condition matches the target.
    DeniesTarget,
    /// Its `aws:RequestedRegion` conditions leave the target out of every Deny.
    AllowsTarget,
    /// No `aws:RequestedRegion` condition the scanner can evaluate.
    NotEvaluated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct SsmParameterCheck {
    pub name: String,
    /// Where the input uses it: resource logical ids or `Parameters/<name>`.
    pub used_by: Vec<String>,
    pub exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct Skipped {
    pub check: String,
    pub reason: String,
}

/// What the input needs checked in the account.
#[derive(Debug, Default)]
pub struct Needs {
    /// Quota rule id, units needed, uncounted values.
    pub quotas: Vec<(&'static rules::Rule, u64, usize)>,
    /// Public parameter path to where the input uses it.
    pub ssm: BTreeMap<String, BTreeSet<String>>,
    /// IAM service prefixes of the input's CloudFormation resources.
    pub services: BTreeSet<String>,
}

/// Counts the input against the quota rules and collects its public SSM parameters.
pub fn needs(template: &Template) -> Needs {
    let mut quotas = Vec::new();
    for rule in rules::all().iter().filter(|r| r.kind == Kind::Quota) {
        let spec = rule.quota.as_ref().expect("quota rules have a quota");
        let (mut units, mut uncounted) = (0u64, 0usize);
        for r in template
            .resources
            .values()
            .filter(|r| rule.types.iter().any(|t| t == r.deployed_type()))
        {
            if rule.paths.is_empty() {
                units += 1;
                continue;
            }
            for v in rule
                .paths
                .iter()
                .filter_map(|p| r.deployed_properties().get(p))
            {
                match v
                    .as_i64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                {
                    Some(n) => units += u64::try_from(n).unwrap_or(0),
                    None if v.is_null() => {}
                    None => uncounted += 1,
                }
            }
        }
        // The service keeps its reserve back only from what the input reserves.
        if units > 0 {
            quotas.push((rule, units + spec.reserve, uncounted));
        } else if uncounted > 0 {
            quotas.push((rule, 0, uncounted));
        }
    }
    let mut ssm: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (param, path) in &template.ssm_defaults {
        ssm.entry(path.clone()).or_default().insert(param.clone());
    }
    let re = regex_lite::Regex::new(r"\{\{resolve:ssm:(/aws/service/[^}:]+)(?::[0-9]+)?\}\}")
        .expect("pattern compiles");
    for r in template.resources.values() {
        let text = r.properties.to_string();
        for c in re.captures_iter(&text) {
            ssm.entry(c[1].to_string())
                .or_default()
                .insert(r.logical_id.clone());
        }
    }
    let services = template
        .resources
        .values()
        .filter_map(|r| iam_prefix(r.deployed_type()))
        .collect();
    Needs {
        quotas,
        ssm,
        services,
    }
}

/// CloudFormation namespaces whose IAM service prefix is not the namespace in lower
/// case, from the Service Authorization Reference.
const IAM_PREFIXES: &[(&str, &str)] = &[
    ("ApiGatewayV2", "apigateway"),
    ("ApplicationAutoScaling", "application-autoscaling"),
    ("CertificateManager", "acm"),
    ("DocDB", "rds"),
    ("EFS", "elasticfilesystem"),
    ("ElasticLoadBalancingV2", "elasticloadbalancing"),
    ("EMR", "elasticmapreduce"),
    ("Elasticsearch", "es"),
    ("KinesisAnalyticsV2", "kinesisanalytics"),
    ("KinesisFirehose", "firehose"),
    ("MSK", "kafka"),
    ("Neptune", "rds"),
    ("OpenSearchService", "es"),
    ("StepFunctions", "states"),
];

/// The IAM prefix of a resource type's service, where it is known: from the table,
/// else the namespace in lower case when botocore has a service of that name.
fn iam_prefix(resource_type: &str) -> Option<String> {
    let ns = match resource_type.split("::").collect::<Vec<_>>().as_slice() {
        ["AWS", ns, _] => *ns,
        _ => return None,
    };
    if let Some((_, p)) = IAM_PREFIXES.iter().find(|(n, _)| *n == ns) {
        return Some((*p).to_string());
    }
    let p = ns.to_ascii_lowercase();
    let index = crate::services::index();
    (index
        .by_endpoint_prefix(&p)
        .is_some_and(|s| s.signing_name == p))
    .then_some(p)
}

/// Partitions whose Organizations endpoint is in one Region; the others serve it in
/// every Region, ESC in its only one.
const ORGANIZATIONS_REGION: &[(&str, &str)] = &[
    ("aws", "us-east-1"),
    ("aws-us-gov", "us-gov-west-1"),
    ("aws-cn", "cn-northwest-1"),
];

pub fn run(
    caller: &impl Call,
    target_region: &str,
    partition: &str,
    account_id: &str,
    needs: &Needs,
) -> AccountChecks {
    let mut out = AccountChecks::default();
    let mut skip = |check: &str, reason: String| {
        out.skipped.push(Skipped {
            check: check.into(),
            reason,
        });
    };
    match caller.call(
        service("ec2"),
        "DescribeRegions",
        "POST",
        "/",
        &[("RegionName.1", target_region), ("AllRegions", "true")],
    ) {
        Outcome::Ok(body) => out.region_opt_in = xml_first(&body, "optInStatus"),
        o => skip("region-opt-in", reason("ec2:DescribeRegions", &o)),
    }
    let sq = service("servicequotas");
    for (rule, needed, uncounted) in &needs.quotas {
        let spec = rule.quota.as_ref().expect("quota rules have a quota");
        let p = [
            ("ServiceCode", spec.service_code.as_str()),
            ("QuotaCode", spec.quota_code.as_str()),
        ];
        let applied = caller.call(sq, "GetServiceQuota", "POST", "/", &p);
        let found = match applied {
            Outcome::Ok(b) => quota_value(&b).map(|v| (v, QuotaSource::Applied)),
            Outcome::Error(ref c) if c == "NoSuchResourceException" => {
                match caller.call(sq, "GetAWSDefaultServiceQuota", "POST", "/", &p) {
                    Outcome::Ok(b) => quota_value(&b).map(|v| (v, QuotaSource::Default)),
                    o => {
                        skip(
                            &rule.id,
                            reason("servicequotas:GetAWSDefaultServiceQuota", &o),
                        );
                        continue;
                    }
                }
            }
            o => {
                skip(&rule.id, reason("servicequotas:GetServiceQuota", &o));
                continue;
            }
        };
        let Some((quota, value_source)) = found else {
            skip(&rule.id, "Service Quotas returned no value".into());
            continue;
        };
        let used = match usage(caller, &spec.quota_code) {
            Some(Ok(n)) => Some(n),
            Some(Err(r)) => {
                skip(&format!("{}-usage", rule.id), r);
                None
            }
            None => None,
        };
        out.quotas.push(QuotaCheck {
            rule: rule.id.clone(),
            service_code: spec.service_code.clone(),
            quota_code: spec.quota_code.clone(),
            name: spec.name.clone(),
            needed: *needed,
            used,
            uncounted: *uncounted,
            quota,
            value_source,
            exceeded: (*needed + used.unwrap_or(0)) as f64 > quota,
            doc: rule.source.url().to_string(),
        });
    }
    match scp(
        caller,
        partition,
        account_id,
        target_region,
        &needs.services,
    ) {
        Ok(s) => out.scp = Some(s),
        Err(r) => skip("scp", r),
    }
    let ssm = service("ssm");
    for (name, used_by) in &needs.ssm {
        let exists = match caller.call(ssm, "GetParameter", "POST", "/", &[("Name", name)]) {
            Outcome::Ok(_) => true,
            Outcome::Error(c) if c == "ParameterNotFound" => false,
            // SSM denies a path under a public namespace the Region does not have.
            Outcome::Error(c) if c.contains("is not a valid namespace") => false,
            o => {
                skip(
                    "ssm-parameter",
                    format!("{name}: {}", reason("ssm:GetParameter", &o)),
                );
                continue;
            }
        };
        out.ssm_parameters.push(SsmParameterCheck {
            name: name.clone(),
            used_by: used_by.iter().cloned().collect(),
            exists,
        });
    }
    out
}

/// What the account already uses of a quota in the target. `None`: no usage call
/// is known for the quota.
fn usage(caller: &impl Call, quota_code: &str) -> Option<Result<u64, String>> {
    let ec2 = service("ec2");
    // Each item of these lists carries its id once.
    let count = |op: &str, paged: bool, tag: &str| -> Result<u64, String> {
        let mut n = 0;
        let mut token = String::new();
        for _ in 0..20 {
            let mut p = Vec::new();
            if paged {
                p.push(("MaxResults", "1000"));
                if !token.is_empty() {
                    p.push(("NextToken", token.as_str()));
                }
            }
            match caller.call(ec2, op, "POST", "/", &p) {
                Outcome::Ok(body) => {
                    n += xml_values(&body, tag).len() as u64;
                    match xml_first(&body, "nextToken") {
                        Some(t) if paged && !t.is_empty() => token = t,
                        _ => return Ok(n),
                    }
                }
                o => return Err(reason(&format!("ec2:{op}"), &o)),
            }
        }
        Err(format!("ec2:{op}: more than 20 pages"))
    };
    Some(match quota_code {
        "L-F678F1CE" => count("DescribeVpcs", true, "vpcId"),
        "L-A4707A72" => count("DescribeInternetGateways", true, "internetGatewayId"),
        "L-0263D0A3" => count("DescribeAddresses", false, "allocationId"),
        // Reserved concurrency already in use: the account's limit minus what is left
        // unreserved.
        "L-B99A9384" => match caller.call(
            service("lambda"),
            "GetAccountSettings",
            "GET",
            "/2016-08-19/account-settings/",
            &[],
        ) {
            Outcome::Ok(body) => serde_json::from_str::<Value>(&body)
                .ok()
                .and_then(|v| {
                    let l = &v["AccountLimit"];
                    Some(
                        l["ConcurrentExecutions"]
                            .as_u64()?
                            .saturating_sub(l["UnreservedConcurrentExecutions"].as_u64()?),
                    )
                })
                .ok_or_else(|| "lambda:GetAccountSettings returned an unreadable answer.".into()),
            o => Err(reason("lambda:GetAccountSettings", &o)),
        },
        _ => return None,
    })
}

fn reason(call: &str, o: &Outcome) -> String {
    match o {
        o if o.is_denied() => format!("{call} was denied for the role."),
        Outcome::NoEndpoint => format!("{call}: the service has no endpoint here."),
        Outcome::Error(c) => format!("{call} returned {c}."),
        Outcome::Failed(e) => format!("{call} failed: {e}"),
        Outcome::Ok(_) => format!("{call} returned an unreadable answer."),
    }
}

fn quota_value(body: &str) -> Option<f64> {
    serde_json::from_str::<Value>(body).ok()?["Quota"]["Value"].as_f64()
}

/// The SCPs that apply to the account. Reading them needs the management account or
/// a delegated administrator.
fn scp<C: Call>(
    caller: &C,
    partition: &str,
    account_id: &str,
    target_region: &str,
    services: &BTreeSet<String>,
) -> Result<ScpCheck, String> {
    let region = ORGANIZATIONS_REGION
        .iter()
        .find(|(p, _)| *p == partition)
        .map_or(target_region, |(_, r)| r);
    let org = caller.in_region(region).map_err(|e| e.to_string())?;
    let s = service("organizations");
    let json = |op: &str, p: &[(&str, &str)]| -> Result<Value, String> {
        match org.call(s, op, "POST", "/", p) {
            Outcome::Ok(b) => serde_json::from_str(&b).map_err(|e| format!("{op}: {e}")),
            o if o.is_denied() => Err(format!(
                "organizations:{op} was denied. Service control policies are readable from the management account or a delegated administrator only."
            )),
            o => Err(reason(&format!("organizations:{op}"), &o)),
        }
    };
    let none = |status| {
        Ok(ScpCheck {
            status,
            policies: Vec::new(),
            services_denied: Vec::new(),
        })
    };
    match org.call(s, "DescribeOrganization", "POST", "/", &[]) {
        Outcome::Error(c) if c == "AWSOrganizationsNotInUseException" => {
            return none(ScpStatus::NotInOrganization);
        }
        Outcome::Ok(b) => {
            let v: Value = serde_json::from_str(&b).unwrap_or_default();
            if v["Organization"]["MasterAccountId"].as_str() == Some(account_id) {
                return none(ScpStatus::ManagementAccount);
            }
        }
        o => return Err(reason("organizations:DescribeOrganization", &o)),
    }
    let mut targets = vec![account_id.to_string()];
    loop {
        let child = targets.last().expect("not empty").clone();
        let v = json("ListParents", &[("ChildId", &child)])?;
        let Some(p) = v["Parents"].get(0) else { break };
        let id = p["Id"].as_str().unwrap_or_default().to_string();
        if id.is_empty() || targets.contains(&id) {
            break;
        }
        let root = p["Type"] == "ROOT";
        targets.push(id);
        if root {
            break;
        }
    }
    let mut contents: BTreeMap<String, String> = BTreeMap::new();
    let mut policies = Vec::new();
    // Each target's policies, as (id, content); every level must allow a service.
    let mut levels: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for t in &targets {
        levels.push((t.clone(), Vec::new()));
        let mut next = String::new();
        loop {
            let mut p = vec![
                ("TargetId", t.as_str()),
                ("Filter", "SERVICE_CONTROL_POLICY"),
            ];
            if !next.is_empty() {
                p.push(("NextToken", &next));
            }
            let v = json("ListPoliciesForTarget", &p)?;
            for pol in v["Policies"].as_array().into_iter().flatten() {
                let id = pol["Id"].as_str().unwrap_or_default().to_string();
                // A policy attached at several levels, such as FullAWSAccess, counts at
                // each of them; it is read and listed once.
                if let Some(content) = contents.get(&id) {
                    if let Some((_, l)) = levels.last_mut() {
                        l.push((id.clone(), content.clone()));
                    }
                    continue;
                }
                let d = json("DescribePolicy", &[("PolicyId", &id)])?;
                let content = d["Policy"]["Content"].as_str().unwrap_or("{}");
                contents.insert(id.clone(), content.to_string());
                if let Some((_, l)) = levels.last_mut() {
                    l.push((id.clone(), content.to_string()));
                }
                let (verdict, conditional) = scp_verdict(content, target_region);
                policies.push(ScpPolicy {
                    name: pol["Name"].as_str().unwrap_or_default().to_string(),
                    id,
                    verdict,
                    conditional,
                });
            }
            match v["NextToken"].as_str() {
                Some(n) if !n.is_empty() => next = n.to_string(),
                _ => break,
            }
        }
    }
    policies.sort_by(|a, b| (a.verdict, &a.id).cmp(&(b.verdict, &b.id)));
    Ok(ScpCheck {
        status: ScpStatus::Evaluated,
        policies,
        services_denied: services_denied(&levels, services),
    })
}

/// Services the SCPs deny whatever the Region and resource.
fn services_denied(
    levels: &[(String, Vec<(String, String)>)],
    services: &BTreeSet<String>,
) -> Vec<ScpServiceDenial> {
    let mut out = Vec::new();
    for svc in services {
        let action = format!("{svc}:*");
        'levels: for (target, policies) in levels {
            let docs: Vec<(&String, Vec<Value>)> =
                policies.iter().map(|(id, c)| (id, statements(c))).collect();
            for (id, sts) in &docs {
                // A Deny without conditions of every action of the service, by
                // `Action`, or by a `NotAction` that leaves it out.
                let denies = sts.iter().any(|s| {
                    s["Effect"] == "Deny"
                        && s.get("Condition").is_none()
                        && s.get("NotResource").is_none()
                        && patterns(&s["Resource"]).iter().any(|r| r == "*")
                        && (patterns(&s["Action"]).iter().any(|p| covers(p, &action))
                            || (s.get("NotAction").is_some()
                                && !patterns(&s["NotAction"])
                                    .iter()
                                    .any(|p| glob_ci(p, &action) || glob_ci(&action, p))))
                });
                if denies {
                    out.push(ScpServiceDenial {
                        service: svc.clone(),
                        target: target.clone(),
                        policy: Some((*id).clone()),
                    });
                    break 'levels;
                }
            }
            if docs.is_empty() {
                continue;
            }
            let allowed = docs.iter().flat_map(|(_, s)| s).any(|s| {
                s["Effect"] == "Allow"
                    && patterns(&s["Action"]).iter().any(|p| {
                        covers(p, &action) || p.to_ascii_lowercase().starts_with(&format!("{svc}:"))
                    })
            });
            if !allowed {
                out.push(ScpServiceDenial {
                    service: svc.clone(),
                    target: target.clone(),
                    policy: None,
                });
                break;
            }
        }
    }
    out
}

fn statements(content: &str) -> Vec<Value> {
    match serde_json::from_str::<Value>(content).map(|d| d["Statement"].clone()) {
        Ok(Value::Array(a)) => a,
        Ok(v @ Value::Object(_)) => vec![v],
        _ => Vec::new(),
    }
}

fn patterns(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

/// `pattern` matches every action of `svc:*`: `*`, `svc:*` or a wildcard covering it.
fn covers(pattern: &str, service_all: &str) -> bool {
    glob_ci(pattern, service_all)
}

fn glob_ci(pattern: &str, s: &str) -> bool {
    glob(&pattern.to_ascii_lowercase(), &s.to_ascii_lowercase())
}

/// Whether an SCP's Deny statements reach `region` through `aws:RequestedRegion`, and
/// whether a denying statement has further conditions.
fn scp_verdict(content: &str, region: &str) -> (ScpVerdict, bool) {
    let Ok(doc) = serde_json::from_str::<Value>(content) else {
        return (ScpVerdict::NotEvaluated, false);
    };
    let statements: Vec<&Value> = match &doc["Statement"] {
        Value::Array(a) => a.iter().collect(),
        v @ Value::Object(_) => vec![v],
        _ => vec![],
    };
    let mut evaluated = false;
    let mut denies: Option<bool> = None;
    for st in statements.into_iter().filter(|s| s["Effect"] == "Deny") {
        let Some(cond) = st["Condition"].as_object() else {
            continue;
        };
        let mut matched = None;
        // A Deny of some actions only, not `*` or everything but `NotAction`.
        let mut others = match &st["Action"] {
            Value::String(a) => a != "*",
            Value::Array(a) => !a.iter().any(|x| x == "*"),
            _ => false,
        };
        for (op, kv) in cond {
            let Some(kv) = kv.as_object() else { continue };
            for (key, values) in kv {
                if !key.eq_ignore_ascii_case("aws:RequestedRegion") {
                    others = true;
                    continue;
                }
                let values: Vec<&str> = match values {
                    Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                    Value::String(s) => vec![s.as_str()],
                    _ => vec![],
                };
                if let Some(m) = operator_matches(op, &values, region) {
                    matched = Some(matched.unwrap_or(true) && m);
                }
            }
        }
        if let Some(m) = matched {
            evaluated = true;
            if m {
                denies = Some(denies.unwrap_or(false) || others);
                if !others {
                    return (ScpVerdict::DeniesTarget, false);
                }
            }
        }
    }
    match denies {
        Some(conditional) => (ScpVerdict::DeniesTarget, conditional),
        None if evaluated => (ScpVerdict::AllowsTarget, false),
        None => (ScpVerdict::NotEvaluated, false),
    }
}

/// Whether the condition holds for `region`, or `None` for an operator not evaluated.
fn operator_matches(op: &str, values: &[&str], region: &str) -> Option<bool> {
    let op = op
        .trim_start_matches("ForAnyValue:")
        .trim_start_matches("ForAllValues:");
    let op = op.strip_suffix("IfExists").unwrap_or(op);
    let eq = values.iter().any(|v| v.eq_ignore_ascii_case(region));
    let like = values.iter().any(|v| glob(v, region));
    match op {
        "StringEquals" | "StringEqualsIgnoreCase" => Some(eq),
        "StringNotEquals" | "StringNotEqualsIgnoreCase" => Some(!eq),
        "StringLike" => Some(like),
        "StringNotLike" => Some(!like),
        _ => None,
    }
}

/// IAM wildcards: `*` any run, `?` one character.
fn glob(pattern: &str, s: &str) -> bool {
    fn go(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], s) || (!s.is_empty() && go(p, &s[1..])),
            (Some(b'?'), Some(_)) => go(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &s[1..]),
            _ => false,
        }
    }
    go(pattern.as_bytes(), s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader;
    use crate::services::Service;

    #[test]
    fn region_deny_policies() {
        let deny_others = r#"{"Statement":[{"Effect":"Deny","NotAction":["iam:*"],"Resource":"*",
            "Condition":{"StringNotEquals":{"aws:RequestedRegion":["eu-central-1","eu-west-1"]}}}]}"#;
        assert_eq!(
            scp_verdict(deny_others, "eu-west-1"),
            (ScpVerdict::AllowsTarget, false)
        );
        assert_eq!(
            scp_verdict(deny_others, "us-east-1"),
            (ScpVerdict::DeniesTarget, false)
        );
        let exempt = r#"{"Statement":{"Effect":"Deny","Action":"*","Resource":"*",
            "Condition":{"StringNotLike":{"aws:RequestedRegion":"eu-*"},
                         "ArnNotLike":{"aws:PrincipalARN":"arn:aws:iam::*:role/Admin"}}}}"#;
        assert_eq!(
            scp_verdict(exempt, "eu-north-1").0,
            ScpVerdict::AllowsTarget
        );
        assert_eq!(
            scp_verdict(exempt, "us-west-2"),
            (ScpVerdict::DeniesTarget, true)
        );
        let deny_one = r#"{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
            "Condition":{"ForAnyValue:StringEqualsIfExists":{"aws:requestedregion":"ap-east-1"}}}]}"#;
        assert_eq!(
            scp_verdict(deny_one, "ap-east-1").0,
            ScpVerdict::DeniesTarget
        );
        assert_eq!(
            scp_verdict(deny_one, "eu-west-1").0,
            ScpVerdict::AllowsTarget
        );
        let other = r#"{"Statement":[{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"},
            {"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
        assert_eq!(scp_verdict(other, "eu-west-1").0, ScpVerdict::NotEvaluated);
        assert_eq!(scp_verdict("not json", "x").0, ScpVerdict::NotEvaluated);
        let one_action = r#"{"Statement":[{"Effect":"Deny","Action":"ec2:RunInstances","Resource":"*",
            "Condition":{"StringNotEquals":{"aws:RequestedRegion":"eu-west-1"}}}]}"#;
        assert_eq!(
            scp_verdict(one_action, "us-east-1"),
            (ScpVerdict::DeniesTarget, true)
        );
    }

    #[test]
    fn globs() {
        assert!(glob("eu-*", "eu-west-1") && glob("us-?ast-1", "us-east-1"));
        assert!(!glob("eu-*", "us-east-1") && !glob("eu-west-?", "eu-west-10"));
    }

    #[test]
    fn needs_count_resources_and_sum_reserved_concurrency() {
        let t = reader::parse_text(
            r#"{"Parameters":{"Ami":{"Type":"AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default":"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64"}},
            "Resources":{
            "V1":{"Type":"AWS::EC2::VPC"},"V2":{"Type":"AWS::EC2::VPC"},
            "F1":{"Type":"AWS::Lambda::Function","Properties":{"ReservedConcurrentExecutions":50}},
            "F2":{"Type":"AWS::Lambda::Function","Properties":{"ReservedConcurrentExecutions":{"Ref":"C"}}},
            "F3":{"Type":"AWS::Lambda::Function","Properties":{"Runtime":"python3.13"}},
            "F4":{"Type":"AWS::Lambda::Function","Properties":{"ReservedConcurrentExecutions":-1}},
            "I":{"Type":"AWS::EC2::Instance","Properties":{"ImageId":"{{resolve:ssm:/aws/service/ami-windows-latest/x:2}}"}}}}"#,
        )
        .unwrap();
        let n = needs(&t);
        let q: Vec<(&str, u64, usize)> = n
            .quotas
            .iter()
            .map(|(r, u, c)| (r.id.as_str(), *u, *c))
            .collect();
        assert_eq!(
            q,
            [
                ("quota-vpcs-per-region", 2, 0),
                ("quota-lambda-reserved-concurrency", 150, 1)
            ]
        );
        assert_eq!(
            n.ssm.into_iter().collect::<Vec<_>>(),
            [
                (
                    "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64".into(),
                    ["Parameters/Ami".to_string()].into()
                ),
                (
                    "/aws/service/ami-windows-latest/x".into(),
                    ["I".to_string()].into()
                )
            ]
        );
    }

    /// A Terraform plan writes `-1` for "no reservation": no units, no reserve.
    #[test]
    fn no_reservation_needs_nothing() {
        let t = reader::parse_text(
            r#"{"Resources":{"F":{"Type":"AWS::Lambda::Function","Properties":{"ReservedConcurrentExecutions":-1}}}}"#,
        )
        .unwrap();
        assert!(needs(&t).quotas.is_empty());
        let t = reader::parse_text(
            r#"{"Resources":{"F":{"Type":"AWS::Lambda::Function","Properties":{"ReservedConcurrentExecutions":{"Ref":"C"}}}}}"#,
        )
        .unwrap();
        let n = needs(&t);
        assert_eq!(
            (n.quotas[0].1, n.quotas[0].2),
            (0, 1),
            "uncounted, no reserve"
        );
    }

    #[test]
    fn allow_lists_and_service_denies() {
        let lvl = |t: &str, docs: &[&str]| {
            (
                t.to_string(),
                docs.iter()
                    .enumerate()
                    .map(|(i, d)| (format!("{t}-p{i}"), (*d).to_string()))
                    .collect::<Vec<_>>(),
            )
        };
        let full = r#"{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#;
        let allow =
            r#"{"Statement":[{"Effect":"Allow","Action":["s3:*","lambda:Get*"],"Resource":"*"}]}"#;
        let deny_sqs = r#"{"Statement":[{"Effect":"Deny","Action":"sqs:*","Resource":"*"}]}"#;
        let deny_some_buckets = r#"{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::secret*"}]}"#;
        let not_action = r#"{"Statement":[{"Effect":"Deny","NotAction":["iam:*","s3:*","lambda:*"],"Resource":"*"}]}"#;
        let region = r#"{"Statement":[{"Effect":"Deny","Action":"sqs:*","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":"eu-west-1"}}}]}"#;
        let services: BTreeSet<String> =
            ["s3", "lambda", "sqs", "dynamodb"].map(String::from).into();
        let d = services_denied(
            &[
                lvl("acct", &[full, deny_sqs, deny_some_buckets]),
                lvl("ou", &[allow]),
                lvl("ou2", &[full, deny_some_buckets]),
                lvl("root", &[full]),
            ],
            &services,
        );
        let got: Vec<(&str, &str, Option<&str>)> = d
            .iter()
            .map(|x| (x.service.as_str(), x.target.as_str(), x.policy.as_deref()))
            .collect();
        assert_eq!(
            got,
            [("dynamodb", "ou", None), ("sqs", "acct", Some("acct-p1"))]
        );
        let n = services_denied(&[lvl("acct", &[full, not_action, region])], &services);
        let svc: Vec<&str> = n.iter().map(|x| x.service.as_str()).collect();
        assert_eq!(svc, ["dynamodb", "sqs"]);
        assert!(services_denied(&[lvl("acct", &[full])], &services).is_empty());
        assert_eq!(
            iam_prefix("AWS::StepFunctions::StateMachine").as_deref(),
            Some("states")
        );
        assert_eq!(
            iam_prefix("AWS::Lambda::Function").as_deref(),
            Some("lambda")
        );
        assert_eq!(iam_prefix("Custom::X"), None);
    }

    #[test]
    fn blockers_count_what_fails() {
        let mut a = AccountChecks {
            region_opt_in: Some("opted-in".into()),
            ..AccountChecks::default()
        };
        assert_eq!(a.blockers(), 0);
        a.region_opt_in = Some("not-opted-in".into());
        a.ssm_parameters.push(SsmParameterCheck {
            name: "/aws/service/x".into(),
            used_by: vec!["A".into(), "B".into()],
            exists: false,
        });
        assert_eq!(a.blockers(), 3, "one per place, as the required changes");
    }

    /// Answers by `<region> <op> <first param value>`; anything else is AccessDenied.
    #[derive(Clone)]
    struct Fake {
        region: String,
        answers: std::rc::Rc<BTreeMap<String, Outcome>>,
    }

    impl Call for Fake {
        fn call(&self, _: &Service, op: &str, _: &str, _: &str, p: &[(&str, &str)]) -> Outcome {
            let key = format!("{} {op} {}", self.region, p.first().map_or("", |x| x.1));
            self.answers
                .get(&key)
                .cloned()
                .unwrap_or_else(|| Outcome::Error("AccessDeniedException: no".into()))
        }
        fn in_region(&self, region: &str) -> crate::error::Result<Self> {
            Ok(Self {
                region: region.into(),
                ..self.clone()
            })
        }
    }

    fn fake(region: &str, answers: &[(&str, Outcome)]) -> Fake {
        Fake {
            region: region.into(),
            answers: std::rc::Rc::new(
                answers
                    .iter()
                    .map(|(k, v)| (format!("{region} {k}"), v.clone()))
                    .chain(answers.iter().filter_map(|(k, v)| {
                        k.strip_prefix("@").map(|k| (k.to_string(), v.clone()))
                    }))
                    .collect(),
            ),
        }
    }

    fn ok(v: &str) -> Outcome {
        Outcome::Ok(v.into())
    }

    const INPUT: &str = r#"{"Resources":{"V1":{"Type":"AWS::EC2::VPC"},"V2":{"Type":"AWS::EC2::VPC"},
        "E":{"Type":"AWS::EC2::EIP"},
        "I":{"Type":"AWS::EC2::Instance","Properties":{
          "ImageId":"{{resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64}}",
          "KeyName":"{{resolve:ssm:/aws/service/nowhere/x}}"}}}}"#;

    /// Quotas fall back to the default; a namespace the Region lacks is missing; the
    /// management account is not evaluated; Organizations is read in us-east-1.
    #[test]
    fn run_reads_quotas_parameters_and_organizations() {
        let c = fake(
            "eu-west-1",
            &[
                (
                    "DescribeRegions eu-west-1",
                    ok("<optInStatus>opt-in-not-required</optInStatus>"),
                ),
                ("GetServiceQuota vpc", ok(r#"{"Quota":{"Value":1.0}}"#)),
                (
                    "GetServiceQuota ec2",
                    Outcome::Error("NoSuchResourceException".into()),
                ),
                (
                    "GetAWSDefaultServiceQuota ec2",
                    ok(r#"{"Quota":{"Value":5.0}}"#),
                ),
                (
                    "DescribeVpcs 1000",
                    ok("<vpcSet><item><vpcId>vpc-1</vpcId></item></vpcSet>"),
                ),
                (
                    "DescribeAddresses ",
                    ok(&"<item><allocationId>eipalloc-1</allocationId></item>".repeat(4)),
                ),
                (
                    "GetParameter /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64",
                    ok("{}"),
                ),
                (
                    "GetParameter /aws/service/nowhere/x",
                    Outcome::Error(
                        "AccessDeniedException: aws/service/nowhere is not a valid namespace"
                            .into(),
                    ),
                ),
                (
                    "@us-east-1 DescribeOrganization ",
                    ok(r#"{"Organization":{"MasterAccountId":"111122223333"}}"#),
                ),
            ],
        );
        let n = needs(&reader::parse_text(INPUT).unwrap());
        let a = run(&c, "eu-west-1", "aws", "111122223333", &n);
        assert_eq!(a.region_opt_in.as_deref(), Some("opt-in-not-required"));
        let q: Vec<(&str, QuotaSource, Option<u64>, bool)> = a
            .quotas
            .iter()
            .map(|q| (q.rule.as_str(), q.value_source, q.used, q.exceeded))
            .collect();
        assert_eq!(
            q,
            [
                ("quota-vpcs-per-region", QuotaSource::Applied, Some(1), true),
                (
                    "quota-elastic-ips-per-region",
                    QuotaSource::Default,
                    Some(4),
                    false
                )
            ]
        );
        assert_eq!(
            a.scp.as_ref().map(|s| s.status),
            Some(ScpStatus::ManagementAccount)
        );
        assert_eq!(
            a.ssm_parameters
                .iter()
                .map(|p| p.exists)
                .collect::<Vec<_>>(),
            [true, false]
        );
        assert!(a.skipped.is_empty(), "{:?}", a.skipped);
        assert_eq!(a.blockers(), 2, "the VPC quota and the missing parameter");
    }

    /// A member account walks up to the root and collects each policy once; any other
    /// denial skips the check with its reason.
    #[test]
    fn run_evaluates_member_account_scps_and_skips_denied_checks() {
        let deny = r#"{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":["eu-central-1"]}}}]}"#;
        let policy = serde_json::json!({"Policy": {"Content": deny}}).to_string();
        let c = fake(
            "eusc-de-east-1",
            &[
                (
                    "DescribeOrganization ",
                    ok(r#"{"Organization":{"MasterAccountId":"444455556666"}}"#),
                ),
                (
                    "ListParents 111122223333",
                    ok(r#"{"Parents":[{"Id":"ou-1","Type":"ORGANIZATIONAL_UNIT"}]}"#),
                ),
                (
                    "ListParents ou-1",
                    ok(r#"{"Parents":[{"Id":"r-1","Type":"ROOT"}]}"#),
                ),
                (
                    "ListPoliciesForTarget 111122223333",
                    ok(r#"{"Policies":[]}"#),
                ),
                (
                    "ListPoliciesForTarget ou-1",
                    ok(r#"{"Policies":[{"Id":"p-1","Name":"Region"}]}"#),
                ),
                (
                    "ListPoliciesForTarget r-1",
                    ok(r#"{"Policies":[{"Id":"p-1","Name":"Region"}]}"#),
                ),
                ("DescribePolicy p-1", ok(&policy)),
            ],
        );
        let n = needs(&reader::parse_text(INPUT).unwrap());
        let a = run(&c, "eusc-de-east-1", "aws-eusc", "111122223333", &n);
        let s = a.scp.as_ref().unwrap();
        assert_eq!(s.status, ScpStatus::Evaluated);
        assert_eq!(s.policies.len(), 1, "once, though attached twice");
        assert_eq!(s.policies[0].verdict, ScpVerdict::DeniesTarget);
        let skipped: Vec<&str> = a.skipped.iter().map(|s| s.check.as_str()).collect();
        assert_eq!(
            skipped,
            [
                "region-opt-in",
                "quota-vpcs-per-region",
                "quota-elastic-ips-per-region",
                "ssm-parameter",
                "ssm-parameter"
            ]
        );
        assert!(a.skipped[0].reason.contains("was denied"));
    }

    /// Against a real ESC account outside an organization. Run with
    /// `ESC_PREFLIGHT_PROFILE=<profile> cargo test -- --ignored live_esc`.
    #[test]
    #[ignore = "network and credentials"]
    fn live_esc_account() {
        let profile = std::env::var("ESC_PREFLIGHT_PROFILE").unwrap();
        let caller = crate::provider::aws_call::Caller::new(
            "eusc-de-east-1",
            "amazonaws.eu",
            Some(&profile),
            None,
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let t = reader::parse_text(
            r#"{"Resources":{"V":{"Type":"AWS::EC2::VPC"},
            "F":{"Type":"AWS::Lambda::Function","Properties":{"ReservedConcurrentExecutions":5000}},
            "I":{"Type":"AWS::EC2::Instance","Properties":{
              "ImageId":"{{resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64}}",
              "KeyName":"{{resolve:ssm:/aws/service/esc-preflight/does-not-exist}}"}}}}"#,
        )
        .unwrap();
        let a = run(
            &caller,
            "eusc-de-east-1",
            "aws-eusc",
            "000000000000",
            &needs(&t),
        );
        eprintln!("{a:?}");
        assert_eq!(a.region_opt_in.as_deref(), Some("opt-in-not-required"));
        let q: BTreeMap<&str, bool> = a
            .quotas
            .iter()
            .map(|q| (q.rule.as_str(), q.exceeded))
            .collect();
        assert!(!q["quota-vpcs-per-region"]);
        assert!(q["quota-lambda-reserved-concurrency"]);
        assert_eq!(
            a.ssm_parameters
                .iter()
                .map(|p| p.exists)
                .collect::<Vec<_>>(),
            [true, false]
        );
        assert_eq!(a.scp.map(|s| s.status), Some(ScpStatus::NotInOrganization));
        assert!(a.skipped.is_empty(), "{:?}", a.skipped);
    }
}
