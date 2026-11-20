//! Command-line entry point and exit-code contract.

use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};

use crate::depth::DepthSource;
use crate::error::{Result, ScanError};
use crate::model::{SourceFormat, Template};
use crate::provider::{self, aws_call, http, knowledge, live, partition, schema, terraform};
use crate::remediation;
use crate::report::{self, KnowledgeProvenance, Provenance, Report, TerraformProvenance};
use crate::type_mapper::{Check, Mapping, TypeMapper};
use crate::{depth, deviation, extractor, matcher, reader};

#[derive(Debug, Parser)]
#[command(
    name = "esc-preflight",
    version,
    about = "Preflight check for the AWS European Sovereign Cloud: reports what in a CloudFormation template, CDK app or Terraform plan breaks there, and why."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Scan a CloudFormation template, a CDK cloud assembly or a Terraform plan.
    #[command(after_help = SCAN_HELP)]
    Scan(ScanArgs),
    /// Plan the move: how each resource reaches the target, in waves.
    #[command(after_help = PLAN_HELP)]
    Plan(PlanArgs),
    /// Compare two Regions: what --from offers that --to does not.
    #[command(after_help = COMPARE_HELP)]
    Compare(CompareArgs),
}

#[derive(Debug, clap::Args)]
struct PlanArgs {
    #[command(flatten)]
    scan: ScanArgs,
    /// The Region the workload runs in today. Overrides the Region the input was
    /// produced for, which is often the target.
    #[arg(long)]
    from: Option<String>,
}

const PLAN_HELP: &str = "\
The plan runs the scan, then reads the bundled mechanism rules: each resource is
redeployed, replicated or restored; blocked when a scan finding blocks it; unknown
when no rule covers its type. The plan executes nothing. --out takes the plan JSON;
the scan options apply to the scan it runs.

Examples:
  esc-preflight plan --region eusc-de-east-1
  esc-preflight plan template.yaml --from eu-central-1 --region eusc-de-east-1 --out plan.json

Exit codes:
  0  plan produced
  1  invalid input or arguments
  3  a data source failed
  4  live-mode authentication failed";

#[derive(Debug, clap::Args)]
struct CompareArgs {
    /// The Region the workload runs in today.
    #[arg(long)]
    from: String,
    /// The Region to compare it with.
    #[arg(long)]
    to: String,
    /// AWS profile for the --to Region: its registry and resource schemas replace the
    /// public data.
    #[arg(long)]
    profile: Option<String>,
    /// Role to assume in the --to Region, on top of the profile or default credentials.
    #[arg(long)]
    role_arn: Option<String>,
    /// Write the JSON report here. Without it, the report goes to stdout when stdout is
    /// redirected or piped.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 60)]
    timeout: u64,
    /// Do not print the summary to stderr.
    #[arg(long, short)]
    quiet: bool,
}

const COMPARE_HELP: &str = "\
Public mode reads both Regions from the AWS Knowledge MCP server and, where both
publish one, their CloudFormation schema bundles. With --profile or --role-arn, the
--to Region's CloudFormation registry and resource schemas are read from the account.

Examples:
  esc-preflight compare --from eu-central-1 --to eusc-de-east-1
  esc-preflight compare --from eu-central-1 --to eusc-de-east-1 --profile esc --out c.json

Exit codes:
  0  report produced
  1  invalid input or arguments
  3  a data source failed
  4  live-mode authentication failed";

#[derive(Debug, clap::Args)]
struct ScanArgs {
    /// CloudFormation template (JSON or YAML), CDK app or `cdk.out` directory, or
    /// `terraform show -json` output. Default: the current directory, or piped stdin.
    path: Option<String>,
    /// Also check the target account (read-only), with the default credential chain.
    #[arg(long)]
    live: bool,
    /// AWS profile for live mode. Implies --live.
    #[arg(long)]
    profile: Option<String>,
    /// Role to assume for live mode, on top of the profile or default credentials.
    /// Implies --live.
    #[arg(long)]
    role_arn: Option<String>,
    /// Write the JSON report here. Without it, the report goes to stdout when stdout is
    /// redirected or piped.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Report every resource, not only those that need action or verification.
    #[arg(long)]
    all: bool,
    /// Exit 2 when a finding of this kind exists.
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,
    /// Region to assess against.
    #[arg(long, default_value = "eusc-de-east-1")]
    region: String,
    /// Account the input moves to, for a move to another account. Literals of other
    /// accounts then break.
    #[arg(long, value_parser = account_id)]
    account: Option<String>,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 60)]
    timeout: u64,
    /// Do not print the summary to stderr.
    #[arg(long, short)]
    quiet: bool,
}

const SCAN_HELP: &str = "\
The summary goes to stderr; the JSON report to --out, or to stdout when it is redirected.

Examples:
  esc-preflight scan
  esc-preflight scan --profile esc
  esc-preflight scan template.yaml --out report.json
  terraform show -json tfplan | esc-preflight scan --fail-on blocker

Exit codes:
  0  report produced
  1  invalid input or arguments
  2  a --fail-on finding exists
  3  a data source failed
  4  live-mode authentication failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FailOn {
    /// Not available, a value or property the region does not offer, a documented
    /// deviation, or a failed account check.
    Blocker,
    /// Any hardcoded value, environment literal or documented dependency.
    Hazard,
    /// Any disputed or cannot-assess finding, or a guide conflict.
    Disputed,
}

pub fn run() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 1 } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    let result = match &cli.command {
        Command::Scan(args) => run_scan(args),
        Command::Plan(args) => run_plan(args),
        Command::Compare(args) => run_compare(args),
    };
    result.unwrap_or_else(|e| {
        eprintln!("error: {e}");
        e.exit_code()
    })
}

fn run_scan(args: &ScanArgs) -> Result<i32> {
    let (mut report, ..) = assess(args)?;
    // The summary, which the exit code and stderr read, covers every finding.
    if !args.all {
        report::gaps_only(&mut report);
    }
    write_json(args.out.as_deref(), &report::to_json(&report))?;
    if !args.quiet {
        let unicode = std::io::stderr().is_terminal();
        let style = report::Style {
            unicode,
            color: unicode && std::env::var_os("NO_COLOR").is_none(),
        };
        eprint!("{}", report::text_summary(&report, style));
    }
    Ok(match args.fail_on {
        Some(f) if fails(report.outcome, f) => 2,
        _ => 0,
    })
}

/// The JSON to `out`, or to stdout when it is redirected or piped.
fn write_json(out: Option<&std::path::Path>, json: &str) -> Result<()> {
    match out {
        Some(p) => std::fs::write(p, json)
            .map_err(|e| ScanError::Input(format!("cannot write {}: {e}", p.display())))?,
        None if !std::io::stdout().is_terminal() => print!("{json}"),
        None => {}
    }
    Ok(())
}

/// The scan: the full report, the input and the target's partition facts.
fn assess(args: &ScanArgs) -> Result<(Report, Template, extractor::PartitionFacts)> {
    let region = &args.region;
    let template = read_input(args.path.as_deref(), region)?;
    let client = http::Client::new(Duration::from_secs(args.timeout))?;
    let mut partition = partition::facts(region)?;
    partition.target_account.clone_from(&args.account);
    partition.source_partition = extractor::source_partition(&template, &partition);
    let live_mode = args.live || args.profile.is_some() || args.role_arn.is_some();
    let listed = knowledge::regions(&client)?.contains(region);
    gate(region, listed, live_mode)?;
    let tf = (template.format == SourceFormat::TerraformPlan)
        .then(|| terraform::fetch(&client))
        .transpose()?;
    let mut depth = depth::checks(&template, region);
    let checks = checks(&template, tf.as_ref());
    // Also for checks with an operation: the service decides when the server does not
    // know the operation.
    let services: BTreeSet<String> = checks
        .iter()
        .filter_map(|c| match c {
            Check::Api { service_id, .. } => Some(service_id.clone()),
            Check::Type(_) => None,
        })
        .collect();
    let needs = knowledge::Needs {
        types: checks.iter().filter_map(type_of).cloned().collect(),
        services: services.clone(),
        operations: checks
            .iter()
            .filter_map(|c| match c {
                Check::Api {
                    service_id,
                    operation: Some(o),
                } => Some(format!("{service_id}+{o}")),
                _ => None,
            })
            .collect(),
        config: depth::needs_config(&depth),
    };
    let data = provider::fetch_public(&client, region, partition, tf, listed.then_some(&needs))?;
    let fetched_at = report::now_utc();
    let mut offered = depth::public_offered(&data.knowledge);
    depth::resolve(&mut depth, &offered, DepthSource::Knowledge);
    let scan = extractor::hazards(&template, &data.partition);
    let schema_types = schema::types(&template);
    let (live, live_prov, account, mut schemas, schema_denied) = if live_mode {
        let needs = live::Needs {
            registry: checks.iter().any(|c| type_of(c).is_some()),
            services,
            depth: std::mem::take(&mut depth),
            // Also for zone literals: whether a zone index exists in the target decides
            // if a derived zone can replace one.
            zones: scan.env_literals.iter().any(|e| !e.zones.is_empty())
                || scan
                    .hazards
                    .iter()
                    .flat_map(|h| &h.literals)
                    .any(|l| l.kind == extractor::HazardKind::AvailabilityZone),
        };
        let mut c = live_checks(args, &data.partition, &template, &schema_types, needs)?;
        depth = std::mem::take(&mut c.live.depth);
        offered.extend(std::mem::take(&mut c.live.offered));
        (
            Some(c.live),
            Some(c.provenance),
            Some(c.account),
            c.schemas,
            c.describe_type_denied,
        )
    } else {
        (None, None, None, None, false)
    };
    if schemas.is_none()
        && !live_mode
        && !schema_types.is_empty()
        && let Some(url) = schema::bundle_url(&data.partition)
    {
        let s = schema::fetch_bundle(&client, &url, &schema_types, false)?;
        schemas = Some((
            schema::SchemaProvenance::new(schema::SchemaSource::Bundle, Some(url), &s),
            s,
        ));
    }
    if let Some((_, s)) = &schemas {
        for (id, checks) in schema::checks(&template, s) {
            depth.entry(id).or_default().extend(checks);
        }
    }
    let findings = matcher::assess(
        &template,
        &data.knowledge,
        data.tf.as_ref(),
        live.as_ref(),
        &depth,
    );
    let (guide, user_guide) = deviation::assess(
        &template,
        &findings,
        data.guide.as_ref(),
        &data.knowledge,
        &data.partition,
    );
    let provenance = Provenance {
        tool_version: env!("CARGO_PKG_VERSION").into(),
        source_format: template.format,
        target_region: region.clone(),
        target_account: args.account.clone(),
        input_environments: template.envs(),
        partitions_version: partition::VERSION.into(),
        knowledge: listed.then(|| KnowledgeProvenance {
            url: knowledge::URL.into(),
            unknown: data.knowledge.unknown.iter().cloned().collect(),
        }),
        user_guide,
        fetched_at,
        terraform: data.tf.as_ref().map(|tf| TerraformProvenance {
            aws_provider_version: tf.aws_version.clone(),
            awscc_provider_version: tf.awscc_version.clone(),
        }),
        live: live_prov,
        schemas: schemas.map(|(p, _)| p),
        schema_types: schema_types.len(),
        schema_denied,
        macros: template.macros.clone(),
    };
    let report = report::build(
        provenance,
        findings,
        scan,
        guide,
        template.out_of_scope.clone(),
        &remediation::Context {
            single_region: data.partition.target_regions == 1,
            target_zones: live.as_ref().and_then(|l| l.target_zones),
            offered: Some(&offered),
            facts: Some(&data.partition),
            account: account.as_ref(),
        },
    );
    Ok((report, template, data.partition))
}

/// Live mode's reads of the target account.
struct LiveChecks {
    /// Registry, services and depth values.
    live: crate::matcher::Live,
    provenance: live::LiveProvenance,
    account: crate::account::AccountChecks,
    /// The schemas of the input's types, through `DescribeType`.
    schemas: Option<(schema::SchemaProvenance, schema::Schemas)>,
    describe_type_denied: bool,
}

fn live_checks(
    args: &ScanArgs,
    facts: &extractor::PartitionFacts,
    template: &Template,
    schema_types: &BTreeSet<String>,
    needs: live::Needs,
) -> Result<LiveChecks> {
    let caller = aws_call::Caller::new(
        &args.region,
        &facts.target_dns_suffix,
        args.profile.as_deref(),
        args.role_arn.as_deref(),
        Duration::from_secs(args.timeout),
    )?;
    let (l, p) = live::run(&caller, needs)?;
    let account = crate::account::run(
        &caller,
        &args.region,
        &facts.target_partition,
        &p.account_id,
        &crate::account::needs(template),
    );
    let mut schemas = None;
    let mut denied = false;
    if !schema_types.is_empty() {
        // A policy without DescribeType skips the property checks with a warning.
        match schema::fetch_live(&caller, schema_types, false) {
            Ok(s) => {
                schemas = Some((
                    schema::SchemaProvenance::new(schema::SchemaSource::Live, None, &s),
                    s,
                ));
            }
            Err(ScanError::Auth(_)) => denied = true,
            Err(e) => return Err(e),
        }
    }
    Ok(LiveChecks {
        live: l,
        provenance: p,
        account,
        schemas,
        describe_type_denied: denied,
    })
}

/// The input named, piped stdin, or the current directory.
fn read_input(path: Option<&str>, region: &str) -> Result<Template> {
    match path {
        Some(p) => reader::read(p, region),
        None if !std::io::stdin().is_terminal() => {
            let text = reader::read_stdin()?;
            if text.trim().is_empty() {
                reader::read(".", region)
            } else {
                reader::parse_text(&text)
            }
        }
        None => reader::read(".", region),
    }
}

/// What decides each resource of the input.
fn checks(template: &Template, tf: Option<&terraform::TfMaps>) -> Vec<Check> {
    let mapper = TypeMapper::new(tf);
    template
        .resources
        .values()
        .filter_map(|r| match mapper.map(r) {
            Mapping::Resource { check, .. } => Some(check),
            _ => None,
        })
        .collect()
}

fn type_of(c: &Check) -> Option<&String> {
    match c {
        Check::Type(t) => Some(t),
        Check::Api { .. } => None,
    }
}

fn fails(o: report::Outcome, f: FailOn) -> bool {
    match f {
        FailOn::Blocker => o.blocker,
        FailOn::Hazard => o.hazard,
        FailOn::Disputed => o.disputed,
    }
}

fn account_id(s: &str) -> std::result::Result<String, String> {
    extractor::is_account_id(s)
        .then(|| s.to_string())
        .ok_or_else(|| "an account id has 12 digits".into())
}

/// Options `plan` rejects before reading any input.
fn check_plan_args(args: &PlanArgs) -> Result<()> {
    if let Some(f) = &args.from {
        partition::facts(f)?;
    }
    if args.from.as_deref() == Some(args.scan.region.as_str()) {
        return Err(ScanError::Input(
            "--from and --region name the same Region".into(),
        ));
    }
    if args.scan.fail_on.is_some() || args.scan.all {
        return Err(ScanError::Input(
            "--fail-on and --all apply to scan, not to plan".into(),
        ));
    }
    Ok(())
}

fn run_plan(args: &PlanArgs) -> Result<i32> {
    check_plan_args(args)?;
    let (report, template, facts) = assess(&args.scan)?;
    let p = crate::plan::build(&report, &template, &facts, args.from.as_deref());
    write_json(args.scan.out.as_deref(), &report::to_json(&p))?;
    if !args.scan.quiet {
        eprint!("{}", crate::plan::text_summary(&p));
    }
    Ok(0)
}

fn run_compare(args: &CompareArgs) -> Result<i32> {
    let c = compare(args)?;
    write_json(args.out.as_deref(), &report::to_json(&c))?;
    if !args.quiet {
        eprint!("{}", crate::compare::text_summary(&c));
    }
    Ok(0)
}

fn compare(args: &CompareArgs) -> Result<crate::compare::Comparison> {
    use crate::compare::{self, CompareProvenance};
    if args.from == args.to {
        return Err(ScanError::Input(
            "--from and --to name the same Region".into(),
        ));
    }
    let (from_facts, to_facts) = (partition::facts(&args.from)?, partition::facts(&args.to)?);
    let client = http::Client::new(Duration::from_secs(args.timeout))?;
    let live_mode = args.profile.is_some() || args.role_arn.is_some();
    let listed = knowledge::regions(&client)?;
    let (from_url, to_url) = (
        schema::bundle_url(&from_facts),
        schema::bundle_url(&to_facts),
    );
    let scope = compare::scope(
        &args.from,
        &args.to,
        &compare::Sources {
            from_listed: listed.contains(&args.from),
            to_listed: listed.contains(&args.to),
            live: live_mode,
            from_bundle: from_url.is_some(),
            to_bundle: to_url.is_some(),
        },
    )
    .map_err(ScanError::Input)?;
    let all = knowledge::Needs {
        config: true,
        ..knowledge::Needs::default()
    };
    // One Region at a time: the server is rate-limited.
    let from = knowledge::fetch(&client, &args.from, &all)?;
    let to = if scope.products {
        knowledge::fetch(&client, &args.to, &all)?
    } else {
        knowledge::Knowledge::default()
    };
    let fetched_at = report::now_utc();
    let caller = live_mode
        .then(|| {
            aws_call::Caller::new(
                &args.to,
                &to_facts.target_dns_suffix,
                args.profile.as_deref(),
                args.role_arn.as_deref(),
                Duration::from_secs(args.timeout),
            )
        })
        .transpose()?;
    let (to_types, live_account_id) = match &caller {
        Some(c) => {
            let (account, _) = live::identity(c)?;
            (live::registry_types(c)?, Some(account))
        }
        None => (compare::available_types(&to), None),
    };
    let from_types = compare::available_types(&from);
    let shared: BTreeSet<String> = from_types.intersection(&to_types).cloned().collect();
    let mut from_prov = None;
    let mut schemas = None;
    if let (Some(url), Some(source)) = (&from_url, scope.to_schemas) {
        let a = schema::fetch_bundle(&client, url, &shared, true)?;
        from_prov = Some(schema::SchemaProvenance::new(
            schema::SchemaSource::Bundle,
            Some(url.clone()),
            &a,
        ));
        // The scope reads a bundle for `to` only where one exists.
        let (b, url) = match (&caller, to_url) {
            (Some(c), _) => (schema::fetch_live(c, &shared, true)?, None),
            (None, u) => (
                schema::fetch_bundle(&client, u.as_deref().unwrap_or_default(), &shared, true)?,
                u,
            ),
        };
        schemas = Some((a, schema::SchemaProvenance::new(source, url, &b), b));
    }
    let diff = compare::diff(
        &from,
        &to,
        &to_types,
        schemas.as_ref().map(|(a, _, b)| (a, b)),
    );
    Ok(compare::build(
        &args.from,
        &args.to,
        CompareProvenance {
            tool_version: env!("CARGO_PKG_VERSION").into(),
            knowledge_url: knowledge::URL.into(),
            fetched_at,
            live_account_id,
            from_schemas: from_prov,
            to_schemas: schemas.map(|(_, p, _)| p),
        },
        diff,
        scope,
    ))
}

/// Without Knowledge MCP data for the target, only live mode can decide.
fn gate(region: &str, listed: bool, live_mode: bool) -> Result<()> {
    if listed || live_mode {
        return Ok(());
    }
    Err(ScanError::Input(knowledge::unlisted(region)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_on_reads_its_outcome_category() {
        let o = report::Outcome {
            blocker: false,
            hazard: true,
            disputed: false,
        };
        assert!(fails(o, FailOn::Hazard));
        assert!(!fails(o, FailOn::Blocker) && !fails(o, FailOn::Disputed));
    }

    #[test]
    fn compare_rejects_one_region_before_any_request() {
        let Command::Compare(c) = Cli::try_parse_from([
            "esc-preflight",
            "compare",
            "--from",
            "eu-west-1",
            "--to",
            "eu-west-1",
        ])
        .unwrap()
        .command
        else {
            panic!("compare");
        };
        assert!(
            compare(&c)
                .unwrap_err()
                .to_string()
                .contains("the same Region")
        );
    }

    /// Rejected before any input is read or any host contacted.
    #[test]
    fn plan_rejects_scan_only_options_and_a_same_region_move() {
        let check = |args: &[&str]| {
            let Command::Plan(p) = Cli::try_parse_from(args).unwrap().command else {
                panic!("plan");
            };
            check_plan_args(&p).map_err(|e| e.to_string())
        };
        let scan_only = "--fail-on and --all apply to scan, not to plan";
        for args in [
            &["esc-preflight", "plan", "--fail-on", "blocker"][..],
            &["esc-preflight", "plan", "--all"],
        ] {
            assert!(check(args).unwrap_err().contains(scan_only), "{args:?}");
        }
        let same = [
            "esc-preflight",
            "plan",
            "--from",
            "eu-west-1",
            "--region",
            "eu-west-1",
        ];
        assert!(check(&same).unwrap_err().contains("the same Region"));
        assert!(check(&["esc-preflight", "plan", "--from", "eu-central-1"]).is_ok());
    }

    #[test]
    fn a_region_without_knowledge_data_needs_live_mode() {
        let e = gate("cn-north-1", false, false).unwrap_err();
        assert_eq!(e.exit_code(), 1);
        assert!(e.to_string().contains("--profile"));
        assert!(gate("cn-north-1", false, true).is_ok());
        assert!(gate("eu-west-1", true, false).is_ok());
    }
}
