//! Command-line entry point and exit-code contract.

use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};

use crate::depth::DepthSource;
use crate::error::{Result, ScanError};
use crate::model::{SourceFormat, Template};
use crate::provider::{self, aws_call, china, http, knowledge, live, partition, schema, terraform};
use crate::report::{self, KnowledgeProvenance, Provenance, Report, TerraformProvenance};
use crate::type_mapper::{Check, Mapping, TypeMapper};
use crate::{depth, deviation, extractor, matcher, reader};
use crate::{output, remediation, tui};

/// The target Region of every command without `--to`.
pub const DEFAULT_REGION: &str = "eusc-de-east-1";

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
}

const PLAN_HELP: &str = "\
The plan runs the scan, then reads the bundled mechanism rules for a move with IaC:
which resources redeploy, which data stores to fill before or after deploying, which
a scan finding blocks, and which need a decision. The plan executes nothing. --out
takes the plan JSON; the scan options apply to the scan it runs.

Examples:
  esc-preflight plan --from eu-central-1
  esc-preflight plan template.yaml --from eu-central-1 --to eusc-de-east-1 --out plan.json

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
    #[arg(long, default_value = DEFAULT_REGION)]
    to: String,
    /// Read the --to Region's registry from the account, with the default credential
    /// chain.
    #[arg(long)]
    live: bool,
    /// AWS profile for the --to Region: its registry and resource schemas replace the
    /// public data. Implies --live.
    #[arg(long)]
    profile: Option<String>,
    /// Role to assume in the --to Region, on top of the profile or default credentials.
    #[arg(long)]
    role_arn: Option<String>,
    /// Also read the --to Region's resource schemas from the account to compare
    /// properties. Needs --profile or --role-arn; takes several minutes.
    #[arg(long)]
    properties: bool,
    /// Write the JSON report here. Without it, the report goes to stdout when stdout is
    /// redirected or piped.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 60)]
    timeout: u64,
    /// Indent the JSON report for reading; it is compact by default.
    #[arg(long)]
    pretty: bool,
    /// Do not print the summary to stderr.
    #[arg(long, short)]
    quiet: bool,
}

const COMPARE_HELP: &str = "\
Public mode reads both Regions from the Builder Center capabilities API and the AWS
Knowledge MCP server and, where both publish one, their CloudFormation schema bundles.
With --live, --profile or --role-arn, the --to Region's CloudFormation registry is read
from the account; --properties also reads its resource schemas, which takes several
minutes.

Examples:
  esc-preflight compare --from eu-central-1
  esc-preflight compare --from eu-central-1 --to eusc-de-east-1 --profile esc --properties --out c.json

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
    /// Report every resource, not only those that need action or verification, and
    /// every difference the ESC User Guide documents for the services in the input.
    #[arg(long)]
    all: bool,
    /// Indent the JSON report for reading; it is compact by default.
    #[arg(long)]
    pretty: bool,
    /// Exit 2 when a finding of this kind exists.
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,
    /// The Region to move to.
    #[arg(long, default_value = DEFAULT_REGION)]
    to: String,
    /// The Region the workload runs in today. For a template that does not say which
    /// Region it was written for, a literal of this Region means the deployment's own
    /// Region; `plan` also applies the partition limits of the move. In `plan`, it is
    /// the source even when a CDK assembly or Terraform plan names another Region,
    /// whose literals keep the Region it names.
    #[arg(long)]
    from: Option<String>,
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

/// `--from` and `--to` name known Regions, and not the same one.
fn check_regions(from: Option<&str>, to: &str) -> Result<()> {
    if let Some(f) = from {
        partition::facts(f)?;
        if f == to {
            return Err(ScanError::Input(
                "--from and --to name the same Region".into(),
            ));
        }
    }
    Ok(())
}

fn run_scan(args: &ScanArgs) -> Result<i32> {
    check_regions(args.from.as_deref(), &args.to)?;
    let started = Instant::now();
    tui::start(&format!("Scanning for {}", args.to), !args.quiet);
    let assessed = assess(args);
    tui::stop();
    let (mut report, ..) = assessed?;
    // The summary, which the exit code and stderr read, covers every finding.
    if !args.all {
        report::gaps_only(&mut report);
    }
    let json = write_json(
        args.out.as_deref(),
        &output::to_json(&output::scan(&report), args.pretty),
    )?;
    if !args.quiet {
        let run = tui::Run {
            elapsed: Some(started.elapsed()),
            json,
        };
        eprint!(
            "{}",
            report::text_summary(&report, tui::Style::for_stderr(), &run)
        );
    }
    Ok(match args.fail_on {
        Some(f) if fails(report.outcome, f) => 2,
        _ => 0,
    })
}

/// The JSON to `out`, or to stdout when it is redirected or piped; where it went.
fn write_json(out: Option<&std::path::Path>, json: &str) -> Result<tui::Destination> {
    Ok(match out {
        Some(p) => {
            std::fs::write(p, json)
                .map_err(|e| ScanError::Input(format!("cannot write {}: {e}", p.display())))?;
            tui::Destination::File(p.display().to_string())
        }
        None if !std::io::stdout().is_terminal() => {
            print!("{json}");
            tui::Destination::Stdout
        }
        None => tui::Destination::Nowhere,
    })
}

/// The scan: the full report, the input and the target's partition facts.
fn assess(args: &ScanArgs) -> Result<(Report, Template, extractor::PartitionFacts)> {
    let region = &args.to;
    tui::phase(format!("reading {}", input_label(args.path.as_deref())));
    let template = read_input(args.path.as_deref(), region)?;
    let client = http::Client::new(Duration::from_secs(args.timeout))?;
    let mut partition = partition::facts(region)?;
    partition.target_account.clone_from(&args.account);
    partition.source_partition = extractor::source_partition(&template, &partition);
    let live_mode = args.live || args.profile.is_some() || args.role_arn.is_some();
    // China has public data of its own; the Knowledge MCP server does not cover it.
    let china = partition.target_partition == china::PARTITION;
    tui::phase("fetching public availability data");
    let (listed, tf) = std::thread::scope(|s| {
        let tf = s.spawn(|| {
            (template.format == SourceFormat::TerraformPlan)
                .then(|| terraform::fetch(&client))
                .transpose()
        });
        let listed = if china {
            Ok(true)
        } else {
            knowledge::regions(&client).map(|r| r.contains(region))
        };
        (listed, tf.join().expect("Terraform fetch does not panic"))
    });
    let listed = listed?;
    gate(region, listed, live_mode)?;
    let tf = tf?;
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
    let schema_types = schema::types(&template, tf.as_ref());
    // Without live mode the target's schemas come from its public bundle, if it has one;
    // the China availability fetch downloads it anyway.
    let bundle_url = (!live_mode && !schema_types.is_empty() && !china)
        .then(|| schema::bundle_url(&partition))
        .flatten();
    let (data, bundle) = std::thread::scope(|s| {
        let bundle = s.spawn(|| {
            bundle_url
                .as_ref()
                .map(|url| schema::fetch_bundle(&client, url, &schema_types, false))
                .transpose()
        });
        let data = provider::fetch_public(&client, region, partition, tf, listed.then_some(&needs));
        (
            data,
            bundle.join().expect("schema bundle fetch does not panic"),
        )
    });
    let (data, bundle) = (data?, bundle?);
    let fetched_at = report::now_utc();
    let mut offered = depth::public_offered(&data.knowledge);
    depth::resolve(&mut depth, &offered, DepthSource::Public);
    let scan = extractor::hazards(&template, &data.partition);
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
        tui::phase("checking the target account");
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
    let bundle = match (bundle, bundle_url, &data.bundle) {
        (Some(s), Some(url), _) => Some((s, url)),
        (_, _, Some((url, zip))) if !live_mode && !schema_types.is_empty() => Some((
            schema::read_bundle(zip, url, Some(&schema_types), false)?,
            url.clone(),
        )),
        _ => None,
    };
    if let Some((s, url)) = bundle {
        schemas = Some((
            schema::SchemaProvenance::new(schema::SchemaSource::Bundle, Some(url), &s),
            s,
        ));
    }
    if let Some((_, s)) = &schemas {
        for (id, checks) in schema::checks(&template, s, data.tf.as_ref()) {
            depth.entry(id).or_default().extend(checks);
        }
    }
    tui::phase("assessing the resources");
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
        input: input_label(args.path.as_deref()),
        source_region: args.from.clone(),
        stacks: stacks(&template),
        source_format: template.format,
        input_kind: template.kind(),
        target_region: region.clone(),
        target_account: args.account.clone(),
        input_environments: template.envs(),
        partitions_version: partition::VERSION.into(),
        knowledge: data
            .urls
            .as_ref()
            .map(|(url, cfn, products)| KnowledgeProvenance {
                url: url.clone(),
                cloudformation_url: cfn.clone(),
                products_url: products.clone(),
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
            source_region: args.from.as_deref(),
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
        &args.to,
        &facts.target_dns_suffix,
        args.profile.as_deref(),
        args.role_arn.as_deref(),
        Duration::from_secs(args.timeout),
    )?;
    let (l, p) = live::run(&caller, needs)?;
    let account = crate::account::run(
        &caller,
        &args.to,
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

/// The input as the summary names it.
fn input_label(path: Option<&str>) -> String {
    match path {
        Some(p) => p.to_string(),
        None if !std::io::stdin().is_terminal() => "stdin".into(),
        None => ".".into(),
    }
}

/// Stacks in a CloudFormation input: CDK ids carry their stack before the last `/`.
fn stacks(t: &Template) -> usize {
    if t.format == SourceFormat::TerraformPlan {
        return 0;
    }
    t.resources
        .keys()
        .map(|id| id.rfind('/').map_or("", |i| &id[..i]))
        .collect::<BTreeSet<_>>()
        .len()
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
    if args.scan.fail_on.is_some() || args.scan.all {
        return Err(ScanError::Input(
            "--fail-on and --all apply to scan, not to plan".into(),
        ));
    }
    Ok(())
}

fn run_plan(args: &PlanArgs) -> Result<i32> {
    check_plan_args(args)?;
    check_regions(args.scan.from.as_deref(), &args.scan.to)?;
    let started = Instant::now();
    tui::start(
        &format!("Planning the move to {}", args.scan.to),
        !args.scan.quiet,
    );
    let assessed = assess(&args.scan).map(|(report, template, facts)| {
        tui::phase("ordering the resources into waves");
        let p = crate::plan::build(&report, &template, &facts, args.scan.from.as_deref());
        (p, report)
    });
    tui::stop();
    let (p, report) = assessed?;
    let json = write_json(
        args.scan.out.as_deref(),
        &output::to_json(&output::plan(&p, &report), args.scan.pretty),
    )?;
    if !args.scan.quiet {
        let run = tui::Run {
            elapsed: Some(started.elapsed()),
            json,
        };
        eprint!(
            "{}",
            crate::summary::plan_summary(&p, &report, tui::Style::for_stderr(), &run)
        );
    }
    Ok(0)
}

fn run_compare(args: &CompareArgs) -> Result<i32> {
    let started = Instant::now();
    tui::start(
        &format!("Comparing {} with {}", args.from, args.to),
        !args.quiet,
    );
    let compared = compare(args);
    tui::stop();
    let c = compared?;
    let json = write_json(
        args.out.as_deref(),
        &output::to_json(&output::compare(&c), args.pretty),
    )?;
    if !args.quiet {
        let run = tui::Run {
            elapsed: Some(started.elapsed()),
            json,
        };
        eprint!(
            "{}",
            crate::summary::compare_summary(&c, tui::Style::for_stderr(), &run)
        );
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
    let live_mode = args.live || args.profile.is_some() || args.role_arn.is_some();
    if args.properties && !live_mode {
        return Err(ScanError::Input(
            "--properties reads the --to Region's schemas from the account and needs --live, --profile or --role-arn".into(),
        ));
    }
    let (from_cn, to_cn) = (
        from_facts.target_partition == china::PARTITION,
        to_facts.target_partition == china::PARTITION,
    );
    let listed = if from_cn && to_cn {
        BTreeSet::new()
    } else {
        knowledge::regions(&client)?
    };
    let (from_url, to_url) = (
        schema::bundle_url(&from_facts),
        schema::bundle_url(&to_facts),
    );
    // China has no product data, whatever the Region list says.
    let (from_products, to_products) = (
        !from_cn && listed.contains(&args.from),
        !to_cn && listed.contains(&args.to),
    );
    let scope = compare::scope(
        &args.from,
        &args.to,
        &compare::Sources {
            from_listed: from_products || from_cn,
            to_listed: to_products || to_cn,
            from_products,
            to_products,
            live: live_mode,
            properties: args.properties,
            from_bundle: from_url.is_some(),
            to_bundle: to_url.is_some(),
        },
    )
    .map_err(ScanError::Input)?;
    tui::phase(format!("fetching {} and {}", args.from, args.to));
    let all = knowledge::Needs {
        config: true,
        ..knowledge::Needs::default()
    };
    // Regions outside China come from one availability fetch, China Regions from their
    // schema bundle; property bundles of the others download alongside.
    let mut regions: Vec<&str> = Vec::new();
    if !from_cn {
        regions.push(&args.from);
    }
    if !to_cn && to_products {
        regions.push(&args.to);
    }
    let to_bundle = scope.to_schemas == Some(schema::SchemaSource::Bundle);
    let (avail, from_china, to_china, from_zip, to_zip) = std::thread::scope(|s| {
        let fc = s.spawn(|| {
            from_cn
                .then(|| china::fetch(&client, &from_facts, None))
                .transpose()
        });
        let tc = s.spawn(|| {
            to_cn
                .then(|| china::fetch(&client, &to_facts, None))
                .transpose()
        });
        let fz = s.spawn(|| {
            from_url
                .as_ref()
                .filter(|_| !from_cn && scope.to_schemas.is_some())
                .map(|u| client.get_bytes(u))
                .transpose()
        });
        let tz = s.spawn(|| {
            to_url
                .as_ref()
                .filter(|_| !to_cn && to_bundle)
                .map(|u| client.get_bytes(u))
                .transpose()
        });
        let avail = (!regions.is_empty())
            .then(|| provider::availability(&client, &regions, &all))
            .transpose();
        let join = "compare fetch does not panic";
        (
            avail,
            fc.join().expect(join),
            tc.join().expect(join),
            fz.join().expect(join),
            tz.join().expect(join),
        )
    });
    let (avail, from_china, to_china) = (avail?, from_china?, to_china?);
    let (from_zip, to_zip) = (from_zip?, to_zip?);
    let cfn_url = avail.as_ref().map(|a| a.cfn_url.to_string());
    let products_url = avail.as_ref().map(|a| a.products_url.to_string());
    let mut fetched = avail.map(|a| a.regions).unwrap_or_default();
    let to = match &to_china {
        Some(c) => c.knowledge.clone(),
        None if !to_cn && to_products => fetched.pop().unwrap_or_default(),
        None => knowledge::Knowledge::default(),
    };
    let from = match &from_china {
        Some(c) => c.knowledge.clone(),
        None => fetched.pop().unwrap_or_default(),
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
    if caller.is_some() {
        tui::phase(format!("reading the {} registry", args.to));
    }
    let (to_types, live_account_id) = match &caller {
        Some(c) => {
            let (account, _) = live::identity(c)?;
            (live::registry_types(c)?, Some(account))
        }
        None => (compare::available_types(&to), None),
    };
    let from_types = compare::available_types(&from);
    let shared: BTreeSet<String> = from_types.intersection(&to_types).cloned().collect();
    let zip_of = |china: &Option<china::China>, zip: Option<Vec<u8>>| match china {
        Some(c) => c.bundle.clone(),
        None => zip,
    };
    let (from_zip, to_zip) = (zip_of(&from_china, from_zip), zip_of(&to_china, to_zip));
    let mut from_prov = None;
    let mut schemas = None;
    if let (Some(url), Some(source), Some(zip)) = (&from_url, scope.to_schemas, &from_zip) {
        let a = schema::read_bundle(zip, url, Some(&shared), true)?;
        from_prov = Some(schema::SchemaProvenance::new(
            schema::SchemaSource::Bundle,
            Some(url.clone()),
            &a,
        ));
        // The scope reads live schemas only in live mode, a bundle only where one exists.
        let (b, url) = match (&caller, source, &to_zip, &to_url) {
            (Some(c), schema::SchemaSource::Live, ..) => {
                tui::phase(format!(
                    "reading {} resource schemas, takes minutes",
                    shared.len()
                ));
                (schema::fetch_live(c, &shared, true)?, None)
            }
            (_, _, Some(zip), Some(u)) => (
                schema::read_bundle(zip, u, Some(&shared), true)?,
                Some(u.clone()),
            ),
            _ => {
                return Err(ScanError::DataSource(format!(
                    "no schemas for {} were read",
                    args.to
                )));
            }
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
            cloudformation_url: cfn_url,
            products_url,
            china_bundle_urls: [&from_china, &to_china]
                .into_iter()
                .flatten()
                .map(|c| c.bundle_url.clone())
                .collect(),
            fetched_at,
            live_account_id,
            from_schemas: from_prov,
            compared_types: schemas.as_ref().map_or(0, |(a, _, b)| {
                a.keys().filter(|t| b.contains_key(*t)).count()
            }),
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

    #[test]
    fn compare_properties_needs_live_mode() {
        let Command::Compare(c) = Cli::try_parse_from([
            "esc-preflight",
            "compare",
            "--from",
            "eu-west-1",
            "--to",
            "eusc-de-east-1",
            "--properties",
        ])
        .unwrap()
        .command
        else {
            panic!("compare");
        };
        assert!(compare(&c).unwrap_err().to_string().contains("--profile"));
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
            "--to",
            "eu-west-1",
        ];
        let Command::Plan(p) = Cli::try_parse_from(same).unwrap().command else {
            panic!("plan");
        };
        assert!(
            check_regions(p.scan.from.as_deref(), &p.scan.to)
                .unwrap_err()
                .to_string()
                .contains("the same Region")
        );
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
