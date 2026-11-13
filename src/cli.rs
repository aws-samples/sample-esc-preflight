//! Command-line entry point and exit-code contract.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};

use crate::depth::DepthSource;
use crate::error::{Result, ScanError};
use crate::model::{SourceFormat, Template};
use crate::provider::{self, aws_call, http, knowledge, live, partition, terraform};
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
}

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
    /// Not available, a depth value the region does not offer, or a feature the
    /// ESC User Guide documents as not available.
    Blocker,
    /// Any hardcoded value or environment literal.
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
    let Command::Scan(args) = cli.command;
    match scan(&args) {
        Ok(report) => {
            if !args.quiet {
                let stderr = std::io::stderr();
                let unicode = stderr.is_terminal();
                let style = report::Style {
                    unicode,
                    color: unicode && std::env::var_os("NO_COLOR").is_none(),
                };
                eprint!("{}", report::text_summary(&report, style));
            }
            if let Some(f) = args.fail_on
                && fails(&report, f)
            {
                return 2;
            }
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            e.exit_code()
        }
    }
}

fn scan(args: &ScanArgs) -> Result<Report> {
    let region = &args.region;
    let template = read_input(args.path.as_deref(), region)?;
    let client = http::Client::new(Duration::from_secs(args.timeout))?;
    let partition = partition::facts(region)?;
    let tf = (template.format == SourceFormat::TerraformPlan)
        .then(|| terraform::fetch(&client))
        .transpose()?;
    let mut depth = depth::checks(&template, region);
    let checks = checks(&template, tf.as_ref());
    let needs = knowledge::Needs {
        types: checks.iter().filter_map(type_of).cloned().collect(),
        // Also for checks with an operation: the service decides when the server does
        // not know the operation.
        services: checks
            .iter()
            .filter_map(|c| match c {
                Check::Api { service_id, .. } => Some(service_id.clone()),
                Check::Type(_) => None,
            })
            .collect(),
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
    let data = provider::fetch_public(&client, region, partition, tf, &needs)?;
    let fetched_at = report::now_utc();
    let mut offered = depth::public_offered(&data.knowledge);
    depth::resolve(&mut depth, &offered, DepthSource::Knowledge);
    let scan = extractor::hazards(&template, &data.partition);
    let live_mode = args.live || args.profile.is_some() || args.role_arn.is_some();
    let (live, live_prov) = if live_mode {
        let caller = aws_call::Caller::new(
            region,
            &data.partition.target_dns_suffix,
            args.profile.as_deref(),
            args.role_arn.as_deref(),
            Duration::from_secs(args.timeout),
        )?;
        let needs = live::Needs {
            registry: checks.iter().any(|c| type_of(c).is_some()),
            services: checks
                .iter()
                .filter_map(|c| match c {
                    Check::Api { service_id, .. } => Some(service_id.clone()),
                    Check::Type(_) => None,
                })
                .collect(),
            depth: depth.clone(),
            // Also for zone literals: whether a zone index exists in the target decides
            // if a derived zone can replace one.
            zones: scan.env_literals.iter().any(|e| !e.zones.is_empty())
                || scan
                    .hazards
                    .iter()
                    .flat_map(|h| &h.literals)
                    .any(|l| l.kind == extractor::HazardKind::AvailabilityZone),
        };
        let (l, p) = live::run(&caller, region, needs)?;
        depth = l.depth.clone();
        offered.extend(l.offered.clone());
        (Some(l), Some(p))
    } else {
        (None, None)
    };
    let findings = matcher::assess(
        &template,
        &data.knowledge,
        data.tf.as_ref(),
        live.as_ref(),
        &depth,
    );
    let (guide, user_guide) = match &data.guide {
        Some(g) => {
            let (f, p) = deviation::assess(&template, &findings, g, &data.knowledge);
            (f, Some(p))
        }
        None => Default::default(),
    };
    let provenance = Provenance {
        tool_version: env!("CARGO_PKG_VERSION").into(),
        source_format: template.format,
        mode: if live_prov.is_some() {
            "live"
        } else {
            "public"
        }
        .into(),
        target_region: region.clone(),
        input_environments: template.envs(),
        partitions_version: partition::VERSION.into(),
        knowledge: KnowledgeProvenance {
            url: knowledge::URL.into(),
            calls: data.knowledge.calls,
            unknown: data.knowledge.unknown.iter().cloned().collect(),
        },
        user_guide,
        fetched_at,
        terraform: data.tf.as_ref().map(|tf| TerraformProvenance {
            aws_provider_version: tf.aws_version.clone(),
            awscc_provider_version: tf.awscc_version.clone(),
            urls: tf.urls.clone(),
        }),
        live: live_prov,
    };
    let mut report = report::build(
        provenance,
        findings,
        scan,
        guide,
        template.out_of_scope,
        &remediation::Context {
            single_region: data.partition.target_regions == 1,
            target_zones: live.as_ref().and_then(|l| l.target_zones),
            offered: Some(&offered),
        },
    );
    // The summary, which the exit code and stderr read, covers every finding.
    if !args.all {
        report::gaps_only(&mut report);
    }
    let json = report::to_json(&report);
    match &args.out {
        Some(p) => std::fs::write(p, json)
            .map_err(|e| ScanError::Input(format!("cannot write {}: {e}", p.display())))?,
        None if !std::io::stdout().is_terminal() => print!("{json}"),
        None => {}
    }
    Ok(report)
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

fn fails(r: &Report, f: FailOn) -> bool {
    let s = &r.summary;
    match f {
        FailOn::Blocker => s.depth_blockers + s.deviations + s.not_available > 0,
        FailOn::Hazard => s.hazards + s.environment_literals > 0,
        FailOn::Disputed => s.disputed + s.cannot_assess + s.guide_conflicts > 0,
    }
}
