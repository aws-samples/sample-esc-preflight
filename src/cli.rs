//! Command-line entry point and exit-code contract.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};

use crate::error::{Result, ScanError};
use crate::model::{SourceFormat, Template};
use crate::provider::{self, PublicData, aws_call, http, live, regional_table};
use crate::remediation;
use crate::report::{self, Provenance, Report, TerraformProvenance};
use crate::type_mapper::{LiveCheck, Mapping, TypeMapper};
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
    /// CloudFormation template (JSON or YAML), `cdk.out` directory, or
    /// `terraform show -json` output. Omit or use `-` to read stdin.
    template: Option<String>,
    /// `public`: public AWS data only. `live`: also check a target-region account (read-only).
    #[arg(long, value_enum, default_value_t = Mode::Public)]
    mode: Mode,
    /// AWS profile for live mode. Without it, the default credential chain is used.
    #[arg(long)]
    profile: Option<String>,
    /// Role to assume for live mode, on top of the profile or default credentials.
    #[arg(long)]
    role_arn: Option<String>,
    /// Write the JSON report here instead of stdout.
    #[arg(long)]
    out: Option<PathBuf>,
    /// `full`: every resource with sources and verdict. `gaps`: only findings that need action or verification.
    #[arg(long, value_enum, default_value_t = Detail::Full)]
    detail: Detail,
    /// Exit 2 when a finding of this kind exists.
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,
    /// Region to assess against. Outside ESC the assessment uses fewer sources.
    #[arg(long, default_value = "eusc-de-east-1")]
    target_region: String,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 30)]
    timeout: u64,
    /// Do not print the summary to stderr.
    #[arg(long, short)]
    quiet: bool,
}

const SCAN_HELP: &str = "\
The JSON report goes to stdout (or --out), the summary to stderr.

Examples:
  esc-preflight scan cdk.out --detail gaps
  terraform show -json plan.out | esc-preflight scan --fail-on blocker
  esc-preflight scan template.yaml --mode live --profile esc

Exit codes:
  0  report produced
  1  invalid input or arguments
  2  a --fail-on finding exists
  3  a data source failed
  4  live-mode authentication failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    Public,
    Live,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Detail {
    Full,
    Gaps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FailOn {
    /// Not available, a depth value the region does not offer, or a feature the
    /// ESC User Guide documents as not available.
    Blocker,
    /// Any hardcoded value or environment literal.
    Hazard,
    /// Any disputed or cannot-assess finding.
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
    let template = match args.template.as_deref() {
        Some(path) => reader::read(path)?,
        None if std::io::stdin().is_terminal() => {
            return Err(ScanError::Input(
                "no input: pass a path or pipe a template to stdin".into(),
            ));
        }
        None => reader::read("-")?,
    };
    let client = http::Client::new(Duration::from_secs(args.timeout))?;
    let data = provider::fetch_public(
        &client,
        &args.target_region,
        template.format == SourceFormat::TerraformPlan,
    )?;
    let fetched_at = report::now_utc();
    let scan = extractor::hazards(&template, &data.botocore.partition);
    let (live, live_prov) = match args.mode {
        Mode::Public => (None, None),
        Mode::Live => {
            let caller = aws_call::Caller::new(
                &args.target_region,
                &data.botocore.partition.target_dns_suffix,
                args.profile.as_deref(),
                args.role_arn.as_deref(),
                Duration::from_secs(args.timeout),
            )?;
            let mut needs = live_needs(&template, &data, &args.target_region);
            // Also for zone literals: whether a zone index exists in the target decides
            // if a derived zone can replace one.
            needs.zones = scan.env_literals.iter().any(|e| !e.zones.is_empty())
                || scan
                    .hazards
                    .iter()
                    .flat_map(|h| &h.literals)
                    .any(|l| l.kind == extractor::HazardKind::AvailabilityZone);
            let (l, p) = live::run(&caller, &args.target_region, needs)?;
            (Some(l), Some(p))
        }
    };
    let findings = matcher::assess(&template, &data, live.as_ref());
    let (guide, user_guide) = match &data.guide {
        Some(g) => {
            let (f, p) = deviation::assess(&template, &findings, g);
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
        target_region: args.target_region.clone(),
        input_environments: template.envs(),
        botocore_version: data.botocore.botocore_version.clone(),
        botocore_urls: data.botocore.urls.clone(),
        regional_table_url: regional_table::URL.into(),
        regional_table_source_version: data.regional_table.source_version.clone(),
        regional_table_unmapped: data.regional_table.unmapped_names.clone(),
        endpoints_docs_url: data.endpoints_page.as_ref().map(|d| d.url.clone()),
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
            single_region: data.botocore.partition.target_regions == 1,
            target_zones: live.as_ref().and_then(|l| l.target_zones),
            offered: live.as_ref().map(|l| &l.offered),
        },
    );
    // The summary, which the exit code and stderr read, covers every finding.
    if args.detail == Detail::Gaps {
        report::gaps_only(&mut report);
    }
    let json = report::to_json(&report);
    match &args.out {
        Some(p) => std::fs::write(p, json)
            .map_err(|e| ScanError::Input(format!("cannot write {}: {e}", p.display())))?,
        None => print!("{json}"),
    }
    Ok(report)
}

/// The live checks this input needs, so live mode makes no call it does not use.
fn live_needs(template: &Template, data: &PublicData, target_region: &str) -> live::Needs {
    let mapper = TypeMapper::new(
        data.botocore.known_services.iter().cloned(),
        data.tf.as_ref(),
    );
    let mut needs = live::Needs {
        depth: depth::checks(template, target_region),
        ..live::Needs::default()
    };
    for r in template.resources.values() {
        let (service, check) = match mapper.map(r) {
            Mapping::Service { service, live } => (Some(service), Some(live)),
            Mapping::Unknown { live, .. } => (None, live),
            Mapping::Pseudo => (None, None),
        };
        match check {
            Some(LiveCheck::Registry(_)) => needs.registry = true,
            Some(LiveCheck::ServiceApi) => needs.services.extend(service),
            None => {}
        }
    }
    needs
}

fn fails(r: &Report, f: FailOn) -> bool {
    let s = &r.summary;
    match f {
        FailOn::Blocker => s.depth_blockers + s.deviations + s.not_available > 0,
        FailOn::Hazard => s.hazards + s.environment_literals > 0,
        FailOn::Disputed => s.disputed + s.cannot_assess > 0,
    }
}
