# 🛫 esc-preflight

Checks a CloudFormation or AWS SAM template, CDK app or Terraform plan for compatibility with the AWS European Sovereign Cloud (ESC), or any other target Region or partition, before you deploy:

* resource types, services and API operations the target does not offer, with their roadmap state (planned for a quarter, being planned, not expanding)
* features the [ESC User Guide](https://docs.aws.eu/esc/latest/userguide/services.html) documents as not available, and caveats for features that behave differently
* EC2 instance types, RDS engine versions, ElastiCache node types, Lambda runtimes, and resource properties the target does not offer
* hardcoded Regions, zones, partitions, DNS suffixes, accounts and resource IDs, such as `arn:aws:`, `amazonaws.com`, `eu-central-1` or `ami-0abc...`
* in live mode: Region opt-in, quotas, service control policies and public SSM parameters

Two more commands help plan a move: `plan` says how each resource reaches the target with IaC, which data stores to fill and what blocks, and `compare` lists what one Region offers and another does not.

It runs locally, read-only, and makes no AI model calls.

![esc-preflight scanning a CDK app, then its summary](docs/scan.gif)

## What is this good for?

* Find out whether the IaC templates behind your AWS landing zone and cloud workloads deploy in ESC.
* Give your AI coding assistant a deterministic check for the IaC it writes, instead of relying on trial and error.
* Run `esc-preflight scan --fail-on blocker` in CI, so no pipeline ships a service, feature or value ESC does not offer.
* In an automated migration, scan, change and re-scan IaC code until no blockers remain, across repositories.
* Move between any Regions or partitions, not only to ESC: `--to eu-west-1` for a move within the global partition, `--to us-gov-west-1` for AWS GovCloud (US), or `--to cn-north-1` for AWS China.

## Install

Requires [Rust](https://www.rust-lang.org/tools/install) 1.99 or later.

```bash
cargo install --locked --git https://github.com/aws-samples/sample-esc-preflight --tag 0.3.1
```

## How it works

![How esc-preflight works](docs/how-it-works.png)

## Scan

Run in your project directory:

| Input | Command |
|---|---|
| CDK app | `AWS_REGION=eusc-de-east-1 cdk synth && esc-preflight scan` |
| CloudFormation | `esc-preflight scan template.yaml` |
| Terraform | `terraform plan -out=tfplan && terraform show -json tfplan \| esc-preflight scan` |

* Without a path, `scan` reads `cdk.out` or a single template in the current directory.
* For a target other than ESC, add `--to <region>` and synthesize or plan for that Region.
* For a template that does not say which Region it was written for, add `--from <region>` with the Region it runs in today: a literal of that Region then counts as the deployment's own Region, and its fix is the deployment Region.
* The summary goes to stderr. The JSON report goes to `--out <file>`, or to stdout when it is redirected; the summary's last line says where it went.
* Add `--profile <profile>` to also check your account in the target (live mode, recommended).

## Plan

`plan` says how each resource reaches the target with IaC: what redeploys, which data stores to fill, what is blocked and what needs a decision. [More in the user guide](docs/user-guide.md#plan).

```bash
esc-preflight plan template.yaml --from eu-central-1 --out plan.json
```

## Compare

`compare` lists what one Region offers and another does not, with roadmap states, and needs no IaC. [More in the user guide](docs/user-guide.md#compare).

```bash
esc-preflight compare --from eu-central-1 --to eusc-de-east-1
```

## Agent skill

[`skills/esc-preflight/`](skills/esc-preflight/SKILL.md) lets a coding agent take your IaC to a target Region: it scans, applies fixes in your source, asks before each proposal, records flags in `PREFLIGHT-GAPS.md` and rescans. It never deploys or commits. Review `git diff` before you commit.

Copy the folder into your project, or into the same folder under your home directory:

| Harness | Folder |
|---|---|
| Claude Code | `.claude/skills/esc-preflight/` |
| Kiro | `.kiro/skills/esc-preflight/` |
| Codex, GitHub Copilot, Cursor, Gemini CLI | `.agents/skills/esc-preflight/` |

The skill can also use the [AWS Knowledge MCP server](https://awslabs.github.io/mcp/servers/aws-knowledge-mcp-server) to research flags, for example where a substitute service is available. It needs no AWS account:

```json
{ "mcpServers": { "aws-knowledge-mcp-server": { "url": "https://knowledge-mcp.global.api.aws", "type": "http" } } }
```

The server's answers go into the gap register; the scanner's report alone decides what the agent edits.

## Options

`esc-preflight scan [OPTIONS] [PATH]`

| Option | Default | Description |
|---|---|---|
| `PATH` | current directory or stdin | Template, CDK app or `cdk.out`, or `terraform show -json` output; `-` reads stdin |
| `--profile <name>` | | AWS profile; turns on live mode |
| `--role-arn <arn>` | | Role to assume; turns on live mode |
| `--live` | | Live mode with the default credential chain |
| `--account <id>` | | Account the input moves to; other accounts' IDs then break |
| `--all` | | Report every resource, not only gaps, and every documented difference of the input's services |
| `--fail-on blocker\|hazard\|disputed` | | Exit 2 on a matching finding; `hazard` includes `portability` literals and dependencies, `disputed` includes guide conflicts |
| `--out <file>` | stdout when redirected | JSON report file |
| `--pretty` | | Indent the JSON report |
| `--to <region>` | `eusc-de-east-1` | The Region to move to |
| `--from <region>` | | The Region the workload runs in today, for a template that does not say it |
| `--timeout <seconds>` | `60` | Per-request timeout |
| `-q`, `--quiet` | | No summary and no progress line |

`esc-preflight plan` takes the scan options except `--fail-on` and `--all`. `esc-preflight compare --from <region>` requires `--from` and takes `--to`, the live mode options, `--properties`, `--out`, `--pretty`, `--timeout` and `-q`.


Exit codes: `0` report produced, `1` invalid input, `2` `--fail-on` matched (`scan` only), `3` a data source failed, `4` live-mode authentication failed.

CI example:

```bash
esc-preflight scan --fail-on blocker -q --out esc-report.json
```

For how to read the report, what live mode checks, and `plan` and `compare` in detail, see the [user guide](docs/user-guide.md).

## Network access

Every run fetches current data, with no cache. Allow these hosts:

| Host | Data |
|---|---|
| `prod.capabilities.builder.aws.com` | Products with roadmap states, CloudFormation resource types and config values for every Region of the run (the data behind [AWS Capabilities by Region](https://builder.aws.com/build/capabilities)) |
| `knowledge-mcp.global.api.aws` | API availability, the not-expanding state of products, and products the capabilities API does not list ([AWS Knowledge MCP server](https://awslabs.github.io/mcp/servers/aws-knowledge-mcp-server)); everything when the capabilities API fails |
| `docs.aws.eu` | ESC User Guide, ESC targets only |
| `schema.cloudformation.<region>.amazonaws.com` (`.amazonaws.com.cn` in China) | The Region's CloudFormation resource schemas, for property checks in public mode, and the resource types of AWS China; not for ESC |
| `raw.githubusercontent.com` | AWS SDK endpoint data (botocore `endpoints.json`) for AWS China targets; Terraform provider type maps for Terraform input |
| `registry.terraform.io` | Terraform provider versions, Terraform input only |
| AWS endpoints in the target Region | Live mode only; Organizations in the partition's Organizations Region |

Public sources are not always up to date, and they can disagree. Where you have read access to an account in the target Region, use live mode: it reads the target itself and overrides public data.

## Related AWS resources

*esc-preflight* checks your IaC. These public AWS resources cover what it does not:

* [Capability Insights for AWS](https://docs.aws.amazon.com/solutions/capability-insights-for-aws/) ([source](https://github.com/aws/capability-insights-for-aws)): a Regional availability dashboard you deploy in your own account, including Region-scoped IAM policies and SCPs.
* [Service Quotas Replicator for AWS](https://github.com/aws-samples/sample-service-quotas-replicator-for-aws): compares service quotas between accounts and Regions.
* [Workload Discovery on AWS](https://aws.amazon.com/solutions/implementations/workload-discovery-on-aws/): maps the resources a workload runs today, including those not in IaC.
* [CloudFormation IaC generator](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/generate-IaC.html) and [AWS Resource Explorer](https://docs.aws.amazon.com/resource-explorer/latest/userguide/welcome.html): find resources that are not in IaC yet and generate templates for them, which *esc-preflight* can then scan.
* [Considerations for migrating workloads between AWS Regions](https://aws.amazon.com/blogs/mt/considerations-for-migrating-workloads-between-aws-regions/): what to plan beyond the IaC within a partition.

## Development

Tests, data maintenance and limitations: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Notice

This is sample code, for non-production usage. You should work with your security and legal teams to meet your organizational security, regulatory and compliance requirements before deployment. Third-party attributions are in [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES).

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
