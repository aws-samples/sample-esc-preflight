# Development

## Build and test

Requires Rust 1.99 or later.

```bash
cargo test                                    # offline, against tests/fixtures
cargo clippy --all-targets -- -D warnings
cargo deny check                              # licenses, advisories, sources
cargo test -- --ignored --skip live_esc       # also the live public sources
ESC_PREFLIGHT_PROFILE=<profile> cargo test -- --ignored live_esc   # live mode in an ESC account
```

The ignored public tests check the Knowledge MCP data, the ESC User Guide (`no_stale_rules_on_the_live_guide`), every quoted sentence of the rules (`doc_quotes_are_on_their_pages`), the Lambda runtime lists against the deprecation table (`runtime_lists_follow_the_deprecation_table`) and a real schema bundle (`live_bundle`). The `live_esc` tests read an ESC account outside an organization: registry and probes, resource schemas (`live_esc_schemas`) and account checks (`live_esc_account`).

After an intended change to the output, regenerate the golden files and the three schema files in `schema/` with `UPDATE_GOLDEN=1 cargo test` and review the diff. If a field was removed or renamed, or its meaning changed, increment the schema version of that output (`SCHEMA_VERSION` in `src/report.rs`, `src/plan.rs` or `src/compare.rs`).

## Code

| Path | Role |
|---|---|
| `src/cli.rs` | Commands `scan`, `plan` and `compare` |
| `src/reader.rs`, `src/reader/` | Templates, `cdk.out` and Terraform plan JSON into `src/model.rs` |
| `src/rules.rs` | Loads `data/rules.json`; conditions, scopes, literal and exemption rules |
| `src/deviation.rs` | Deviation and dependency rules against the input |
| `src/extractor.rs` | Hardcoded literals |
| `src/depth.rs` | Values the target must offer |
| `src/account.rs` | Live account checks |
| `src/plan.rs`, `src/compare.rs` | The `plan` and `compare` outputs |
| `src/provider/schema.rs` | CloudFormation resource schemas: per-Region bundles and `DescribeType`; reads the bundle zip with `miniz_oxide` |
| `src/provider/` (others) | Knowledge MCP, ESC User Guide, Terraform provider data, signed AWS calls, partition facts |

`tests/fixtures/schemas.zip` holds two trimmed schemas from a bundle, one stored and one deflated, written with Python's `zipfile`.

## Data

`data/` holds maps, partition facts and the rules. Availability data is never bundled; every run fetches it from the AWS Knowledge MCP server.

| File | Update |
|---|---|
| `botocore-services.json`, `partitions.json` | `uv run --with botocore python3 scripts/gen-botocore-services.py <names_data.hcl>`; needed for a new partition or Region |
| `rules.json` | By hand, see below |
| `cfn-products.json` | By hand: CloudFormation namespaces and types whose Knowledge MCP product name does not follow from the namespace. `cargo test -- --ignored` fails on a name the server no longer lists, here and in rule `feature`s |
| `cdk-sdk-v2-to-v3.json` | Copied from `aws-cdk-lib` |
| `esc-guide-pages.json` | By hand; the ignored live guide test lists unmapped pages |
| `cfn-service-overrides.json` | By hand |

`tests/fixtures/knowledge.json` is a recorded Knowledge MCP response for eusc-de-east-1; record it again when tests should see newer data.

## Rules

`data/rules.json` is the one rule set for every command. A rule needs an AWS-documented deviation or a deterministic target state; availability itself comes from the Knowledge MCP data and live mode, never from rules. A deviation rule ties one documented difference to the resources that use the feature:

```json
{
  "id": "lambda-xray",
  "kind": "deviation",
  "scope": { "partitions": ["aws-eusc"] },
  "source": { "guide": { "page": "lambda", "text": "X-Ray Integration is not available" } },
  "types": ["AWS::Lambda::Function", "aws_lambda_function"],
  "when": [{ "path": "TracingConfig.Mode", "equals": "Active" },
           { "path": "tracing_config.mode", "equals": "Active" }]
}
```

Kinds:

| Kind | Meaning | Extra fields |
|---|---|---|
| `deviation` | A feature the target does not offer, or offers differently (`severity` `caveat`) | `feature`, `remediation` |
| `dependency` | Something the resource needs stays outside the target; always a flag | `remediation` (required) |
| `literal` | A literal form that works only in some Regions | `pattern` (two captures: the literal, its Region), `replace` per source format |
| `exemption` | A literal the target requires at a property, so it is no hazard there | `paths`, `literal` |
| `quota` | A quota the input counts against; live mode | `quota` (`service_code`, `quota_code`, `name`, `reserve`); `paths` to sum, else one per resource |
| `mechanism` | How a resource moves, for `plan` | `mechanism` (`boundary`, `content`, `path`, `via`, `data`, `crosses_partition`, `layer`, optional `fallback` with its own `url` and `quote`) |

- `scope`: the target `partitions` or `regions` the rule applies to, both empty for any target; `except_regions`; `within_partition` for moves inside one partition (the input's environment is in the target's partition, or, without an environment, `--account` is set).
- `source.guide`: `text`, and every `also` fragment, must appear in one difference on the [ESC User Guide](https://docs.aws.eu/esc/latest/userguide/services.html) page. The rule fires only while it does, and only for targets that read the guide. `source.doc`: a `url` on docs.aws.amazon.com and the sentence the rule rests on, verbatim, as `quote`; these rules apply to every target in their scope.
- `when` conditions are alternatives; `all` requires every condition in it. A condition tests `path` with `equals` or `one_of` (case-insensitive; booleans and numbers as text), `prefix`, `contains`, `not_in` (a string outside the list), `no_other_region` (a string without a breaking Region or zone hazard) or `absent` (no value), or without an operator requires a value. Empty `when`: the type alone fires the rule. For mechanism rules, rules with conditions are tried first.
- `feature`: the Knowledge MCP product or feature the sentence restricts. When the server lists it as available, the blocker becomes a guide conflict warning.
- Types-only deviation rules carry Terraform `aws_*` types only: the Knowledge MCP data and live mode decide CloudFormation types. The exception is a rule with `remediation`.
- `remediation` (`action`, `change`, `consequence`, `doc`; `action` is the short form for the terminal summary). On guide rules, only for features that cannot exist in a single-region partition.
- The Lambda runtime lists are static, so the output does not depend on the date. Update them when the deprecation table changes; the ignored test fails when it does.

A blocker fails someone's build, so a wrong rule is costly. To add or change a rule:

1. Quote a sentence that says the feature is not available, or for a caveat how it differs, and match only values the template shows.
2. Add a case that fires and a near miss to `tests/fixtures/rule-cases.json` (deviation and dependency rules with conditions).
3. Check types and paths against the CloudFormation and Terraform schemas:
   ```bash
   curl -sSfLO https://schema.cloudformation.us-east-1.amazonaws.com/CloudformationSchema.zip
   terraform providers schema -json > tf-schema.json   # in a config with the aws and awscc providers
   python3 scripts/check-rules.py CloudformationSchema.zip tf-schema.json
   ```
4. Run `cargo test -- --ignored`, which fails if a guide rule's sentence is not on the live guide or a quote is not on its page.

## Limitations

Scan:

- Only what the input declares is assessed, not settings made outside it.
- Custom resources backed by your own code, SAM resources (`AWS::Serverless::*`) and nested stacks in a single template are reported as not assessable. Scan `cdk.out` or the processed template instead. SAM `Globals` are not read, so a runtime set only there is not checked.
- Terraform `aws_*` resources are assessed per service, not per resource type. Plan with the awscc provider, or use live mode, for type-level answers.
- Roadmap states need a product name for the namespace; namespaces without one show no roadmap.
- Terraform resource IDs count only where the configuration writes them as constants; IDs in variable defaults and locals are not reported.
- S3 Signature Version 2 is a client setting, not part of IaC, and is not checked.
- Property checks compare top-level properties of `AWS::` CloudFormation types; SAM types, custom resources (including `AWS::CloudFormation::CustomResource`) and Terraform inputs are not checked. A value under `Fn::If` counts as set. Any transform other than SAM and language extensions, in any stack of a CDK assembly, turns the checks off with a warning. In AWS GovCloud (US), some types have older schemas (for example `AWS::CloudFormation::Stack`), so properties such as `StackName` are reported there.
- `aws:RequestedRegion` is found in IAM, SCP, S3 bucket, KMS key and VPC endpoint policies the input writes out; Terraform policies left as `aws_iam_policy_document` references are not checked, for `aws:RequestedRegion` or for account IDs.
- A fixed S3 bucket name inside `Fn::Sub` or `Fn::Join` is not checked. In a Terraform plan with `--account`, a name that already holds the planning account may be flagged. A bucket name in a CDK assembly that holds the environment's Region gets neither a hazard nor the dependency.
- The deprecated-runtime caveat is a caveat in ESC too; no source lists ESC's runtimes separately.
- `scripts/check-rules.py` does not check SAM paths.

Live account checks:

- Quotas compare what the input alone needs, not what the account already uses.
- Service control policies are read only from the management account or a delegated administrator. Only Deny statements with `aws:RequestedRegion` and String operators are evaluated; allow-list SCPs are not evaluated. `conditional` marks a denying statement with further conditions or limited actions.
- Public SSM parameters overridden at deploy time, and Terraform `aws_ssm_parameter` data sources, are not checked.

Plan and compare:

- `plan` covers the most frequent resource types; `unknown` means no rule covers the type. It does not follow nested-stack or cross-stack references, and Terraform plans follow the layers only. Proposals count as blocking until applied.
- `compare` reads properties from schema bundles only where both Regions publish one, else from the account with `--profile`.

## Releases

Not published to crates.io. For a new version, bump `version` in `Cargo.toml` and in the skill's metadata and `compatibility`, tag `<version>` (no `v` prefix, e.g. `0.3.0`) and update the tag in the README install command.
