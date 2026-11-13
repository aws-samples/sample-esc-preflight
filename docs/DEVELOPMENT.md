# Development

## Build and test

Requires Rust 1.99 or later.

```bash
cargo test                                    # offline, against tests/fixtures
cargo clippy --all-targets -- -D warnings
cargo deny check                              # licenses, advisories, sources
cargo test -- --ignored                       # also the live public sources
ESC_PREFLIGHT_PROFILE=<profile> cargo test -- --ignored   # also live mode in an ESC account
```

After an intended change to the report, regenerate the golden files with `UPDATE_GOLDEN=1 cargo test` and review the diff.

## Data

`data/` holds maps, partition facts and the deviation rules. Availability data is never bundled; every scan fetches it from the AWS Knowledge MCP server.

| File | Update |
|---|---|
| `botocore-services.json`, `partitions.json` | `uv run --with botocore python3 scripts/gen-botocore-services.py <names_data.hcl>`; needed for a new partition or Region |
| `esc-guide-rules.json` | By hand, see below |
| `cfn-products.json` | By hand: CloudFormation namespaces and types whose Knowledge MCP product name does not follow from the namespace. `cargo test -- --ignored` fails on a name the server no longer lists, here and in rule `feature`s |
| `cdk-sdk-v2-to-v3.json` | Copied from `aws-cdk-lib` |
| `esc-guide-pages.json` | By hand; the report warns about unmapped pages |
| `cfn-service-overrides.json` | By hand |

`tests/fixtures/knowledge.json` is a recorded Knowledge MCP response for eusc-de-east-1; record it again when tests should see newer data.

## Deviation rules

A rule ties one difference in the [ESC User Guide](https://docs.aws.eu/esc/latest/userguide/services.html) to the resources that use the feature:

```json
{
  "id": "lambda-xray",
  "page": "lambda",
  "text": "X-Ray Integration is not available",
  "types": ["AWS::Lambda::Function", "aws_lambda_function"],
  "when": [{ "path": "TracingConfig.Mode", "equals": "Active" },
           { "path": "tracing_config.mode", "equals": "Active" }]
}
```

- `text`, and every `also` fragment, must appear in one difference on the page. The rule fires only while it does.
- `when` conditions are alternatives; `all` requires every condition in it. A condition tests `path` with `equals`, `prefix`, `contains`, `not_in` (a string outside the list) or `absent` (no value), or without an operator requires a value. Empty `when`: the type alone fires the rule.
- `severity`: `blocker` (default) or `caveat`, for a feature that works with an ESC difference. Caveats never block.
- `feature`: the Knowledge MCP product or feature the sentence restricts. When the server lists it as available, the blocker becomes a guide conflict warning.
- Types-only rules carry Terraform `aws_*` types only: the Knowledge MCP data and live mode decide CloudFormation types. The exception is a rule with `remediation`.
- `remediation` (`action`, `change`, `consequence`, `doc`; `action` is the short form for the terminal summary) is only for features that cannot exist in a single-region partition.

A blocker fails someone's build, so a wrong rule is costly. To add or change a rule:

1. Quote a sentence that says the feature is not available, or for a caveat how it differs, and match only values the template shows.
2. Add a case that fires and a near miss to `tests/fixtures/rule-cases.json`.
3. Check types and paths against the CloudFormation and Terraform schemas:
   ```bash
   curl -sSfLO https://schema.cloudformation.us-east-1.amazonaws.com/CloudformationSchema.zip
   terraform providers schema -json > tf-schema.json   # in a config with the aws and awscc providers
   python3 scripts/check-rules.py CloudformationSchema.zip tf-schema.json
   ```
4. Run `cargo test -- --ignored`, which fails if a rule's sentence is not on the live guide.

## Limitations

- Only what the input declares is assessed, not settings made outside it.
- Custom resources backed by your own code, SAM resources (`AWS::Serverless::*`) and nested stacks in a single template are reported as not assessable. Scan `cdk.out` or the processed template instead.
- In a Terraform plan for a commercial Region, ARNs built from `data.aws_partition` look hand-written. Plan against the ESC Region where you can.
- Terraform `aws_*` resources are assessed per service, not per resource type. Plan with the awscc provider, or use live mode, for type-level answers.
- Roadmap states need a product name for the namespace; namespaces without one show no roadmap.

## Releases

Not published to crates.io. For a new version, bump `version` in `Cargo.toml`, tag `<version>` (no `v` prefix, e.g. `0.2.0`) and update the tag in the README install command.
