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

`data/` holds service metadata and the deviation rules. Availability data is never bundled; every scan fetches it.

| File | Update |
|---|---|
| `botocore-services.json` | `python3 scripts/gen-botocore-services.py <names_data.hcl>` (needs `pip install botocore`) |
| `esc-guide-rules.json` | By hand, see below |
| `cdk-sdk-v2-to-v3.json` | Copied from `aws-cdk-lib` |
| `esc-guide-pages.json`, `regional-table-names.json` | By hand; the report warns about unmapped pages and names |
| `cfn-service-overrides.json` | By hand |

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
- `when` conditions are alternatives; `all` requires every condition in it. A condition tests `path` with `equals`, `prefix` or `contains`, or without an operator requires a value. Empty `when`: the type alone fires the rule.
- `remediation` (`change`, `consequence`, `doc`) is only for features that cannot exist in a single-region partition.

A deviation is a blocker, so a wrong rule fails someone's build. To add or change a rule:

1. Quote a sentence that says the feature is not available, and match only values the template shows.
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

## Releases

Not published to crates.io. For a new version, bump `version` in `Cargo.toml`, tag `<version>` (no `v` prefix, e.g. `0.1.0`) and update the tag in the README install command.
