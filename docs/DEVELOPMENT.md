# Development

This guide is for contributors who change or extend esc-preflight: how the code is organized, how to test it, and how to add a rule.

## Build and Test

Requires Rust 1.99 or later.

```bash
cargo test                                   # offline, against tests/fixtures
cargo clippy --all-targets -- -D warnings
cargo deny check                             # licenses, advisories, sources
cargo test -- --ignored --skip live_esc      # also against the live public sources
ESC_PREFLIGHT_PROFILE=<profile> cargo test -- --ignored live_esc   # live mode in an ESC account
```

The ignored tests catch drift in the outside world: every quoted sentence of the rules must still be on its page, every ESC User Guide rule on the live guide, and the public sources must still answer in the shape the code reads. Run them before a release and after changing `data/`. The offline tests read a recorded Knowledge MCP response, `tests/fixtures/knowledge.json`; record it again when tests should see newer data.

The terminal summaries and the JSON reports are compared against golden files in `tests/fixtures/`. After an intended output change, run `UPDATE_GOLDEN=1 cargo test`, which also regenerates the JSON schemas in `schema/`, and review the diff. If a JSON field is removed or renamed, or its meaning changes, increment `SCHEMA_VERSION` in `src/output.rs` and the version the agent skill checks.

## How the Code Fits Together

A run reads the input into one model, checks it against the target, and renders the results twice: as a summary for people and as JSON for automation.

| Step | Code |
|---|---|
| Read CloudFormation, SAM, `cdk.out` or a Terraform plan into one model | `src/reader.rs`, `src/reader/`, `src/model.rs` |
| Fetch availability data, the ESC User Guide and resource schemas | `src/provider/` |
| Find unavailable types and services, values the target does not offer, and documented deviations | `src/depth.rs`, `src/deviation.rs` |
| Find hardcoded values | `src/extractor.rs` |
| Turn findings into required changes with tiers and replacements | `src/remediation.rs` |
| Run the live account checks | `src/account.rs` |
| Build `plan` and `compare` | `src/plan.rs`, `src/compare.rs` |
| Render the summaries and the JSON | `src/summary.rs`, `src/summary/`, `src/tui.rs`, `src/output.rs` |
| Parse the command line and wire the steps | `src/cli.rs` |

Availability data is never bundled. Every run fetches it, so the output reflects the target as of the run, and the `sources` block of the report records what was read.

## Data

`data/` holds what does not change from run to run:

| File | Content | Update |
|---|---|---|
| `rules.json` | Deviations, dependencies, literal forms, quotas and plan mechanisms | By hand, see [Rules](#rules) |
| `mitigations.json` | Known mitigations for gaps, each with a quoted AWS sentence and a `validation` of `documented` or `field-proven` | By hand; `field-proven` needs evidence in the pull request, and internal-only workarounds do not belong here |
| `sam.json` | Per SAM type, its base CloudFormation type and the properties SAM passes through | From the AWS SAM resource reference |
| `cfn-products.json` | CloudFormation namespaces and types whose product name does not follow from the namespace | By hand; the ignored tests fail on a name the sources no longer list |
| `cfn-service-overrides.json` | CloudFormation namespaces whose SDK endpoint prefix is not the lowercased namespace | By hand |
| `esc-guide-pages.json` | ESC User Guide pages per service | By hand, when the live guide test lists an unmapped page |
| `botocore-services.json`, `partitions.json` | Services and partition facts | `uv run --with botocore python3 scripts/gen-botocore-services.py <names_data.hcl>`, for a new partition or Region |
| `cdk-sdk-v2-to-v3.json` | CDK SDK name mapping | Copied from `aws-cdk-lib` |

## Rules

`data/rules.json` is the one rule set for every command. A rule needs an AWS-documented difference or a deterministic target state; whether a service is available comes from the public data and live mode, never from a rule. This deviation rule ties one sentence of the ESC User Guide to the resources that use the feature:

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

| Kind | Use |
|---|---|
| `deviation` | A feature the target does not offer, or offers differently (`severity: caveat`) |
| `dependency` | Something the resource needs stays outside the target |
| `literal` | A literal form that works only in some Regions |
| `exemption` | A literal the target requires at a property, so it is not a hazard there |
| `quota` | A quota the input counts against, for live mode |
| `mechanism` | How a resource moves, for `plan` |

Every rule rests on a source. A `guide` source must match a difference on the [ESC User Guide](https://docs.aws.eu/esc/latest/userguide/services.html), and the rule stops firing when the sentence leaves the guide. A `doc` source quotes a sentence from docs.aws.amazon.com verbatim. `scope` limits a rule to partitions or Regions, and `when` lists alternative conditions on property paths; the structs in `src/rules.rs` define every field.

Three constraints keep rules from contradicting the availability data:

- A rule's `feature` names the product the sentence restricts. Where the public data lists it as available, the blocker becomes a guide conflict warning instead.
- A blocker deviation rule without conditions lists Terraform `aws_*` types only, unless it carries a `remediation`; the availability data already decides CloudFormation types.
- The Lambda runtime lists are static, so the output does not depend on the date. The ignored tests fail when the deprecation table changes.

A blocker fails someone's build, so a wrong rule is costly. To add or change one:

1. Quote the sentence that says the feature is not available, or how it differs, and match only values the input shows.
2. Add a case that fires and a near miss to `tests/fixtures/rule-cases.json`.
3. Check types and paths against the CloudFormation and Terraform schemas:
   ```bash
   curl -sSfLO https://schema.cloudformation.us-east-1.amazonaws.com/CloudformationSchema.zip
   terraform providers schema -json > tf-schema.json   # in a config with the aws and awscc providers
   python3 scripts/check-rules.py CloudformationSchema.zip tf-schema.json
   ```
4. Run `cargo test -- --ignored`, which fails if the sentence is not on its page.

## Known Limits

These are the main gaps, and good places to contribute:

- Only what the input declares is checked, not settings made outside it.
- Custom resources backed by your own code, and nested stacks in a single template, are not assessed. Scanning `cdk.out` or the processed template covers more.
- Terraform `aws_*` resources are checked per service, not per type, and their properties are not checked, because no public source maps their arguments to CloudFormation properties. The `awscc` provider and live mode give type-level answers.
- SAM resources are checked as their base type; resources SAM generates from event sources are not.
- Live quota checks cover VPCs, internet gateways, Elastic IPs and Lambda reserved concurrency only.
- `plan` covers the most frequent resource types; others are reported as needing a decision.
- AWS China publishes no product, roadmap or config value data, so those checks need live mode there.

## Releases

esc-preflight is not published to crates.io. For a new version, bump `version` in `Cargo.toml` and in the skill's metadata and `compatibility`, update the tag in the README install command, merge to `main`, and tag the merge commit `<version>` (no `v` prefix, for example `0.3.1`).
