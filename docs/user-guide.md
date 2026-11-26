# esc-preflight User Guide

This guide explains how to act on a scan report, what live mode adds, and how the `plan` and `compare` commands help you prepare a move. The [README](../README.md) covers installation and the basic commands.

## Reading the Scan Report

Every finding that needs action becomes a required change. Its tier says who decides:

| Tier | Meaning | Example |
|---|---|---|
| `fix` | Apply as stated; nothing changes where you deploy today | `arn:aws:` becomes the partition |
| `propose` | Apply after review; the change states its precondition and consequence | the deployment account instead of a literal account ID |
| `flag` | Your decision | an unavailable service, a documented deviation, a dependency |

Each change names the resources and properties it applies to, the replacement in the language of your input, and the source that decided it, such as the ESC User Guide or live mode. For an unavailable service, the report can name a known mitigation, such as another AWS service, with the AWS page that describes it.

Hardcoded values either break in the target, because they name another Region, partition or account, or only tie the input to one Region. Pass `--from <region>` for a template that does not state its Region: literals of that Region then become fixes.

Some findings only need attention:

- **Disputed**: the type exists in the target, but the service is only planned there. Test before relying on it.
- **Caveat**: the feature works with a documented difference. Read the quoted sentence.
- **Guide conflict**: the ESC User Guide and the availability data disagree. Ask your AWS team to confirm.

None of these blocks deployment. In CI, `--fail-on` takes one category: `blocker` fails the build on what cannot deploy, `hazard` on hardcoded values and dependencies, and `disputed` on disputed findings, guide conflicts and resources the scan cannot assess. The JSON report follows the schemas in [`schema/`](../schema); for automation, read its codes and counts, not its text.

## Live Mode

Public sources are not always current, and they can disagree. Live mode reads your account in the target Region with read-only calls and overrides them:

```bash
esc-preflight scan --profile <profile>
```

Live mode also checks Availability Zones, Bedrock models, RDS instance classes and resource properties, and it runs account checks: whether the Region is enabled, whether the input fits the account's quotas, whether service control policies deny the Region or a service, and whether the public SSM parameters the input resolves exist.

The role needs [`iam/esc-preflight-readonly.json`](../iam/esc-preflight-readonly.json) plus read access to the services in your input. Service control policies can only be read from the management account or a delegated administrator; a check the role cannot read is skipped with a warning.

## Plan

`plan` runs the scan, then says how each resource reaches the target. It follows a move done with IaC:

1. Deploy the stacks in the target. Data stores that restore from a copy, such as a DynamoDB table imported from an S3 export, deploy from it.
2. Fill the data stores the stacks created, such as a bucket through S3 Replication.
3. Switch traffic: drain the source queues, and re-encrypt data under the new KMS keys.
4. Retire the source.

```bash
esc-preflight plan template.yaml --from eu-central-1 --out plan.json
```

The summary lists the data to fill, what to handle at the switch, what a scan blocker stops, and what needs a decision, then the steps in order. A resource with no known way is not impossible to move; no documented mechanism covers it yet. Each mechanism rests on a quoted sentence of the AWS documentation, linked in the JSON.

`plan` changes nothing and takes the scan options except `--fail-on` and `--all`.

## Compare

`compare` lists what one Region offers and another does not, with the roadmap state in the target. It needs no IaC, so use it to choose a Region or to check a service before you write code:

```bash
esc-preflight compare --from eu-central-1 --to eusc-de-east-1
```

It covers products and features, CloudFormation resource types, config values such as instance types and engine versions, and resource properties. Products and types that are not expanding to the target, or not available there, are marked red: neither is on its roadmap, so they need an alternative.

ESC publishes no CloudFormation schemas, so for ESC, properties are compared only with `--properties` and an account, such as `--profile <profile> --properties`. This reads the schemas from your account and takes several minutes.

## See Also

- [AWS European Sovereign Cloud User Guide](https://docs.aws.eu/esc/latest/userguide/services.html): the documented service differences
- [AWS Capabilities by Region](https://builder.aws.com/build/capabilities): the public availability data
- [Development](DEVELOPMENT.md): rules, data and tests
