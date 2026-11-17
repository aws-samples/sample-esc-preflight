# Edit recipes

Each `edits` entry names the property `path`, the literal to `find` and its `replace` per source. Replace every occurrence of `find` in that value. `${...}` in `replace` is an expression and other text is literal, such as a service principal swap. A zone replacement is an expression that replaces the whole value. Change only the matched literal; keep formatting and comments. Apply all approved edits at one `path` in one pass.

## CDK

- Put `replace.cdk` into the string as a template literal (`` `arn:${Aws.PARTITION}:...` ``). Escape a `${` already in the string as `\${`. Import `Aws` or `Stack` from `aws-cdk-lib` if missing.
- The replacements are TypeScript. In Python, Java, C# or Go use the same members (`Aws.PARTITION`, `Stack.of(this).availabilityZones`) in that language's string formatting.
- Prefer a helper that derives the value: `Stack.of(this).formatArn`, `Arn.format`, `Stack.of(this).region`.
- `Aws.*` values are tokens until deployment. If the literal feeds a branch (`if (region === ...)`), a map key, a lookup or a property validated at construct time, do not edit; flag it.
- One construct used in several stacks clears several entries with one edit.
- `cdk_path` is null for outputs, for `*` and when path metadata is disabled; find the literal by searching the source.
- A literal equal to the input's own Region, zone or account is counted as an environment literal, not a hazard. To find hand-typed ones, synthesize without `env` if the app allows it and scan again. Without `env`, a stack sees two zones; `availabilityZones[2]` and later need an explicit account and Region.

## CloudFormation

- Wrap the value in `Fn::Sub` and put `replace.cloudformation` in place of `find`. Escape a `${` already in the value as `${!` (`${aws:username}` becomes `${!aws:username}`). Inside an existing `Fn::Sub`, edit in place.
- Inside `Fn::Join`, wrap only the element that holds the literal.
- A `Fn::Select`/`Fn::GetAZs` replacement replaces the whole value.

## Terraform

- `path` starts with `values.`, the plan attribute path. Map it to the resource argument; `values.policy.Statement[0]...` is the JSON inside `policy`.
- The literal may sit in `data "aws_iam_policy_document"`, `jsonencode(...)`, a `locals` block, a variable default or tfvars. A module from a registry or another repository is outside the input: flag it with the module address.
- Put `replace.terraform` into the string and add the data source it references once: `data "aws_partition" "current" {}`, `data "aws_region" "current" {}`, `data "aws_caller_identity" "current" {}`, `data "aws_availability_zones" "available" {}`. If the `hashicorp/aws` version in `.terraform.lock.hcl` is below 6.0, use `data.aws_region.current.name` instead of `.region`.
- A file loaded with `file()` needs `templatefile()` with the value passed in, for example `templatefile("def.json", { partition = data.aws_partition.current.partition })` and `arn:${partition}:` in the file; escape any other `${` there as `$${`.
- `count` and `for_each` instances (`aws_x.y[0]`, `aws_x.y["a"]`) are one source edit.
- Sensitive values are redacted before the scan; note that under Not checked.
