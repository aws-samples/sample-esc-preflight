# AGENTS.md

`esc-preflight` is a Rust CLI that checks CloudFormation templates, CDK cloud assemblies and Terraform plans for the AWS European Sovereign Cloud. User docs: `README.md`. Contributor docs: `docs/DEVELOPMENT.md`.

## Commands

```bash
cargo test                                  # offline; must pass before any commit
cargo clippy --all-targets -- -D warnings
cargo fmt
UPDATE_GOLDEN=1 cargo test                  # after an intended report change; review the diff
```

## Pipeline

`reader` → `type_mapper` → `matcher` (availability) + `deviation` (documented differences) + `extractor` (hardcoded values) + `depth` (offered values) → `remediation` (fix, propose, flag) → `report`.

| Path | Role |
|---|---|
| `src/reader.rs`, `src/reader/` | Parse templates, `cdk.out` and Terraform plan JSON into `src/model.rs` |
| `src/provider/` | Fetch public data (botocore, regional table, ESC endpoints page and User Guide, Terraform provider data) and run live-mode calls |
| `src/remediation.rs` | Tier and edit for every required change |
| `data/esc-guide-rules.json` | Deviation rules, see `docs/DEVELOPMENT.md` |
| `skills/esc-preflight/SKILL.md` | Skill that applies the report to a user's code |
| `tests/fixtures/` | Test inputs and golden reports |

## Rules

- Tests are offline. Network tests are `#[ignore]`d and run with `cargo test -- --ignored`.
- Outbound hosts are an allowlist enforced by `tests/guards.rs`; adding a host means changing that test on purpose.
- Live mode is read-only: only List, Describe and Get calls (`probes_are_read_calls`).
- The CLI never edits files and never calls a model.
- Keep dependencies and flags minimal; prefer deleting code to adding it.
- Every new or changed deviation rule needs a firing case and a near miss in `tests/fixtures/rule-cases.json`.
