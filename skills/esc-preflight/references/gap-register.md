# Gap register

`PREFLIGHT-GAPS.md` at the project root. One top-level section per target Region; a scan for a second target adds a section. Key each entry by `logical_id`, `cause.type` and `cause.ids`, plus the property path in `reason` when a resource has more than one entry with the same cause. State the decision and what it depends on; recommend no architecture. Quote account IDs only where the report does.

```
# Preflight gaps: <target_region>

Input <path>, produced for <input_environments> · esc-preflight <tool_version> · <date> · mode <public|live>

## Decisions needed

### <logical_id> (<cdk_path or address>) · <cause.type> <cause.ids>
- Finding: <reason>
- Documented: <doc; roadmap status and launch quarter>
- Decision needed: <change>
- Known mitigations: <per entry of `mitigations`: summary; tradeoffs; doc; validation. Omit the line when there are none>
- Before deciding, the owner needs: <what the code cannot tell: which callers use the endpoint, whether data must move, which account replaces this one>
- Decision: <left for the owner>

## Declined proposals
<same fields, plus what the user said>

## Verify
<disputed, cannot-assess, caveats, guide conflicts, unknown to the public availability data, stale rules, out of scope>

## Not in the report
<blockers you found, with file and line>

## Not checked
<sensitive Terraform values, custom resource code, environment literals of the input's own Region>
```
