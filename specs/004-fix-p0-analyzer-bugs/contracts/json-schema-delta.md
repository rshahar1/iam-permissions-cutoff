# JSON Output Contract Delta: 004-fix-p0-analyzer-bugs

Base contract: `specs/003-iam-audit-cli/contracts/json-schema.md`.

`schema_version` remains `"1.0.0"`. All changes are **additive**; existing consumers keep working.

## Permission findings (`category: "overly_permissive"`) - `metadata`

| Key | Type | Description |
|-----|------|-------------|
| `not_actions` | `string[]` | `NotAction` entries of the statement; empty list when absent. |
| `not_resources` | `string[]` | `NotResource` entries of the statement; empty list when absent. |
| `policy_is_aws_managed` | `boolean` | True when the policy ARN starts with `arn:aws:iam::aws:policy/`. |

Existing keys (`actions`, `resources`, `has_deny_statements`, etc.) are unchanged. For NotAction statements `actions` is an empty list and `not_actions` carries the excluded actions.

## Unused-permission findings

Metadata keys unchanged. Behavioral change only: findings now cover only Access Advisor-tracked actions, and action names use AWS's canonical casing.

## Behavioral notes (not schema changes)

- Roles under `/aws-reserved/` are excluded unless `--include-aws-managed`; consumers will see fewer findings by default.
- When `policy_is_aws_managed` is true, `recommendation` says to detach the policy and replace it with a customer-managed least-privilege policy.
