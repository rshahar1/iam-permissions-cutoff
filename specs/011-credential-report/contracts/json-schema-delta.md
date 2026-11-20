# JSON Output Contract Delta: 011-credential-report

Base contract: `specs/003-iam-audit-cli/contracts/json-schema.md`.

`schema_version` remains `"1.0.0"`. All changes are **additive**.

## New category

`category: "credential"` (text/HTML heading "Credential Findings"). It appears in `summary.by_category` only when findings exist. `principal_type` is `"user"` or `"root"` (root account, `principal_name` `<root_account>`).

## Metadata

| Key | Type | Rules | Description |
|-----|------|-------|-------------|
| `rule_id` | `string` | all | `CRED-001` to `CRED-008`. |
| `active_key_slots` | `integer[]` | CRED-001, CRED-007 | Active access key slots (1 and/or 2). |
| `mfa_active` | `boolean` | CRED-002, CRED-004 | Always `false` for these rules. |
| `password_enabled` | `boolean` | CRED-004, CRED-008 | Always `true` for these rules. |
| `password_last_used` | `string \| null` | CRED-003, CRED-008 | ISO 8601 timestamp, or null when never used. |
| `user_creation_time` | `string` | CRED-008 | ISO 8601 timestamp. |
| `key_slot` | `integer` | CRED-005, CRED-006 | Access key slot, 1 or 2 (one finding per key). |
| `last_rotated` | `string \| null` | CRED-005, CRED-006 | ISO 8601 timestamp of the key's last rotation. |
| `last_used_date` | `string \| null` | CRED-005, CRED-006 | ISO 8601 timestamp, or null when never used. |
| `max_age_days` | `integer` | CRED-005 | The `--key-max-age` value. |
| `threshold_days` | `integer` | CRED-003, CRED-006, CRED-008 | The `--days` value. |

## Behavioral notes (not schema changes)

- `report` now also runs the credential check, so it needs `iam:GenerateCredentialReport` and `iam:GetCredentialReport`; when denied or timed out, `data_gaps` gets an entry with `principal_arn` `credential-report`.
- New option `--key-max-age N` (default 90) and new subcommand `credentials`.
