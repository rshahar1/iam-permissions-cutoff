# JSON Output Schema: iam-audit

**Branch**: `003-iam-audit-cli` | **Date**: 2026-03-11

## Envelope

All JSON output uses a single top-level structure regardless of subcommand.

```json
{
  "schema_version": "1.0.0",
  "account_id": "123456789012",
  "audit_timestamp": "2026-03-08T14:30:00Z",
  "threshold_days": 90,
  "include_aws_managed": false,
  "filters": {
    "path_prefix": null,
    "name_pattern": null,
    "tags": null
  },
  "summary": {
    "total_findings": 15,
    "principals_scanned": 120,
    "data_gaps_count": 2,
    "by_category": {
      "dormancy": 5,
      "permission": 7,
      "unused_permission": 3
    },
    "by_severity": {
      "critical": 2,
      "high": 5,
      "medium": 6,
      "low": 2
    }
  },
  "findings": [ "..." ],
  "data_gaps": [ "..." ]
}
```

**Sort order**: The `findings` array is sorted by severity descending (Critical → High → Medium → Low), then alphabetically by `principal_name` within the same severity (FR-037).

## Finding Object

```json
{
  "principal_arn": "arn:aws:iam::123456789012:role/my-role",
  "principal_name": "my-role",
  "principal_type": "role",
  "category": "dormancy",
  "severity": "high",
  "title": "Role unused for 180 days",
  "description": "Role 'my-role' was last assumed on 2025-09-08. This exceeds the 90-day dormancy threshold.",
  "recommendation": "Delete this role or investigate if it is still needed.",
  "metadata": {}
}
```

### Metadata by Category

**dormancy**:
```json
{
  "last_activity": "2025-09-08T10:00:00Z",
  "days_inactive": 180,
  "has_password": false
}
```
`last_activity` is `null` for never-used principals. `has_password` applies to users only (always `false` for roles).

**permission**:
```json
{
  "policy_name": "AdminAccess",
  "policy_type": "inline",
  "statement_sid": "AllowAll",
  "actions": ["*"],
  "resources": ["*"],
  "has_deny_statements": false
}
```
`policy_type` is `"inline"`, `"managed"`, or `"group"`. `has_deny_statements` is `true` when the principal has explicit Deny statements in any of its policies (FR-036). When `true`, the finding description includes a note about potential Deny restrictions.

**unused_permission**:
```json
{
  "service_namespace": "s3",
  "unused_actions": ["PutObject", "DeleteObject"],
  "keep_actions": ["GetObject", "ListBucket"],
  "last_accessed": "2025-12-01T10:00:00Z",
  "granularity": "ACTION_LEVEL"
}
```
`granularity` is `"ACTION_LEVEL"` or `"SERVICE_LEVEL"`. When `"SERVICE_LEVEL"`, `unused_actions` and `keep_actions` are `null` and the finding is at the service level. `last_accessed` is `null` when the service was never accessed.

## Data Gap Object

```json
{
  "principal_arn": "arn:aws:iam::123456789012:role/new-role",
  "reason": "Newly created (less than 24 hours old)"
}
```

## Field Constraints

| Field | Type | Nullable | Constraints |
|-------|------|----------|-------------|
| `schema_version` | `string` | no | Semantic version |
| `account_id` | `string` | no | 12-digit AWS account ID |
| `audit_timestamp` | `string` | no | ISO 8601 UTC |
| `threshold_days` | `integer` | no | > 0 |
| `category` | `string` | no | `dormancy`, `permission`, `unused_permission` |
| `severity` | `string` | no | `critical`, `high`, `medium`, `low` |
| `principal_type` | `string` | no | `role`, `user` |
| `granularity` | `string` | no | `ACTION_LEVEL`, `SERVICE_LEVEL` |

## Versioning

The `schema_version` field follows semantic versioning. Breaking changes (field removals, type changes) increment MAJOR. New optional fields increment MINOR. Documentation-only changes increment PATCH.
