# Data Model: IAM Audit CLI

**Branch**: `003-iam-audit-cli` | **Date**: 2026-03-11

All entities are Python `dataclass` instances. No database storage — all data is in-memory for the duration of a single audit run.

## Entities

### Principal (abstract base)

Shared fields for IAM roles and users.

| Field | Type | Description |
|-------|------|-------------|
| `arn` | `str` | Full ARN (unique identifier) |
| `name` | `str` | Role/user name |
| `path` | `str` | IAM path (e.g., `/`, `/team-alpha/`) |
| `created_date` | `datetime` | Creation timestamp |
| `tags` | `dict[str, str]` | Resource tags |
| `attached_policies` | `list[AttachedPolicy]` | Managed policies attached to this principal |
| `inline_policies` | `list[InlinePolicy]` | Inline policies embedded in this principal |
| `is_aws_managed` | `bool` | True if service-linked role, service role, or has only AWS-managed policies |

### IAMRole (extends Principal)

| Field | Type | Description |
|-------|------|-------------|
| `last_used_date` | `datetime | None` | Last time the role was assumed (`None` = never) |
| `last_used_region` | `str | None` | Region where last assumed |
| `is_service_linked` | `bool` | True if path starts with `/aws-service-role/` |
| `is_service_role` | `bool` | True if path starts with `/service-role/` |

### IAMUser (extends Principal)

| Field | Type | Description |
|-------|------|-------------|
| `password_last_used` | `datetime | None` | Last console login (`None` = never or no password) |
| `access_key_last_used` | `datetime | None` | Most recent access key usage |
| `group_memberships` | `list[str]` | Group names the user belongs to |
| `group_policies` | `list[AttachedPolicy]` | Policies inherited from groups |

**Last activity derivation**: `last_activity = max(password_last_used, access_key_last_used)` — the most recent of all activity signals. For roles: `last_activity = last_used_date`.

### AttachedPolicy

| Field | Type | Description |
|-------|------|-------------|
| `arn` | `str` | Policy ARN |
| `name` | `str` | Policy name |
| `is_aws_managed` | `bool` | True if ARN starts with `arn:aws:iam::aws:policy/` |
| `document` | `PolicyDocument` | Parsed policy document |

### InlinePolicy

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Inline policy name |
| `document` | `PolicyDocument` | Parsed policy document |

### PolicyDocument

| Field | Type | Description |
|-------|------|-------------|
| `version` | `str` | Policy version (e.g., `"2012-10-17"`) |
| `statements` | `list[PolicyStatement]` | All statements in the document |

### PolicyStatement

| Field | Type | Description |
|-------|------|-------------|
| `sid` | `str | None` | Optional statement ID |
| `effect` | `str` | `"Allow"` or `"Deny"` |
| `actions` | `list[str]` | Action patterns (e.g., `["s3:GetObject", "s3:*"]`) |
| `resources` | `list[str]` | Resource ARN patterns |
| `conditions` | `dict | None` | Condition block (preserved but not deeply analyzed) |

**Normalization**: Actions and resources are always stored as lists even when the original policy uses a single string value.

### ServiceLastAccessedRecord

| Field | Type | Description |
|-------|------|-------------|
| `service_namespace` | `str` | Service prefix (e.g., `s3`, `iam`) |
| `service_name` | `str` | Display name |
| `last_authenticated` | `datetime | None` | Last access timestamp (`None` = never) |
| `last_authenticated_region` | `str | None` | Region of last access |
| `tracked_actions` | `list[ActionLastAccessed] | None` | Action-level data if available |

### ActionLastAccessed

| Field | Type | Description |
|-------|------|-------------|
| `action_name` | `str` | Action name without prefix (e.g., `GetObject`) |
| `last_accessed_time` | `datetime | None` | Timestamp (`None` = never accessed) |

### Finding

| Field | Type | Description |
|-------|------|-------------|
| `principal_arn` | `str` | ARN of the affected principal |
| `principal_name` | `str` | Name of the affected principal |
| `principal_type` | `str` | `"role"` or `"user"` |
| `category` | `FindingCategory` | `dormancy`, `permission`, or `unused_permission` |
| `severity` | `Severity` | `Critical`, `High`, `Medium`, or `Low` |
| `title` | `str` | Short summary (e.g., "Wildcard actions on all resources") |
| `description` | `str` | Detailed explanation |
| `recommendation` | `str` | Actionable fix |
| `metadata` | `dict` | Category-specific data (see below) |

**Finding metadata by category**:
- `dormancy`: `{"last_activity": "2025-06-01T...", "days_inactive": 270, "has_password": true}`
- `permission`: `{"policy_name": "AdminAccess", "policy_type": "inline", "statement_sid": "AllowAll", "actions": ["*"], "resources": ["*"], "has_deny_statements": false}`
- `unused_permission`: `{"service_namespace": "s3", "unused_actions": ["PutObject", "DeleteObject"], "keep_actions": ["GetObject"], "last_accessed": "2025-12-01T...", "granularity": "ACTION_LEVEL"}`

### AuditReport

| Field | Type | Description |
|-------|------|-------------|
| `account_id` | `str` | AWS account ID |
| `audit_timestamp` | `datetime` | When the audit ran |
| `threshold_days` | `int` | Dormancy/usage threshold used |
| `filters_applied` | `FiltersApplied` | Active filters |
| `include_aws_managed` | `bool` | Whether AWS-managed entities were included |
| `findings` | `list[Finding]` | All findings, sorted by severity desc then principal name asc (FR-037) |
| `data_gaps` | `list[DataGap]` | Principals with incomplete data |
| `summary` | `ReportSummary` | Aggregated counts |

### FiltersApplied

| Field | Type | Description |
|-------|------|-------------|
| `path_prefix` | `str | None` | IAM path filter |
| `name_pattern` | `str | None` | Glob pattern filter |
| `tags` | `dict[str, str] | None` | Tag filter |

### DataGap

| Field | Type | Description |
|-------|------|-------------|
| `principal_arn` | `str` | Affected principal |
| `reason` | `str` | Why data is missing (e.g., "Newly created", "API timeout") |

### ReportSummary

| Field | Type | Description |
|-------|------|-------------|
| `total_findings` | `int` | Total finding count |
| `by_category` | `dict[str, int]` | Count per category |
| `by_severity` | `dict[str, int]` | Count per severity |
| `principals_scanned` | `int` | Total principals evaluated |
| `data_gaps_count` | `int` | Number of principals with data gaps |

## Enumerations

### FindingCategory

| Value | Description |
|-------|-------------|
| `dormancy` | Principal inactive beyond threshold |
| `permission` | Overly broad policy statement |
| `unused_permission` | Granted but never-used service/action |

### Severity

| Value | Priority | Description |
|-------|----------|-------------|
| `Critical` | 1 | `Action: *` + `Resource: *` |
| `High` | 2 | Full-service wildcard or `Resource: *` |
| `Medium` | 3 | Broad patterns or sensitive unused services |
| `Low` | 4 | Minor issues, zero-policy entities |

## Relationships

```text
AuditReport 1──* Finding
AuditReport 1──* DataGap
AuditReport 1──1 ReportSummary
AuditReport 1──1 FiltersApplied

Principal 1──* AttachedPolicy
Principal 1──* InlinePolicy
Principal 1──* ServiceLastAccessedRecord

AttachedPolicy 1──1 PolicyDocument
InlinePolicy 1──1 PolicyDocument
PolicyDocument 1──* PolicyStatement

ServiceLastAccessedRecord 1──* ActionLastAccessed

Finding *──1 Principal (via principal_arn)
```

## Validation Rules

- `Principal.arn` must match pattern `arn:aws:iam::\d{12}:(role|user)/.+`
- `Severity` must be one of the four defined values
- `FindingCategory` must be one of the three defined values
- `PolicyStatement.effect` must be `"Allow"` or `"Deny"`
- `PolicyStatement.actions` and `PolicyStatement.resources` must be non-empty lists
- `AuditReport.threshold_days` must be > 0
- `Finding.metadata` keys must match the expected schema for the finding's category
