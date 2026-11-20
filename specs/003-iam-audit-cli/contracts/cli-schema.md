# CLI Contract: iam-audit

**Feature**: 003-iam-audit-cli | **Date**: 2026-03-11

## Invocation

```text
iam-audit <command> [options]
```

Executable via `python -m iam_audit` or as an installed console script `iam-audit`.

## Commands

### dormancy

Scan for dormant IAM roles and users.

```text
iam-audit dormancy [--days N] [--path-prefix PREFIX] [--name PATTERN] [--tag KEY=VALUE] [--format text|json|html] [--output PATH] [--include-aws-managed] [--concurrency N]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--days` | int | 90 | Dormancy threshold and Access Advisor lookback window in days |
| `--path-prefix` | str | — | Filter by IAM path prefix |
| `--name` | str | — | Filter by glob pattern on principal name |
| `--tag` | str | — | Filter by tag (KEY=VALUE). Repeatable. |
| `--format` | text \| json \| html | text | Output format |
| `--output` | str | — | File path to write output to instead of stdout. **Required** when `--format html`; optional for `text` and `json`. Silently overwrites existing files. |
| `--include-aws-managed` | flag | off | Include AWS service-linked roles, service roles, and AWS-managed policies |
| `--concurrency` | int | 10 | Max concurrent Access Advisor API jobs |

### permissions

Scan for overly permissive IAM policies.

```text
iam-audit permissions [--days N] [--path-prefix PREFIX] [--name PATTERN] [--tag KEY=VALUE] [--format text|json|html] [--output PATH] [--include-aws-managed] [--concurrency N]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--days` | int | 90 | Access Advisor lookback window in days (for unused-permissions analysis) |
| `--path-prefix` | str | — | Filter by IAM path prefix |
| `--name` | str | — | Filter by glob pattern on principal name |
| `--tag` | str | — | Filter by tag (KEY=VALUE). Repeatable. |
| `--format` | text \| json \| html | text | Output format |
| `--output` | str | — | File path to write output to instead of stdout. **Required** when `--format html`; optional for `text` and `json`. Silently overwrites existing files. |
| `--include-aws-managed` | flag | off | Include AWS service-linked roles, service roles, and AWS-managed policies |
| `--concurrency` | int | 10 | Max concurrent Access Advisor API jobs |

### report

Run both dormancy and permissions audits and produce a consolidated report.

```text
iam-audit report [--days N] [--path-prefix PREFIX] [--name PATTERN] [--tag KEY=VALUE] [--format text|json|html] [--output PATH] [--include-aws-managed] [--concurrency N]
```

All flags from `dormancy` and `permissions` are accepted, including `--include-aws-managed`, `--output`, and `--concurrency`.

## Global Options

| Flag | Description |
|------|-------------|
| `--help`, `-h` | Show help for any command |
| `--version` | Show tool version |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Audit completed, no findings |
| 1 | Audit completed, findings present |
| 2 | Tool error (invalid args, missing permissions, AWS failure) |

## Output Contracts

### Text Format (stdout)

Human-readable table grouped by category with a summary header. Findings sorted by severity descending, then principal name alphabetically within each category (FR-037).

```text
IAM Audit Report — Account 123456789012
========================================
Timestamp: 2026-03-07T14:30:00Z
Filters:   path-prefix=/team-alpha/
Threshold: 90 days

Summary: 7 findings (2 Critical, 1 High, 2 Medium, 2 Low)

DORMANCY FINDINGS (2)
┌──────────┬──────────┬────────────┬──────────────┬─────────────────────────────┐
│ Severity │ Type     │ Name       │ Last Active  │ Recommendation              │
├──────────┼──────────┼────────────┼──────────────┼─────────────────────────────┤
│ Low      │ role     │ old-role   │ 2025-11-01   │ Delete this unused role      │
│ Low      │ user     │ test-user  │ Never        │ Delete this unused user      │
└──────────┴──────────┴────────────┴──────────────┴─────────────────────────────┘

PERMISSION FINDINGS (3)
┌──────────┬──────────┬────────────┬──────────────┬─────────────────────────────┐
│ Severity │ Type     │ Name       │ Policy       │ Recommendation              │
├──────────┼──────────┼────────────┼──────────────┼─────────────────────────────┤
│ Critical │ role     │ admin-role │ AdminPolicy  │ Scope actions and resources  │
│ High     │ user     │ dev-user   │ S3FullAccess │ Restrict s3:* to specific…  │
│ Medium   │ role     │ ci-role    │ CIPolicy     │ Narrow ec2:* to required…   │
└──────────┴──────────┴────────────┴──────────────┴─────────────────────────────┘

UNUSED PERMISSION FINDINGS (2)
┌──────────┬──────────┬────────────┬──────────────────────┬─────────────────────────────┐
│ Severity │ Type     │ Name       │ Unused Service/Action│ Recommendation              │
├──────────┼──────────┼────────────┼──────────────────────┼─────────────────────────────┤
│ Medium   │ role     │ app-role   │ sqs (service-level)  │ Remove SQS access — never…  │
│ Low      │ user     │ dev-user   │ s3:DeleteObject      │ Remove s3:DeleteObject —…   │
└──────────┴──────────┴────────────┴──────────────────────┴─────────────────────────────┘
```

Errors are written to stderr.

### JSON Format (stdout)

See `json-schema.md` for the canonical schema definition. Example:

```json
{
  "schema_version": "1.0.0",
  "account_id": "123456789012",
  "audit_timestamp": "2026-03-07T14:30:00Z",
  "threshold_days": 90,
  "include_aws_managed": false,
  "filters": {
    "path_prefix": "/team-alpha/",
    "name_pattern": null,
    "tags": null
  },
  "summary": {
    "total_findings": 7,
    "principals_scanned": 120,
    "data_gaps_count": 0,
    "by_category": {
      "dormancy": 2,
      "permission": 3,
      "unused_permission": 2
    },
    "by_severity": {
      "critical": 2,
      "high": 1,
      "medium": 2,
      "low": 2
    }
  },
  "findings": [
    {
      "principal_arn": "arn:aws:iam::123456789012:role/admin-role",
      "principal_name": "admin-role",
      "principal_type": "role",
      "category": "permission",
      "severity": "critical",
      "title": "Overly permissive policy: AdminPolicy",
      "description": "",
      "recommendation": "Remove this policy or replace with least-privilege permissions.",
      "metadata": {
        "policy_name": "AdminPolicy",
        "policy_type": "inline",
        "statement_sid": null,
        "actions": ["*"],
        "resources": ["*"],
        "has_deny_statements": false
      }
    },
    {
      "principal_arn": "arn:aws:iam::123456789012:role/old-role",
      "principal_name": "old-role",
      "principal_type": "role",
      "category": "dormancy",
      "severity": "low",
      "title": "Role unused for 120 days",
      "description": "Role 'old-role' was last assumed on 2025-11-01.",
      "recommendation": "Delete this unused role",
      "metadata": {
        "last_activity": "2025-11-01T00:00:00Z",
        "days_inactive": 120,
        "has_password": false
      }
    }
  ],
  "data_gaps": []
}
```

Findings are sorted by severity descending, then principal name alphabetically (FR-037).

### HTML Format (file via `--output`)

Self-contained HTML file with inline CSS, no JavaScript. Native HTML `<details>`/`<summary>` elements for collapse/expand. Structure:

1. **Header**: Report title with account ID and audit timestamp
2. **Summary section**: Total findings count, category breakdown, severity badges (color-coded: Critical=red, High=orange, Medium=yellow, Low=blue). Always visible (not inside `<details>`).
3. **Finding categories**: Each category wrapped in a `<details>`/`<summary>` element, **collapsed by default**:
   - `<summary>` displays category name and finding count (e.g., "Dormancy Findings (5)")
   - Table with columns: Principal (name + ARN), Severity, Title, Recommendation
   - Severity cells color-coded to match summary badges
   - Findings sorted by severity descending, then principal name alphabetically (FR-037)
4. **Data gaps section** (if any): Table listing principals with incomplete data
5. **Footer**: Audit metadata (threshold, filters applied, tool version)

**Zero findings**: Summary shows all-zero counts; body displays "No issues found" message. No `<details>` sections rendered.

**Print support**: `@media print` CSS rule forces all `<details>` content visible so printed/PDF output includes all findings.

**Validation rules**:
- `--output` is **required** when `--format html` — tool exits with error code 2 if missing
- Parent directory of `--output` path must exist — tool exits with error code 2 if not
- Existing files at `--output` path are silently overwritten
- All finding text is HTML-escaped to prevent rendering issues with special characters in ARNs or policy names

## Error Output Contract (stderr)

All errors go to stderr in structured format:

```text
ERROR: Missing IAM permissions: iam:GetAccountAuthorizationDetails, iam:ListAccessKeys
       Configure credentials with: aws configure
       Required permissions: iam:Get*, iam:List*, iam:GenerateServiceLastAccessedDetails
```

For `--format json`, errors are still written to stderr as plain text (not JSON) to avoid corrupting the stdout JSON stream.
