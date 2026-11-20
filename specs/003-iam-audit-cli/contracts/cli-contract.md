# CLI Contract: iam-audit

**Branch**: `003-iam-audit-cli` | **Date**: 2026-03-11

## Entry Point

```
python -m iam_audit <subcommand> [options]
```

## Subcommands

### `dormancy`

Scan for dormant (inactive) IAM roles and users.

```
iam-audit dormancy [--days N] [--path-prefix PREFIX] [--name PATTERN]
                   [--tag KEY=VALUE] [--include-aws-managed]
                   [--format {text,json,html}] [--output PATH]
                   [--concurrency N]
```

### `permissions`

Scan for overly permissive policies and unused permissions (Access Advisor).

```
iam-audit permissions [--days N] [--path-prefix PREFIX] [--name PATTERN]
                      [--tag KEY=VALUE] [--include-aws-managed]
                      [--format {text,json,html}] [--output PATH]
                      [--concurrency N]
```

### `report`

Run all scans (dormancy + permissions) and produce a consolidated report.

```
iam-audit report [--days N] [--path-prefix PREFIX] [--name PATTERN]
                 [--tag KEY=VALUE] [--include-aws-managed]
                 [--format {text,json,html}] [--output PATH]
                 [--concurrency N]
```

## Global Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--days` | `int` | `90` | Dormancy threshold and Access Advisor lookback window in days |
| `--path-prefix` | `str` | none | Filter principals by IAM path prefix (e.g., `/team-alpha/`) |
| `--name` | `str` | none | Filter principals by name glob pattern (e.g., `ci-*`) |
| `--tag` | `str` | none | Filter principals by tag (`KEY=VALUE`). Repeatable. |
| `--include-aws-managed` | `flag` | `false` | Include AWS service-linked roles, service roles, and AWS-managed policies |
| `--format` | `choice` | `text` | Output format: `text` (human-readable table), `json`, or `html` |
| `--output` | `str` | none | File path to write output to instead of stdout. **Required** when `--format html`; optional for `text` and `json`. Silently overwrites existing files. |
| `--concurrency` | `int` | `10` | Max concurrent Access Advisor API jobs |

## Output Destinations

| Stream | Content |
|--------|---------|
| `stdout` | Findings report (text or JSON based on `--format`), unless `--output` redirects to file |
| `--output` file | Report written to file path when specified. Required for HTML format. |
| `stderr` | Progress messages, warnings, errors |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Audit completed, no findings |
| `1` | Audit completed, findings present |
| `2` | Tool error (invalid args, missing credentials, insufficient permissions, unrecoverable API error) |

## Required IAM Permissions

The caller must have these IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListRoles",
        "iam:ListUsers",
        "iam:GetRole",
        "iam:GetUser",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListGroupsForUser",
        "iam:ListGroupPolicies",
        "iam:ListAttachedGroupPolicies",
        "iam:GetGroupPolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListRoleTags",
        "iam:ListUserTags",
        "iam:GetAccessKeyLastUsed",
        "iam:ListAccessKeys",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetServiceLastAccessedDetails"
      ],
      "Resource": "*"
    }
  ]
}
```

## Credential Resolution

Standard boto3 credential chain (in order):
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. Shared credentials file (`~/.aws/credentials`)
3. AWS config file (`~/.aws/config`)
4. Instance metadata (EC2, ECS, Lambda)
5. SSO credentials

The tool does not manage, store, or request credentials.
