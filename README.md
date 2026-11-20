# iam-audit

A CLI tool to audit AWS IAM roles and users for over-provisioning. It identifies dormant principals, overly permissive policies, and unused permissions — helping teams achieve a least-privilege security posture without manual AWS console work.

## Features

- **Dormancy detection** — flags roles and users with no activity beyond a configurable threshold (default: 90 days), including entities that have never been used
- **Permission analysis** — detects wildcard actions (`*`), wildcard resources (`*`), and broad service-level wildcards (e.g., `s3:*`) across inline, managed, and group policies. Notes the presence of Deny statements that may restrict effective permissions
- **Unused permission analysis** — uses AWS Access Advisor (action-level granularity) to identify granted permissions that have never been exercised, with wildcard expansion via a bundled IAM actions map
- **Consolidated reporting** — combines all findings into a single report in text (table), JSON, or **HTML** format
- **HTML reports** — self-contained, static HTML files with collapsible category sections, severity color-coding, summary badges, and print-friendly styling. No JavaScript required
- **Scoped audits** — filter by IAM path prefix, name glob pattern, or resource tags (AND-combined)
- **Safe by design** — read-only; audits and recommends, never modifies AWS resources
- **CI/CD-friendly** — distinct exit codes and JSON output for pipeline integration
- **Deterministic output** — findings are sorted by severity (Critical → Low), then alphabetically by principal name

## Requirements

- Python 3.12+
- AWS credentials configured via the standard credential chain (environment variables, `~/.aws/credentials`, SSO, or instance profile)
- IAM read permissions (see [Required AWS Permissions](#required-aws-permissions))

## Installation

```bash
cd src
pip install -e .
```

For development:

```bash
pip install -r requirements-dev.txt
```

## Required AWS Permissions

The caller needs the following IAM permissions. The tool validates these before starting and reports any that are missing:

```
iam:ListRoles
iam:GetRole
iam:ListUsers
iam:ListAccessKeys
iam:GetAccessKeyLastUsed
iam:ListGroupsForUser
iam:ListAttachedRolePolicies
iam:ListAttachedUserPolicies
iam:ListRolePolicies
iam:ListUserPolicies
iam:GetRolePolicy
iam:GetUserPolicy
iam:GetPolicy
iam:GetPolicyVersion
iam:ListRoleTags
iam:GenerateServiceLastAccessedDetails
iam:GetServiceLastAccessedDetails
sts:GetCallerIdentity
```

The tool is entirely read-only and requires no write permissions.

## Usage

```
iam-audit <subcommand> [options]
```

### Subcommands

| Subcommand    | Description                                                        |
|---------------|--------------------------------------------------------------------|
| `dormancy`    | Identify principals with no recent activity                        |
| `permissions` | Detect overly permissive policies and unused permission grants     |
| `report`      | Generate a consolidated audit report (dormancy + permissions)      |

### Options

| Option                  | Default | Description                                                |
|-------------------------|---------|------------------------------------------------------------|
| `--days N`              | `90`    | Dormancy threshold and Access Advisor lookback window      |
| `--path-prefix PREFIX`  | —       | Filter principals by IAM path prefix                       |
| `--name PATTERN`        | —       | Filter principals by name glob pattern (e.g., `ci-*`)     |
| `--tag KEY=VALUE`       | —       | Filter by tag; repeatable for multiple tags (AND-combined) |
| `--include-aws-managed` | off     | Also scan service-linked, service, and IAM Identity Center (`/aws-reserved/`) roles. AWS-managed policies attached to your own principals are always analyzed |
| `--format text\|json\|html` | `text` | Output format                                          |
| `--output PATH`         | —       | Write output to file instead of stdout (required for HTML) |
| `--concurrency N`       | `10`    | Max concurrent Access Advisor API requests                 |
| `--trusted-accounts IDS` | —      | Comma-separated 12-digit account IDs whose role trust is expected (trust checks); repeatable |
| `--version`             |         | Show version and exit                                      |

### Examples

```bash
# Find dormant roles and users (90-day default)
iam-audit dormancy

# Custom threshold (30 days)
iam-audit dormancy --days 30

# Scan for overly permissive policies and unused permissions
iam-audit permissions

# Full consolidated report
iam-audit report

# JSON output for automation pipelines
iam-audit report --format json > audit-results.json

# HTML report (standalone shareable file)
iam-audit report --format html --output audit-report.html

# HTML works on all subcommands
iam-audit dormancy --format html --output dormancy.html
iam-audit permissions --format html --output permissions.html

# Scope to a specific team
iam-audit report --path-prefix /team-alpha/
iam-audit report --tag team=platform
iam-audit report --name "ci-*"

# Also scan AWS-managed roles (service-linked, service, and SSO /aws-reserved/ roles)
iam-audit report --include-aws-managed

# Write any format to a file
iam-audit report --format json --output audit.json
iam-audit report --format text --output audit.txt
```

## Output Formats

### Text

Human-readable table output grouped by finding category with severity indicators.

```
IAM Audit Report — Account: 123456789012
Timestamp : 2026-03-10T14:32:00Z
Threshold : 90 days
Principals scanned: 87

DORMANCY FINDINGS (3)
─────────────────────────────────────────────────────────
  CRITICAL  arn:aws:iam::123456789012:role/old-deploy-role
            Last activity: never
            Recommendation: Delete this unused role

  HIGH      arn:aws:iam::123456789012:user/ci-legacy
            Last activity: 2025-08-12
            Recommendation: Delete this dormant user

PERMISSION FINDINGS (2)
─────────────────────────────────────────────────────────
  CRITICAL  arn:aws:iam::123456789012:role/admin-role
            Policy: inline/AdminPolicy — Action:*, Resource:*
            Recommendation: Scope actions and resources to minimum required
```

### JSON

Machine-readable output following a versioned schema (`schema_version: "1.0.0"`). Findings are sorted by severity descending, then by principal name. See [specs/003-iam-audit-cli/contracts/json-schema.md](specs/003-iam-audit-cli/contracts/json-schema.md) for the full schema reference.

```json
{
  "schema_version": "1.0.0",
  "account_id": "123456789012",
  "audit_timestamp": "2026-03-10T14:32:00Z",
  "threshold_days": 90,
  "include_aws_managed": false,
  "filters": { "path_prefix": null, "name_pattern": null, "tags": null },
  "summary": {
    "total_findings": 5,
    "principals_scanned": 87,
    "by_severity": { "critical": 2, "high": 2, "medium": 1, "low": 0 },
    "by_category": { "dormancy": 3, "permission": 2 }
  },
  "findings": [ "..." ],
  "data_gaps": []
}
```

### HTML

Self-contained static HTML file with:
- Summary badges showing total findings and severity breakdown
- Collapsible `<details>`/`<summary>` sections per finding category (collapsed by default)
- Severity color-coding (Critical: red, High: orange, Medium: yellow, Low: blue)
- Print-friendly — `@media print` forces all sections expanded
- No JavaScript — works in any browser, safe to share as a standalone file
- All dynamic content escaped via `html.escape()` to prevent XSS

## Exit Codes

| Code | Meaning                                                         |
|------|-----------------------------------------------------------------|
| `0`  | Audit complete — no findings                                    |
| `1`  | Audit complete — findings present                               |
| `2`  | Tool error (credentials, permissions, invalid arguments)        |

### Trust policy checks

The `permissions` and `report` subcommands also inspect each role's trust policy (`AssumeRolePolicyDocument`, already returned by `ListRoles`, so no extra API calls). Only `Allow` statements that grant `sts:AssumeRole`, `sts:AssumeRoleWithWebIdentity`, `sts:AssumeRoleWithSAML` (or `sts:*` / `*`) are examined, and service-linked and `/aws-reserved/` roles are skipped. One finding is emitted per statement per rule (category `trust_policy`).

| Rule | Severity | Detects |
|------|----------|---------|
| `TRUST-001` | CRITICAL | Principal `*` (any AWS account) with no `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`, `aws:PrincipalAccount`, `aws:PrincipalArn`, `aws:SourceAccount`, `aws:SourceArn` or `aws:SourceOrgID` condition |
| `TRUST-002` | HIGH | `Allow` with `NotPrincipal` (trusts everyone except those listed) |
| `TRUST-003` | HIGH | Cross-account principal not on the trusted list and no `sts:ExternalId` condition |
| `TRUST-004` | LOW | Cross-account principal not on the trusted list, with `sts:ExternalId` (verify the third party) |
| `TRUST-005` | CRITICAL | GitHub Actions OIDC without a restrictive `token.actions.githubusercontent.com:sub` condition |
| `TRUST-006` | MEDIUM | GitHub Actions OIDC with a valid `sub` but no `:aud` condition |
| `TRUST-007` | HIGH | Other OIDC provider without a `<provider>:sub` condition |
| `TRUST-008` | HIGH | Cognito identity pool trust without a `cognito-identity.amazonaws.com:aud` condition |
| `TRUST-009` | MEDIUM | SAML provider without a `SAML:aud` condition |

The audited account itself and any account passed to `--trusted-accounts` (comma-separated, repeatable) never trigger `TRUST-003`/`TRUST-004`.

```bash
iam-audit permissions --trusted-accounts 111122223333,444455556666
```

## Severity Ratings

| Severity   | Criteria                                                                        |
|------------|---------------------------------------------------------------------------------|
| `CRITICAL` | All actions (`*` anywhere in `Action`) on all resources (`*` anywhere in `Resource`, or any `NotResource`) |
| `HIGH`     | All actions on specific resources, full-service wildcard (e.g., `s3:*`), `Allow` + `NotAction` on all resources, more than 5 actions on all resources, principal never used or dormant > 2× threshold, or unused IAM/KMS/STS/Organizations/Secrets Manager permissions |
| `MEDIUM`   | 2–5 specific actions on all resources, partial wildcards (e.g., `s3:Get*`), `Allow` + `NotAction` on specific resources, or most unused service permissions |
| `LOW`      | Zero-policy entities, or one or two unused actions in a non-sensitive service |

## Development

### Running tests

```bash
# All tests (113 tests)
pytest

# Unit tests only
pytest tests/unit

# Integration tests (uses moto for AWS mocking — no real AWS account needed)
pytest tests/integration

# Benchmark tests only
pytest -m benchmark

# All tests with coverage
pytest --cov=iam_audit --cov-report=term-missing
```

### Linting and type checking

```bash
ruff check src tests
mypy src
```

### Local emulator smoke test

```bash
python scripts/emulator_smoke.py [--keep-reports DIR]
```

Starts a local [moto](https://github.com/getmoto/moto) IAM emulator, seeds one principal per known scenario, runs the real `iam-audit` CLI against it (default and `--include-aws-managed`) and fails (exit 1) if the findings differ from the expectations table in the script. It needs no AWS account or credentials and never contacts AWS: the environment is scrubbed of all `AWS_*` variables and pinned to the local emulator. Limits: moto does not emulate Access Advisor, so unused-permission checks are not covered, and freshly created principals show "never used" dormancy findings, which is expected.

### Security audit

```bash
pip-audit
```

## Architecture

```
src/iam_audit/
├── __init__.py            # Package version
├── __main__.py            # python -m iam_audit entry point
├── cli.py                 # Argument parsing, subcommand dispatch, output routing
├── aws_client.py          # Boto3 session/client factory, permission pre-flight check
├── models.py              # Core dataclasses (Principal, Finding, AuditReport, …)
├── filters.py             # Path-prefix / name-glob / tag filtering (AND-combined)
├── logging_config.py      # Structured JSON logging with correlation IDs
├── collectors/
│   ├── roles.py           # IAM role enumeration (paginated, get_role for accurate RoleLastUsed)
│   ├── users.py           # IAM user enumeration (paginated, access key last used)
│   ├── policies.py        # Policy document collection per principal (inline/managed/group)
│   └── access_advisor.py  # Concurrent Access Advisor collection (ThreadPoolExecutor)
├── analyzers/
│   ├── dormancy.py        # Last-activity threshold analysis
│   ├── permissions.py     # Wildcard/broad policy detection with Deny awareness
│   └── unused.py          # Unused permission detection via Access Advisor + wildcard expansion
├── reporters/
│   ├── text.py            # Human-readable table output
│   ├── json_reporter.py   # Versioned JSON schema output
│   └── html.py            # Static HTML report with collapsible sections
└── data/
    └── iam_actions.json   # Static IAM actions map for wildcard expansion
```

## Known Limitations

- **Single account per invocation** — multi-account / AWS Organizations support is not yet implemented.
- **Access Advisor availability** — if Access Advisor data is unavailable for a principal, it is recorded as a data gap in the report rather than silently skipped.
- **Service-linked roles** — always labeled and excluded from deletion recommendations regardless of dormancy status.
- **Unused actions are limited to what Access Advisor tracks** — action-level findings only cover actions AWS Access Advisor reports in `TrackedActionsLastAccessed`; granted actions it does not track (for example most S3 data-plane actions such as `s3:GetObject`) are never reported as unused.
- **AWS-managed policies are always analyzed** — `--include-aws-managed` only widens which *principals* are scanned. An AWS-managed policy (e.g., `AdministratorAccess`) attached to your own role or user is still flagged, with `policy_is_aws_managed: true` in the finding metadata.
- **Deny statements** — noted in findings metadata but do not alter severity ratings (effective permissions may be narrower than reported).
- **Read-only** — the tool never modifies, deletes, or remediates any AWS resource.

## License

This project is provided as-is for internal use.
