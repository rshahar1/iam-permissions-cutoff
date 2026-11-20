# Quickstart: IAM Audit CLI

**Branch**: `003-iam-audit-cli` | **Date**: 2026-03-11

## Prerequisites

- Python 3.12+
- AWS credentials configured (via environment variables, `~/.aws/credentials`, SSO, or instance profile)
- IAM read permissions: `iam:Get*`, `iam:List*`, `iam:GenerateServiceLastAccessedDetails`, `iam:GetServiceLastAccessedDetails`

## Install

```bash
cd src
pip install -e ".[dev]"
```

## Verify Setup

```bash
python -m iam_audit --help
```

## Run Audits

### Find dormant roles and users (inactive >90 days)

```bash
python -m iam_audit dormancy
```

### Custom threshold (30 days)

```bash
python -m iam_audit dormancy --days 30
```

### Scan for overly permissive policies and unused permissions

```bash
python -m iam_audit permissions
```

### Full consolidated report

```bash
python -m iam_audit report
```

### JSON output (for automation pipelines)

```bash
python -m iam_audit report --format json > audit-results.json
```

### HTML report (shareable standalone file)

```bash
python -m iam_audit report --format html --output audit-report.html
```

HTML output works on all subcommands:

```bash
python -m iam_audit dormancy --format html --output dormancy.html
python -m iam_audit permissions --format html --output permissions.html
```

### Scope to a specific team

```bash
python -m iam_audit report --path-prefix /team-alpha/
python -m iam_audit report --tag team=platform
python -m iam_audit report --name "ci-*"
```

### Include AWS-managed roles and policies

```bash
python -m iam_audit report --include-aws-managed
```

### Write any format to a file

```bash
python -m iam_audit report --format json --output audit.json
python -m iam_audit report --format text --output audit.txt
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings |
| `1` | Findings present — review the report |
| `2` | Error — check stderr for details |

## Run Tests

```bash
pip install -e ".[dev]"
pytest
```

## Project Layout

```
src/iam_audit/         # Production code
tests/unit/            # Unit tests
tests/integration/     # Integration tests (botocore Stubber)
```
