# Implementation Plan: IAM Audit CLI

**Branch**: `003-iam-audit-cli` | **Date**: 2026-03-11 | **Spec**: `specs/003-iam-audit-cli/spec.md`
**Input**: Feature specification from `/specs/003-iam-audit-cli/spec.md`

## Summary

Build a Python CLI tool (`iam-audit`) that audits AWS IAM roles and users for dormancy, overly permissive policies, and unused permissions via Service Last Accessed data. The tool outputs findings in text, JSON, or self-contained HTML format with severity ratings and actionable recommendations. HTML reports use `<details>`/`<summary>` for collapsible category sections. All output is sorted by severity descending then principal name. The tool notes Deny statement presence in findings without evaluating effective permissions. No Prometheus integration — removed per Session 2026-03-11 clarification.

## Technical Context

**Language/Version**: Python 3.12+
**Primary Dependencies**: boto3 (AWS SDK). All other functionality from Python stdlib: `argparse`, `json`, `logging`, `fnmatch`, `dataclasses`, `concurrent.futures`, `pathlib`, `html`, `string`, `datetime`, `enum`.
**Storage**: N/A — read-only tool with no persistent state. All data is in-memory for the duration of a single audit run.
**Testing**: pytest + botocore.stub.Stubber for AWS API mocking. No external test services required.
**Target Platform**: Linux/macOS CLI (Python 3.12+ with boto3)
**Project Type**: CLI tool
**Performance Goals**: Audit of 500 roles + 100 users within 5 minutes under normal conditions (SC-003). Cold start under 2 seconds (Constitution V).
**Constraints**: <256 MB memory (Constitution V). Functions ≤40 lines, files ≤400 lines (Constitution I). ≥80% line coverage (Constitution III).
**Scale/Scope**: Single AWS account per invocation. Up to ~1000 principals typical, paginated to avoid memory issues.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Single-responsibility modules (collectors, analyzers, reporters). Type annotations. Functions ≤40 LOC, files ≤400 LOC. ruff for linting. |
| II. Security by Default | PASS | Read-only IAM operations. No secrets in code. `html.escape()` for all HTML output. Input validation via argparse + schema checks. Pinned dependencies with `pip-audit`. |
| III. Testing Standards | PASS | Unit tests with botocore Stubber. Integration tests for CLI commands. ≥80% coverage enforced. Deterministic tests (mocked AWS). Edge case tests for empty/error states. |
| IV. User Experience | PASS | POSIX CLI conventions: flags, `--format json`, errors to stderr. Actionable error messages with specific permission names. `--help` on all subcommands. |
| V. Performance | PASS | Paginated AWS API calls. Generator-based processing. Concurrent Access Advisor jobs (ThreadPoolExecutor). Memory bounded by account size (~5K findings max). Cold start <2s. |

No violations detected. No complexity tracking entries needed.

## Project Structure

### Documentation (this feature)

```text
specs/003-iam-audit-cli/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
│   ├── cli-contract.md  # CLI flags, exit codes, credential chain
│   ├── cli-schema.md    # Detailed CLI schema with output examples
│   └── json-schema.md   # JSON output structure
└── tasks.md             # Phase 2 output (created by /speckit.tasks)
```

### Source Code (repository root)

```text
src/
├── iam_audit/
│   ├── __init__.py
│   ├── __main__.py          # Entry point
│   ├── cli.py               # Argument parsing, subcommand routing
│   ├── aws_client.py        # boto3 session/client factory, account ID
│   ├── models.py            # Dataclasses: Principal, Finding, AuditReport, etc.
│   ├── filters.py           # Path-prefix, name-glob, tag filtering
│   ├── logging_config.py    # Structured JSON logging with correlation IDs
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── roles.py         # IAM role enumeration + metadata
│   │   ├── users.py         # IAM user enumeration + metadata
│   │   ├── policies.py      # Policy document fetching + parsing
│   │   └── access_advisor.py # Service Last Accessed data collection
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── dormancy.py      # Dormancy threshold analysis
│   │   ├── permissions.py   # Overly permissive policy detection + Deny awareness
│   │   └── unused.py        # Unused permissions via Access Advisor
│   ├── reporters/
│   │   ├── __init__.py
│   │   ├── text.py          # Text/table output formatter
│   │   ├── json_reporter.py # JSON output formatter
│   │   └── html.py          # HTML report generator (string.Template, details/summary)
│   └── data/
│       └── iam_actions.json # Static IAM actions map for wildcard expansion

tests/
├── conftest.py              # Shared fixtures and factory helpers
├── unit/
│   ├── test_aws_client.py
│   ├── test_collectors.py
│   ├── test_dormancy_analyzer.py
│   ├── test_permissions_analyzer.py
│   ├── test_unused_analyzer.py
│   ├── test_filters.py
│   ├── test_text_reporter.py
│   ├── test_json_reporter.py
│   └── test_html_reporter.py
└── integration/
    └── test_cli.py          # End-to-end CLI invocation tests
```

**Structure Decision**: Single-project layout. CLI tool with clear separation: collectors (AWS data), analyzers (finding logic), reporters (output formats). No web frontend, no database. Tests mirror source structure.
