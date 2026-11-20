# Feature Specification: Shared audit pipeline with a check registry

**Feature Branch**: `007-check-pipeline` | **Created**: 2026-11-20 | **Status**: Implemented

## Summary

`cli.py` had three near-identical `_run_*` functions (dormancy, permissions, report), and both reporters kept their own copy of the category display names. Adding a check meant editing the CLI, each subcommand runner and both reporters. This feature adds a check registry so that upcoming checks (trust policies, privilege escalation, credential report) plug in at one place.

## User Scenarios & Testing

### User Story 1 — CLI behaves exactly as before (Priority: P1)
**Acceptance**: same subcommands, options, help text, exit codes (0/1/2), output formats and finding order; existing integration tests pass unchanged except for the patch target of the moved Access Advisor call.

### User Story 2 — A maintainer adds a check in one place (Priority: P1)
**Acceptance**: a new check needs only an analyzer module, one `Check` entry in `pipeline.CHECKS`, its name in the relevant `SUBCOMMANDS` entries, and (if it emits a new category) one `FindingCategory` member with a display name. CLI options for a check come from `Check.add_arguments` and are available on every subcommand.

## Requirements

- **FR-001**: `iam_audit.pipeline` MUST define `AuditContext` (IAM client, account id, options, principals, `now`, report-level `data_gaps`), `Check` (`name`, `run`, `needs_policies`, `add_arguments`), `Subcommand` (`name`, `help`, `description`, `epilog`, `checks`), `CHECKS`, `SUBCOMMANDS`, `get_subcommand`, `needs_policies` and `run_checks`.
- **FR-002**: The CLI MUST build its subparsers from `SUBCOMMANDS` and run every subcommand through one function; policy documents are fetched only when a selected check has `needs_policies`.
- **FR-003**: The `report` subcommand MUST run every registered check.
- **FR-004**: `FindingCategory.display_name` MUST be the single source of section headings for the text and HTML reporters.
- **FR-005**: No change to JSON output or `schema_version`.

## Success Criteria

- `cli.py` shrinks (388 → 273 lines) with no duplicated subcommand runners.
- Full test suite, mypy (strict), ruff and the emulator smoke test pass.
