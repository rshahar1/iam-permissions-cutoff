# Feature Specification: Credential report hygiene checks

**Feature Branch**: `011-credential-report` | **Created**: 2026-11-20 | **Status**: Implemented

## Summary

The audit looked at policies and activity but not at how credentials are managed: root keys and MFA, console users without MFA, stale or unused access keys. The IAM credential report has all of this in one call. This feature adds a `credentials` check (new category `credential`) and a `credentials` subcommand, and includes the check in `report`.

## User Scenarios & Testing

### User Story 1 — Find risky root account settings (Priority: P1)
**Acceptance**: an active root access key or a root without MFA is CRITICAL; recent root password use is MEDIUM.

### User Story 2 — Find weak user credentials (Priority: P1)
**Acceptance**: console password without MFA is HIGH; stale, never-used or duplicate access keys and never-used console passwords are reported with per-key metadata.

### User Story 3 — Scoped audits stay scoped (Priority: P2)
**Acceptance**: only users that pass `--path-prefix/--name/--tag` are reported; the root row is included only when no such filter is set. A denied or slow report yields a data gap, not a crash.

## Requirements

- **FR-001**: The collector MUST call `generate_credential_report` until `COMPLETE` (exponential backoff, ~60 s bound, injectable sleep), then parse `get_credential_report` CSV; `N/A`, `no_information` and `not_supported` parse to `None`.
- **FR-002**: Failures (`ClientError`, timeout) MUST append `DataGap("credential-report", reason)` and produce no findings.
- **FR-003**: Rules CRED-001..CRED-008 as in the README; metadata always has `rule_id`; per-key rules emit one finding per key with `key_slot`.
- **FR-004**: New option `--key-max-age N` (default 90) for CRED-005; `--days` is used for CRED-003, CRED-006 and CRED-008.
- **FR-005**: Age calculations MUST use `ctx.now`.
- **FR-006**: JSON change is additive (see `contracts/json-schema-delta.md`); `schema_version` stays `1.0.0`.

## Success Criteria

- Tests cover each rule positive and negative, CSV parsing, polling/timeout, data gap, filter scoping and one moto-backed credential report.
- Full test suite, mypy (strict), ruff and the emulator smoke test pass.
