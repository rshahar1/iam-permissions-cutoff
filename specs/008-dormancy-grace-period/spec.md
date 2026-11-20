# Feature Specification: Dormancy grace period for new principals

**Feature Branch**: `008-dormancy-grace-period` | **Created**: 2026-11-20 | **Status**: Implemented

## Summary

A role or user created minutes ago has no recorded activity, so dormancy reported it as HIGH "has never been used". A principal with no activity has only been inactive since it was created, so it cannot have been idle longer than its age. This feature treats "never used" as inactive-since-creation and applies the same threshold and severity scale as principals with activity.

## User Scenarios & Testing

### User Story 1 — New principals are not flagged (Priority: P1)
**Acceptance**: a never-used principal younger than `--days` produces no dormancy finding (naive `created_date` is treated as UTC).

### User Story 2 — Old never-used principals keep a graded severity (Priority: P1)
**Acceptance**: never used and age >= `--days` is MEDIUM; age >= 2x `--days` is HIGH. The title states the age; metadata carries `days_inactive` and `created_days_ago` (both the age) and `last_activity: None`.

### User Story 3 — Role tracking window is explained (Priority: P2)
**Acceptance**: a never-used role older than 400 days gets a description noting IAM only tracks role activity for about 400 days.

## Requirements

- **FR-001**: `analyze_dormancy` MUST accept an optional `now` (default current UTC time); the pipeline passes `ctx.now`.
- **FR-002**: Principals with recorded activity MUST behave exactly as before.
- **FR-003**: No new CLI flag; JSON `schema_version` unchanged.
- **FR-004**: The emulator smoke test MUST assert zero dormancy findings in the default run (all seeded principals are new).

## Success Criteria

- Unit tests cover the new-principal, MEDIUM/HIGH boundary, naive-datetime and 400-day cases.
- Full test suite, mypy (strict), ruff and the emulator smoke test pass.
