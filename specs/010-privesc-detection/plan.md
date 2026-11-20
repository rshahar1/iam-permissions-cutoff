# Implementation Plan: Privilege-escalation detection

**Branch**: `010-privesc-detection` | **Date**: 2026-11-20 | **Spec**: [spec.md](spec.md)

## Technical Context

Python 3.12, stdlib only. New modules `analyzers/privesc.py` (rule table + `run(ctx)`) and `analyzers/grants.py` (case-insensitive action glob helpers). `models.py`, `pipeline.py` and README updated. Reporters are untouched (they read `FindingCategory.display_name`).

## Design

- Rules are a tuple of `PrivescRule` (`rule_id`, `name`, `severity`, `required_actions`, `description`, `recommendation`).
- For each required action: any effective `Deny` (all-resources, unconditional) means not granted; otherwise the set of policy names with a matching all-resources `Allow`. Results are cached per principal.
- Principals with `Allow *` on all resources and no effective Deny are skipped (full admin).
- `Check("privesc", ..., needs_policies=True)` is appended to `CHECKS`, and `"privesc"` to the `permissions` and `report` subcommands.
- Contract: see [contracts/json-schema-delta.md](contracts/json-schema-delta.md).

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Rules as data; functions ≤ 40 lines; typed and documented; files ≤ 400 lines. |
| II. Security | PASS | Read-only, no new AWS calls or permissions; no secrets. |
| III. Testing | PASS | Table-driven tests per rule and grant/deny semantics; moto end-to-end test; only AWS I/O mocked. |
| IV. UX Consistency | PASS | Same CLI surface and output formats; new section "Privilege Escalation Findings". |
| V. Performance | PASS | Pure in-memory evaluation of already-fetched policies. |
