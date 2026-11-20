# Implementation Plan: Smoke Test Coverage for New Checks

**Branch**: `012-smoke-new-checks` | **Date**: 2026-11-20 | **Spec**: `specs/012-smoke-new-checks/spec.md`
**Input**: Feature specification from `/specs/012-smoke-new-checks/spec.md`

## Summary

Extend `scripts/emulator_smoke.py` with seeded principals and declarative expectation tables for the trust-policy, privilege-escalation and credential-report analyzers. No changes to `src/`.

## Technical Context

**Language/Version**: Python 3.12+
**Primary Dependencies**: boto3, moto[iam,server] (dev only)
**Testing**: The script is the end-to-end test; pytest suite unchanged
**Constraints**: Functions <= 40 lines, files <= 400 lines; ruff and mypy clean; never reach real AWS
**Scale/Scope**: `scripts/emulator_smoke.py`, `README.md`

## Design Decisions

1. **Tables over code**: `EXPECTED_RULES` and `EXPECTED_ABSENT` list rows; one `check_rules` function evaluates them.
2. **Rule identity**: match on principal, category and `metadata["rule_id"]` so a rule firing on the wrong principal fails.
3. **Allow-list for trust findings**: all other seeded roles use EC2 service trust, so any extra `trust_policy` finding is a regression.
4. **Fake values only**: the console password is an obviously fake test value sent only to the local emulator.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Typed, docstringed, small functions; expectations in tables. |
| II. Security by Default | PASS | Isolation unchanged; fake test password only; no real secrets. |
| III. Testing Standards | PASS | Adds end-to-end coverage for three analyzers; failure proven with a mutated rule id. |
| IV. User Experience | PASS | README updated; no CLI/JSON contract change. |
| V. Performance | PASS | Dev/CI-only. |

No violations.

## Project Structure

```text
specs/012-smoke-new-checks/{spec,plan,tasks}.md
scripts/emulator_smoke.py      # new seeds, tables, check_rules
README.md                      # smoke test subsection
```
