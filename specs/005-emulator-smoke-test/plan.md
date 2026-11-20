# Implementation Plan: Local AWS Emulator Smoke Test

**Branch**: `005-emulator-smoke-test` | **Date**: 2026-11-20 | **Spec**: `specs/005-emulator-smoke-test/spec.md`
**Input**: Feature specification from `/specs/005-emulator-smoke-test/spec.md`

## Summary

Add a reusable script that seeds a local moto IAM emulator with permission and scope scenarios, runs the real CLI twice (default and `--include-aws-managed`), and asserts findings against an expectations table. Run it as a blocking CI job. No changes to `src/`.

## Technical Context

**Language/Version**: Python 3.12+
**Primary Dependencies**: boto3, moto[iam,server] (dev only; `ThreadedMotoServer`)
**Storage**: N/A
**Testing**: The script is itself the end-to-end test; existing pytest suite unchanged
**Target Platform**: Linux/macOS CLI, GitHub Actions
**Project Type**: CLI tool (existing) plus dev script
**Performance Goals**: Completes in well under a minute in CI
**Constraints**: Functions <= 40 lines, files <= 400 lines; ruff clean; never reach real AWS
**Scale/Scope**: `scripts/emulator_smoke.py`, `.github/workflows/ci.yml`, `requirements-dev.txt`, `README.md`

## Design Decisions

1. **In-process server**: `ThreadedMotoServer` on a free 127.0.0.1 port with managed policies loaded so `AdministratorAccess` exists.
2. **Real CLI via subprocess**: `python -m iam_audit report --format json`, so the argument parsing, collection, analysis and JSON output are all exercised.
3. **Declarative expectations**: module-level table keyed by principal; checker compares highest permission severity and scope counts, collecting all mismatches before exiting 1.
4. **Isolation**: scrub `AWS_*`, dummy credentials, null-device config files, explicit localhost endpoint, host assertion before any call.
5. **CI**: separate `smoke` job (Python 3.12, pinned actions, `permissions: contents: read`); ruff step also covers `scripts/`.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Small single-purpose functions with type annotations and docstrings; expectations in one table; ruff-linted. |
| II. Security by Default | PASS | Cannot reach real AWS or use operator credentials; dummy credentials only; no secrets committed; read-only CI token. |
| III. Testing Standards | PASS | Adds end-to-end regression coverage in CI; unit coverage unchanged; known gap (Access Advisor) documented. |
| IV. User Experience | PASS | Clear exit codes and mismatch messages; README documents usage; no CLI/JSON contract change. |
| V. Performance | PASS | Dev/CI-only; no impact on tool runtime. |

No violations; no complexity tracking entries needed.

## Project Structure

### Documentation (this feature)

```text
specs/005-emulator-smoke-test/
├── spec.md
├── plan.md
├── tasks.md
└── checklists/
    └── requirements.md
```

### Source Code (repository root)

```text
scripts/emulator_smoke.py      # new
.github/workflows/ci.yml       # new smoke job; ruff covers scripts/
requirements-dev.txt           # moto[iam,server]
README.md                      # Development: Local emulator smoke test
```

**Structure Decision**: Existing single-project layout; one new script, no new modules under `src/`.
