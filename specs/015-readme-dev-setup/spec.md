# Feature Specification: README development setup matches CI

**Feature Branch**: `015-readme-dev-setup` | **Created**: 2026-11-20 | **Status**: Implemented

## Summary

The README's setup and development commands had drifted from CI: installation said `cd src` before `pip install -e .` (the package is installed from the repo root), the test section quoted a stale count ("113 tests"; the suite has 352), and lint/type-check used `ruff check src tests` and `mypy src` instead of the CI commands. A new contributor following the README got different results from CI.

## User Scenarios & Testing

### User Story 1 — Set up and check the project from the README (Priority: P1)
**Acceptance**: following the README from a fresh clone (venv, install, test, lint, type check, dependency audit) runs the same commands CI runs and they pass.

## Requirements

- **FR-001**: Installation runs from the repo root inside a virtualenv; the development install is `pip install -r requirements-dev.txt -e .`, as in CI.
- **FR-002**: The test section does not quote a test count.
- **FR-003**: Lint, type check and dependency audit are `ruff check src tests scripts`, `mypy` and `pip-audit -r requirements-dev.txt --strict`.
- **FR-004**: Remove the `CLAUDE.md` gotcha that warned about this drift.
