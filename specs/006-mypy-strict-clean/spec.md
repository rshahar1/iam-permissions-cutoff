# Feature Specification: Mypy Strict Clean

**Feature Branch**: `006-mypy-strict-clean`
**Created**: 2026-11-20
**Status**: Draft
**Input**: User description: "Fix all mypy strict errors and make type checking block CI"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Codebase Passes Strict Type Checking (Priority: P1)

A maintainer runs `mypy` (strict, configured in `pyproject.toml`) and gets no errors, with no change in runtime behavior.

**Why this priority**: The constitution requires type checking to block merge; it cannot until the existing errors are gone.

**Independent Test**: `python -m mypy` prints "Success: no issues found"; the existing 162 tests and the emulator smoke test still pass unchanged.

**Acceptance Scenarios**:

1. **Given** the current tree, **When** `mypy` runs, **Then** it reports zero errors.
2. **Given** boto3 clients, **Then** they are typed with `mypy_boto3_iam.IAMClient` / `mypy_boto3_sts.STSClient`, not `boto3.client` or `object`.
3. **Given** the change, **Then** pytest, ruff, the smoke test and pip-audit results are unchanged.

---

### User Story 2 - Blocking CI Type Check (Priority: P1)

A reviewer wants type errors to fail the pull request.

**Independent Test**: The `mypy` step in `.github/workflows/ci.yml` has no `continue-on-error`.

**Acceptance Scenarios**:

1. **Given** a PR introducing a type error, **Then** the lint/type job fails.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `mypy` MUST report no errors on `src/`.
- **FR-002**: Changes MUST NOT alter runtime behavior (typing-only plus minimal restructuring the checker needs).
- **FR-003**: boto3 clients MUST use stub types imported under `TYPE_CHECKING`; `requirements-dev.txt` MUST depend on `boto3-stubs[iam,sts]`.
- **FR-004**: `# type: ignore` MUST be avoided; `Any` from boto3/json MUST be converted or `cast` explicitly.
- **FR-005**: CI mypy step MUST be blocking.

### Out of Scope

- Type-checking `tests/` and `scripts/`.
- Any functional change to collectors or analyzers.

## Success Criteria *(mandatory)*

- **SC-001**: `mypy` exits 0 locally and in CI.
- **SC-002**: 162 tests pass; smoke test exits 0.
