# Tasks: Fix P0 Analyzer Correctness Bugs

**Input**: Design documents from `/specs/004-fix-p0-analyzer-bugs/`
**Prerequisites**: plan.md, spec.md, contracts/json-schema-delta.md

**Tests**: Included - Constitution III requires regression tests and >= 80% coverage.

**Organization**: Grouped by user story (US1-US5). US = story in spec.md.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Foundational (Blocking Prerequisites)

- [x] T001 Add `not_actions: list[str]` and `not_resources: list[str]` (default empty) to `PolicyStatement` and `is_aws_reserved: bool` (default False) to `IAMRole` in `src/iam_audit/models.py`
- [x] T002 Parse `NotAction` / `NotResource` (string or list) in `_parse_policy_document` in `src/iam_audit/collectors/policies.py`
- [x] T003 [P] Parser unit tests (NotAction string/list, NotResource, absent defaults) in `tests/unit/`

**Checkpoint**: models and parser ready.

---

## Phase 2: User Story 1 - NotAction / NotResource (Priority: P1)

- [x] T004 [US1] In `src/iam_audit/analyzers/permissions.py` classify Allow+NotAction (HIGH on all resources, MEDIUM scoped) with recommendation "replace NotAction with an explicit allow-list of actions"; treat NotResource as all resources
- [x] T005 [US1] In `src/iam_audit/analyzers/unused.py` treat Allow+NotAction as granting all known services except wholly excluded `svc:*`; never report individually excluded actions as unused
- [x] T006 [P] [US1] Tests for NotAction/NotResource in permissions and unused analyzers in `tests/unit/`

---

## Phase 3: User Story 2 - Wildcard Classification (Priority: P1)

- [x] T007 [US2] Normalize in `permissions.py`: `_has_all_actions` (`*`, `*:*`), `_applies_to_all_resources`; rewrite `_classify_statement` per FR-005
- [x] T008 [P] [US2] Table-driven classifier tests (`"*"` on bucket ARN, `["*","s3:GetObject"]` on `"*"`, `["arn","*"]` resource, `*:*`, `svc:*`, `s3:Get*`, >5 and 2-5 actions on `"*"`) in `tests/unit/`

---

## Phase 4: User Story 3 - Tracked-Only Unused Analysis (Priority: P1)

- [x] T009 [US3] Rewrite `_compare_service_usage` in `src/iam_audit/analyzers/unused.py` to iterate `TrackedActionsLastAccessed`, report used/unused by `--days` threshold, skip untracked, use AWS canonical casing, and update finding description to state only tracked actions are assessed
- [x] T010 [US3] Update existing unused-analyzer tests that encoded the old behavior (one tracked action but untracked ones expected unused) in `tests/unit/`
- [x] T011 [P] [US3] New tests: tracked vs untracked, used vs unused boundary, canonical casing in `tests/unit/`

---

## Phase 5: User Story 4 - Case-Insensitive Glob Matching (Priority: P2)

- [x] T012 [US4] Add case-insensitive glob matcher (`*`, `?`) in `unused.py`; remove `_expand_wildcard_actions` and its tests/imports
- [x] T013 [P] [US4] Tests: `s3:createbucket` vs `CreateBucket`, `s3:Get*Tagging`, `?` single char, regex-special chars treated literally in `tests/unit/`

---

## Phase 6: User Story 5 - Flag Semantics and SSO Roles (Priority: P1)

- [x] T014 [US5] Set `IAMRole.is_aws_reserved` from `/aws-reserved/` path and exclude such roles unless `--include-aws-managed` in `src/iam_audit/collectors/roles.py` (and filter wiring in `src/iam_audit/filters.py` / `cli.py` if needed)
- [x] T015 [US5] Add `policy_is_aws_managed` to permission finding metadata; for AWS-managed policies recommend detach and replace with customer-managed least-privilege policy in `permissions.py`; ensure AWS-managed policies on customer principals are always analyzed
- [x] T016 [US5] Emit `not_actions`, `not_resources`, `policy_is_aws_managed` in JSON output (`src/iam_audit/reporters/json_reporter.py`) if not passed through; keep `schema_version` `1.0.0`
- [x] T017 [P] [US5] Roles collector test with moto: `/aws-reserved/sso.amazonaws.com/` role excluded by default, included with flag, in `tests/`
- [x] T018 [P] [US5] Tests: AdministratorAccess on customer role yields CRITICAL with `policy_is_aws_managed: true` and detach recommendation; JSON reporter includes new keys

---

## Phase 7: Polish & Cross-Cutting

- [x] T019 [P] Update `--include-aws-managed` help text in `src/iam_audit/cli.py`, `README.md`, and any docs to say it controls principal scope only
- [ ] T020 [P] Update `specs/003-iam-audit-cli/contracts/json-schema.md` cross-reference to `contracts/json-schema-delta.md` (if desired by maintainers) — deferred: not done in this change
- [x] T021 Run `ruff check` and `pytest --cov`; confirm no violations and coverage >= 80%
- [ ] T022 Re-run against a sample account (or fixtures) to confirm reserved-role noise is gone and AWS-managed policy findings remain — pending: needs a live AWS account run by the maintainer
- [x] T023 Verify constitution limits (functions <= 40 lines, files <= 400 lines) on touched files
- [x] T024 Add GitHub Actions CI (`.github/workflows/ci.yml`): ruff + pytest with coverage on Python 3.12/3.13, mypy (non-blocking until the 30 pre-existing errors are fixed), and blocking `pip-audit`; actions pinned to commit SHAs, read-only token
- [x] T025 Bump `pytest` to `>=9.0.3,<10.0.0` in `requirements-dev.txt` to resolve PYSEC-2026-1845 flagged by `pip-audit`

---

## Dependencies & Order

- Phase 1 blocks all others. US1-US5 touch different logic; US1/US2 share `permissions.py` (sequential), US3/US4 share `unused.py` (sequential); US5 T015 follows T007.
- Polish last.

## Follow-ups (out of scope)

Trust-policy analysis; privilege-escalation rules; credential report; permission boundaries/SCPs; finding grouping and stable IDs; API-call efficiency; `collectors/policies.py` duplication refactor; mypy errors.
