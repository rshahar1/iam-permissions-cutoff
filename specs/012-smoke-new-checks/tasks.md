# Tasks: Smoke Test Coverage for New Checks

**Input**: Design documents from `/specs/012-smoke-new-checks/`
**Prerequisites**: plan.md, spec.md

---

## Phase 1: User Story 1 - New Rules Fire (Priority: P1)

- [x] T001 [US1] Add optional `trust` parameter to `make_role` in `scripts/emulator_smoke.py`
- [x] T002 [US1] Seed `trust-anyone`, `gh-deploy`, `passrole-runner` and `console-no-mfa`
- [x] T003 [US1] Add `EXPECTED_RULES` table and `check_rules` evaluation

## Phase 2: User Story 2 - Absences (Priority: P1)

- [x] T004 [US2] Add `EXPECTED_ABSENT` table and the trust_policy allow-list assertion
- [x] T005 Update `DEFAULT_SCANNED` / `MANAGED_SCANNED` to 11 / 13

## Phase 3: Polish

- [x] T006 [P] Update README "Local emulator smoke test" subsection
- [x] T007 Run the script (exit 0), prove failure with a mutated rule id (exit 1), ruff, mypy, pytest
- [x] T008 Verify CI passes on the pull request — all 5 checks green on PR #9 (ad392f1), 2026-11-20
