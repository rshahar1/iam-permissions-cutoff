# Tasks: Local AWS Emulator Smoke Test

**Input**: Design documents from `/specs/005-emulator-smoke-test/`
**Prerequisites**: plan.md, spec.md

**Tests**: The script is the end-to-end test; verified by running it locally and in CI.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: User Story 1 - End-to-End Run (Priority: P1)

- [x] T001 [US1] Create `scripts/emulator_smoke.py`: start `ThreadedMotoServer` on a free 127.0.0.1 port with `MOTO_IAM_LOAD_MANAGED_POLICIES=true`
- [x] T002 [US1] Seed scenarios (`ci-admin`, `mixed-star`, `bucket-star`, `power-notaction`, `mixed-resource`, `deploy-bot` via group, `tight-reader`, SSO reserved role, service-linked role)
- [x] T003 [US1] Run `python -m iam_audit report --format json` twice (default and `--include-aws-managed`) and check findings against a module-level expectations table
- [x] T004 [US1] Exit codes 0/1/2 and optional `--keep-reports DIR`

## Phase 2: User Story 2 - Isolation (Priority: P1)

- [x] T005 [US2] Remove all `AWS_*` env vars, use dummy credentials, null-device config/credentials files, explicit localhost endpoint
- [x] T006 [US2] Abort when the endpoint host is not localhost

## Phase 3: User Story 3 - CI Gate (Priority: P2)

- [x] T007 [US3] Add blocking `smoke` job to `.github/workflows/ci.yml` (Python 3.12, pinned actions, read-only token)
- [x] T008 [P] [US3] Extend ruff step to lint `scripts/`
- [x] T009 [P] Change `moto[iam]` to `moto[iam,server]` in `requirements-dev.txt`

## Phase 4: Polish & Cross-Cutting

- [x] T010 [P] Add "Local emulator smoke test" subsection under Development in `README.md`
- [x] T011 Run the script locally: exit 0 on the seeded scenarios; ruff clean
- [x] T012 Mark 004 T022 done with a pointer to this feature in `specs/004-fix-p0-analyzer-bugs/tasks.md`
- [ ] T013 Verify the `smoke` CI job passes on the pull request

---

## Dependencies & Order

- T001-T004 sequential in one file; T005-T006 same file, after T004. T007-T009 touch different files and can run in parallel. T013 last.
