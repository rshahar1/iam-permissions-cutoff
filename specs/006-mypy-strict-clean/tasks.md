# Tasks: Mypy Strict Clean

**Input**: `specs/006-mypy-strict-clean/spec.md`, `plan.md`

## Phase 1: Type Fixes (US1)

- [x] T001 Change `boto3-stubs[iam]` to `boto3-stubs[iam,sts]` in `requirements-dev.txt`
- [x] T002 Type `aws_client.py` with `IAMClient` (return of `create_iam_client`, `check_iam_permissions`) and `str()` the STS account id
- [x] T003 [P] Annotate `collectors/users.py` and `collectors/roles.py` (clients, `dict[str, Any]` kwargs, `datetime | None`)
- [x] T004 [P] Annotate `collectors/access_advisor.py` (client, `dict[str, Any]`, cast responses)
- [x] T005 Annotate `collectors/policies.py`, add `_load_document`, restructure `replace()` for `IAMUser`
- [x] T006 [P] Fix `analyzers/unused.py` `Any` return, remove unused ignore in `logging_config.py`, type `cli.py` client params
- [x] T007 `python -m mypy` reports no issues

## Phase 2: CI Gate (US2)

- [x] T008 Remove `continue-on-error` from the mypy step in `.github/workflows/ci.yml`

## Phase 3: Verification

- [x] T009 pytest (162 pass), ruff, `scripts/emulator_smoke.py` exit 0, pip-audit clean
- [ ] T010 Verify CI passes on the pull request
