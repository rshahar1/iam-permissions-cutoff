# Tasks: Credential report hygiene checks

- [x] T001 Add `FindingCategory.CREDENTIAL` and its display name
- [x] T002 Add `collectors/credential_report.py` (generate/poll/parse, data gap on failure)
- [x] T003 Add `analyzers/credentials.py` with rules CRED-001..CRED-008, `--key-max-age` and `run(ctx)`
- [x] T004 Register the `credentials` check, add it to `report`, add the `credentials` subcommand
- [x] T005 Add `tests/unit/test_credential_report_collector.py` (incl. moto-backed report)
- [x] T006 Add `tests/unit/test_credentials_analyzer.py`
- [x] T007 Update README (credential checks, subcommand, option, IAM permissions)
- [x] T008 Add `contracts/json-schema-delta.md`
- [x] T009 Run ruff, mypy (strict), pytest and the emulator smoke test
- [x] T010 Verify CI passes on the pull request — all 5 checks green on PR #7 (b853406, merged with 008+010), 2026-11-20
