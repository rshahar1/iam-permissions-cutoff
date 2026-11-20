# Tasks: Shared audit pipeline with a check registry

- [x] T001 Add `src/iam_audit/pipeline.py` with `AuditContext`, `Check`, `Subcommand`, `CHECKS`, `SUBCOMMANDS`, `get_subcommand`, `needs_policies`, `run_checks`
- [x] T002 Port dormancy, permissions and Access Advisor unused analysis into registered checks
- [x] T003 Build CLI subparsers from `SUBCOMMANDS`, wire `Check.add_arguments`, replace the three runners with `_run_subcommand`
- [x] T004 Add `FindingCategory.display_name`; reporters derive section headings from it
- [x] T005 Point integration tests at `iam_audit.pipeline.collect_access_advisor`
- [x] T006 Add `tests/unit/test_pipeline.py`
- [x] T007 Run ruff, mypy (strict), pytest and the emulator smoke test
- [x] T008 Verify CI passes on the pull request — all 5 checks green on PR #4, 2026-11-20
