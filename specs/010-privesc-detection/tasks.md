# Tasks: Privilege-escalation detection

- [x] T001 Add `analyzers/grants.py` with case-insensitive action matching for Action/NotAction
- [x] T002 Add `analyzers/privesc.py` with the PE-001..PE-024 rule table, grant/deny evaluation and `run(ctx)`
- [x] T003 Add `FindingCategory.PRIVILEGE_ESCALATION` and its display name
- [x] T004 Register the `privesc` check and add it to the `permissions` and `report` subcommands
- [x] T005 README: "Privilege-escalation checks" section with the rules and the all-resources limitation
- [x] T006 Add `tests/unit/test_privesc_rules.py` and `tests/integration/test_privesc_cli.py`
- [x] T007 Write the JSON contract delta
- [x] T008 Run ruff, mypy (strict), pytest and the emulator smoke test
- [x] T009 Verify CI passes on the pull request — all 5 checks green on PR #6 (54ae6bb, rebased onto 008), 2026-11-20
