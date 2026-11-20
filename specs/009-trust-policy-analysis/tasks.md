# Tasks: Trust-policy analysis

- [x] T001 Add `principals`/`not_principals` to `PolicyStatement` and parse `Principal`/`NotPrincipal`
- [x] T002 Add `IAMRole.trust_policy` and populate it from `list_roles` in `collectors/roles.py`
- [x] T003 Add `FindingCategory.TRUST_POLICY` and its display name
- [x] T004 Add `src/iam_audit/analyzers/trust.py` (rule table, detectors, `run`, `--trusted-accounts`)
- [x] T005 Register the `trust` check and add it to the `permissions` and `report` subcommands
- [x] T006 Add `tests/unit/test_trust_analyzer.py` and `tests/unit/test_trust_collection.py`
- [x] T007 README: "Trust policy checks" section and `--trusted-accounts` option
- [x] T008 Document the JSON schema delta in `contracts/json-schema-delta.md`
- [x] T009 Run ruff, mypy (strict), pytest and the emulator smoke test
- [ ] T010 Verify CI passes on the pull request
