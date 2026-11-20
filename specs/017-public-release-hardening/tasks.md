# Tasks: Public release hardening

## Repository files

- [x] T001 [P] Add `LICENSE` (MIT)
- [x] T002 [P] Add `SECURITY.md` (private vulnerability reporting, supported versions, scope, response targets)
- [x] T003 [P] Add `CONTRIBUTING.md` (setup, CI checks, spec-kit workflow, security rules, review process)
- [x] T004 [P] Add `.github/CODEOWNERS` assigning every path to the owner
- [x] T005 [P] Add `.github/pull_request_template.md` and issue forms in `.github/ISSUE_TEMPLATE/` (bug, feature, config with blank issues disabled and a security link)
- [x] T006 [P] Add `.github/dependabot.yml` (weekly pip and github-actions updates)
- [x] T007 Add License, Contributing and Security sections to `README.md`

## Settings definitions

- [x] T008 Define `contracts/ruleset-ci-gate.json` and `contracts/ruleset-review-gate.json` with check names read from live check runs
- [x] T009 Write the post-publication runbook `quickstart.md`

## Verification

- [x] T010 Validate YAML/JSON files, scan new files for emails, account IDs and secrets, run ruff, mypy and pytest
- [x] T011 Update `CLAUDE.md` Recent Changes and open the PR

## After publication (owner)

- [x] T012 Owner makes the repository public, then the runbook steps 1-5 are applied and verified (2026-11-20; rulesets `main: CI gate` and `main: owner review gate` active)
