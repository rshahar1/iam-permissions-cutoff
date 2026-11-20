# Tasks: Dormancy grace period for new principals

- [x] T001 Rework `analyze_dormancy` with the creation-based grace period, `now` parameter and 400-day role note
- [x] T002 Pass `ctx.now` from the dormancy check in `pipeline.py`
- [x] T003 Assert zero dormancy findings in `scripts/emulator_smoke.py`
- [x] T004 Update dormancy unit tests and add grace-period, boundary, naive-datetime and 400-day tests
- [x] T005 Update README dormancy and severity descriptions
- [x] T006 Run ruff, mypy (strict), pytest and the emulator smoke test
- [x] T007 Verify CI passes on the pull request — all 5 checks green on PR #5, 2026-11-20
