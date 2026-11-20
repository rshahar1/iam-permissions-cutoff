# Implementation Plan: Shared audit pipeline with a check registry

**Branch**: `007-check-pipeline` | **Date**: 2026-11-20 | **Spec**: [spec.md](spec.md)

## Technical Context

Python 3.12, stdlib only. New module `src/iam_audit/pipeline.py`; `cli.py`, `models.py` and both reporters updated. No dependency changes.

## Design

- Existing analyses become checks: `dormancy`, `permissions` (needs policies) and `unused` (needs policies; runs Access Advisor and appends its data gaps to `ctx.data_gaps`).
- Subcommand epilogs move next to their `Subcommand` definitions; the top-level epilog stays in `cli.py`.
- `_run_subcommand` does: validate output args → init AWS → collect → filter → enrich if needed → `run_checks` → build report → output.
- Reporters derive their `CATEGORY_DISPLAY*` maps from `FindingCategory.display_name` (the names are kept as module constants for compatibility).

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Removes the three duplicated runners (rule of three); functions ≤ 40 lines; typed and documented. |
| II. Security | PASS | No new inputs, no AWS calls added, read-only. |
| III. Testing | PASS | New `tests/unit/test_pipeline.py` covers registry consistency, ordering, `needs_policies`, option wiring and display names; existing suite unchanged. |
| IV. UX Consistency | PASS | Same CLI surface and output; `report` help now says it runs all checks. |
| V. Performance | PASS | Same API calls; policies still fetched only when needed. |
