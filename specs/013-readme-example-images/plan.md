# Implementation Plan: README example report images

**Branch**: `013-readme-example-images` | **Date**: 2026-11-20 | **Spec**: [spec.md](spec.md)

## Approach

1. Seed the moto emulator with the smoke test's scenarios (`scripts/emulator_smoke.py` helpers) and run `iam-audit report` in-process in text, JSON and HTML formats, replacing `iam_audit.pipeline.collect_access_advisor` with simulated last-accessed data.
2. Text → terminal-style SVG: header plus the first findings of each category, long lines soft-wrapped, severities coloured.
3. HTML → PNG screenshots with headless Chrome (sections expanded): an overview (summary badges + first table) and the full report.
4. Replace the README "Output Formats" examples; refresh `examples/`; preview through GitHub's Markdown API before committing.

The one-off generation scripts were not added to the repo; regenerate the same way if the output format changes.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Documentation and sample assets only; no source changes. |
| II. Security | PASS | Fictional emulator data only; placeholder account ID verified; no credentials. |
| III. Testing | PASS | No code changes; full suite and smoke test still run in CI. |
| IV. UX Consistency | PASS | README examples now match real output (constitution: docs updated with features). |
| V. Performance | PASS | Image sizes kept small: 7 KB SVG, 261 KB and 638 KB PNGs. |
