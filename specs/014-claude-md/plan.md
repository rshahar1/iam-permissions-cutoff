# Implementation Plan: Replace Cursor config with CLAUDE.md

**Branch**: `014-claude-md` | **Date**: 2026-11-20 | **Spec**: [spec.md](spec.md)

## Approach

1. Read the code, `pyproject.toml`, CI workflow, constitution and recent specs; write `CLAUDE.md` from those sources (not from the stale Cursor rule file).
2. Check each command in `CLAUDE.md` by running it locally.
3. `git rm -r .cursor`.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Documentation only; no source changes. |
| II. Security | PASS | No credentials or account data; file restates the no-secrets rule. |
| III. Testing | PASS | No code changes; full suite and smoke test still run in CI. |
| IV. UX Consistency | PASS | Contributor docs now match the actual tooling. |
| V. Performance | PASS | Not affected. |
