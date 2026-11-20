# Implementation Plan: README development setup matches CI

**Branch**: `015-readme-dev-setup` | **Date**: 2026-11-20 | **Spec**: [spec.md](spec.md)

## Approach

1. Align the README "Installation", "Running tests" and "Linting and type checking" blocks with `.github/workflows/ci.yml`.
2. Drop the now-obsolete drift note from `CLAUDE.md`.
3. Run the README commands in a freshly created `.venv`.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Documentation only; no source changes. |
| II. Security | PASS | No credentials or account data. |
| III. Testing | PASS | No code changes; documented commands verified locally. |
| IV. UX Consistency | PASS | Docs now match the tooling (constitution: docs updated with features). |
| V. Performance | PASS | Not affected. |
