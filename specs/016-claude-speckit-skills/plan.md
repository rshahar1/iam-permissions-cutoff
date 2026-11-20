# Implementation Plan: Spec-kit commands as Claude Code skills

**Branch**: `016-claude-speckit-skills` | **Date**: 2026-11-20 | **Spec**: [spec.md](spec.md)

## Approach

1. Convert each `git show 628fda0:.cursor/commands/speckit.<name>.md` with a one-off script (not committed) applying only the FR-001/FR-002 changes; diff each result against its original.
2. Narrow the `.claude/` ignore rule; update `CLAUDE.md`.
3. Parse every frontmatter as YAML (all values strings) and confirm a headless `claude -p` session lists all nine skills.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Agent prompts and config only; no source changes. |
| II. Security | PASS | No secrets; `.claude/settings.local.json` and worktrees stay ignored. |
| III. Testing | PASS | No code changes; frontmatter validated and skill loading checked. |
| IV. UX Consistency | PASS | Command names match the workflow documented in `CLAUDE.md`. |
| V. Performance | PASS | Not affected. |
