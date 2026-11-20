# Feature Specification: Replace Cursor config with CLAUDE.md

**Feature Branch**: `014-claude-md` | **Created**: 2026-11-20 | **Status**: Implemented

## Summary

The repository carried a `.cursor/` folder (spec-kit command prompts and an auto-generated rule file) from when development used Cursor. Development now happens in Claude Code, and the Cursor rule file had gone stale (it listed `prometheus-client`, which is no longer a dependency, and its "Commands" section was unfilled template text). This feature removes `.cursor/` and adds a hand-written `CLAUDE.md` that gives an agent accurate project context.

## User Scenarios & Testing

### User Story 1 — An agent starts with correct project context (Priority: P1)
**Acceptance**: a Claude Code session opened in the repo loads `CLAUDE.md`, which states what the tool does, the exact setup/lint/type-check/test/audit/smoke commands CI runs, the architecture, the coding and security rules, and the spec-kit workflow.

### User Story 2 — No leftover editor-specific config (Priority: P2)
**Acceptance**: `.cursor/` no longer exists in the repo.

## Requirements

- **FR-001**: Delete `.cursor/` (commands and rules) from the repository.
- **FR-002**: Add `CLAUDE.md` at the repo root; every command and file path in it MUST match the code, `pyproject.toml` and `.github/workflows/ci.yml`.
- **FR-003**: `CLAUDE.md` MUST defer to `.specify/memory/constitution.md` on conflict and must not restate it in full.
- **FR-004**: `CLAUDE.md` MUST keep the `## Active Technologies` and `## Recent Changes` headings so `.specify/scripts/bash/update-agent-context.sh claude` can keep updating it.
- **FR-005**: No secrets, real account IDs or principal names in the added file.
