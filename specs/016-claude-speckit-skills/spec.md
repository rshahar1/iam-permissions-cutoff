# Feature Specification: Spec-kit commands as Claude Code skills

**Feature Branch**: `016-claude-speckit-skills` | **Created**: 2026-11-20 | **Status**: Implemented

## Summary

The spec-kit command prompts lived in `.cursor/commands/`, which only Cursor reads, and were deleted with the move to Claude Code (014). Claude Code therefore had no `/speckit-*` commands, although the workflow in `CLAUDE.md` is written around them. This feature ports the nine prompts to project skills under `.claude/skills/` and versions them with the repo.

## User Scenarios & Testing

### User Story 1 — Run the spec-kit workflow from Claude Code (Priority: P1)
**Acceptance**: a Claude Code session opened in the repo lists and can run `/speckit-specify`, `/speckit-clarify`, `/speckit-plan`, `/speckit-tasks`, `/speckit-analyze`, `/speckit-implement`, `/speckit-checklist`, `/speckit-constitution` and `/speckit-taskstoissues`.

### User Story 2 — Skills are shared through git (Priority: P1)
**Acceptance**: `.claude/skills/` is committed; agent worktrees and personal settings under `.claude/` stay ignored.

## Requirements

- **FR-001**: One `.claude/skills/speckit-<name>/SKILL.md` per original prompt (from commit `628fda0`), body unchanged except: `/speckit.x` → `/speckit-x`, and `update-agent-context.sh cursor-agent` → `update-agent-context.sh claude` in plan.
- **FR-002**: Frontmatter is `name`, the original `description` and a quoted `argument-hint`, all strings. Cursor-only keys are dropped: `handoffs` becomes a trailing "Next steps" section, and the `tools:` line in taskstoissues is removed (the body still says to use the GitHub MCP server).
- **FR-003**: `.gitignore` ignores only `.claude/worktrees/` and `.claude/settings.local.json`, not all of `.claude/`.
- **FR-004**: `CLAUDE.md` says where the skills live and that they must track `.specify/` on spec-kit upgrades.
