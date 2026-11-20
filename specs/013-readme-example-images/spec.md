# Feature Specification: README example report images

**Feature Branch**: `013-readme-example-images` | **Created**: 2026-11-20 | **Status**: Implemented

## Summary

The README's "Output Formats" section showed a hand-written text example that no longer matched the tool's real output (different layout, only the original two categories). New users could not see what a report looks like. This feature adds images of real output and refreshes the sample reports.

## User Scenarios & Testing

### User Story 1 — See what the reports look like before installing (Priority: P1)
**Acceptance**: the README shows (a) a terminal image of `iam-audit report` text output covering every finding category, and (b) a screenshot of the HTML report that links to a full-length screenshot; the JSON snippet reflects the current categories.

### User Story 2 — Trust that examples contain no real data (Priority: P1)
**Acceptance**: a note states the examples come from a fictional account (placeholder `123456789012`) in the local moto emulator, and that Access Advisor data behind *Unused Permission* findings is simulated because moto does not implement Access Advisor.

## Requirements

- **FR-001**: Images MUST be generated from the real CLI and reporters against the smoke test's emulator account; only Access Advisor responses may be simulated.
- **FR-002**: Images live in `docs/images/` (`report-text.svg`, `report-html-overview.png`, `report-html-full.png`); the text image is an SVG so it stays sharp and small.
- **FR-003**: `examples/report.{txt,json,html}` MUST be regenerated from the same sample run.
- **FR-004**: No real AWS account data: the only 12-digit account ID in the added files is `123456789012`.
- **FR-005**: The README must render correctly on GitHub (verified with GitHub's Markdown API in `markdown` mode).
