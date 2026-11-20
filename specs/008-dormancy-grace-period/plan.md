# Implementation Plan: Dormancy grace period for new principals

**Branch**: `008-dormancy-grace-period` | **Date**: 2026-11-20 | **Spec**: [spec.md](spec.md)

## Technical Context

Python 3.12, stdlib only. Changes in `analyzers/dormancy.py`, one argument in `pipeline.py`, the smoke script, README and tests. No dependency changes.

## Design

- `age_days = (now - created_date).days`; with no activity, skip when `age_days < threshold`, otherwise MEDIUM (HIGH from 2x threshold).
- The finding builders are split into helpers so each function stays under 40 lines; severity uses one shared function for both branches.
- Roles older than 400 days get a description about the IAM `RoleLastUsed` tracking window.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Small typed, documented helpers; functions ≤ 40 lines; file well under 400 lines. |
| II. Security | PASS | No new inputs or AWS calls; read-only. |
| III. Testing | PASS | Scenario-named unit tests with a fixed `now`; only AWS I/O is mocked elsewhere. |
| IV. UX Consistency | PASS | Same CLI surface; fewer false HIGH findings; README updated. |
| V. Performance | PASS | Pure in-memory computation, no extra calls. |
