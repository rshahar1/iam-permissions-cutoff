# Implementation Plan: Public release hardening

**Branch**: `017-public-release-hardening` | **Date**: 2026-11-20 | **Spec**: [spec.md](spec.md)

## Approach

1. Add the community files GitHub recognises: `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, `.github/CODEOWNERS`,
   `.github/pull_request_template.md`, `.github/ISSUE_TEMPLATE/{bug_report.yml,feature_request.yml,config.yml}` and
   `.github/dependabot.yml` (weekly `pip` and `github-actions` updates, grouped, limited open PRs).
2. README: add License, Contributing and Security sections linking to those files.
3. Define the branch rules as two importable rulesets in [`contracts/`](contracts/):
   - [`ruleset-ci-gate.json`](contracts/ruleset-ci-gate.json): pull request required, squash only, the five required
     checks (`test (3.12)`, `test (3.13)`, `typecheck`, `audit`, `smoke`, pinned to the GitHub Actions app) with an
     up-to-date branch, linear history, resolved conversations, no deletion or force push. **No bypass actors**, so the
     owner's own PRs also need green CI.
   - [`ruleset-review-gate.json`](contracts/ruleset-review-gate.json): one approval, code-owner review, stale approvals
     dismissed, approval of the last push. Repository admins may bypass **for pull requests only**, because GitHub never
     lets an author approve their own PR and the owner is the sole maintainer.
   Splitting them is deliberate: a bypass skips every rule in a ruleset, so one combined ruleset would let the owner
   skip CI as well.
4. Write the post-publication runbook [`quickstart.md`](quickstart.md): merge methods, Actions permissions and fork-PR
   approval, security features, ruleset import, and verification commands. Rulesets cannot be created while the
   repository is private on GitHub Free, so settings are applied after the owner flips visibility.

Required check names were read from the check runs of `f751409` on `main` (all reported by app `github-actions`, id
15368). If a job in `.github/workflows/ci.yml` is renamed, update `ruleset-ci-gate.json` and the live ruleset in the
same PR, otherwise every PR waits for a check that never reports.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Repository configuration and documentation only; no source changes. |
| II. Security | PASS | Adds private vulnerability reporting, secret scanning with push protection, Dependabot, CodeQL, read-only workflow token and fork-PR approval. No secrets or personal emails in new files; only the owner's public GitHub handle (CODEOWNERS). |
| III. Testing | PASS | No code changes; the full CI suite runs on the PR. Rulesets make the CI gate mandatory for every change. |
| IV. UX Consistency | PASS | README links to the new docs in the same PR; CONTRIBUTING mirrors the commands in `CLAUDE.md` and CI. |
| V. Performance | PASS | Not affected. |

**Development Workflow note**: the constitution requires "at least one approving review". External PRs get it from the
review gate. The owner's own PRs cannot be self-approved on GitHub, so they use the admin pull-request bypass, which is
what every PR merged so far has effectively done; CI remains mandatory for them.

## Out of scope

- Changing repository visibility (the owner does it).
- Rewriting git history to change commit author emails (owner's decision; see quickstart step 0).
- Adding CodeQL as a required check (it can be added later as a `code_scanning` ruleset rule once it has run on `main`).
