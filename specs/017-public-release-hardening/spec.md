# Feature Specification: Public release hardening

**Feature Branch**: `017-public-release-hardening`
**Created**: 2026-11-20
**Status**: Implemented; repository public and all runbook settings applied on 2026-11-20
**Input**: User description: "Prepare the repository to become public on GitHub Free so outside users can use and contribute; every PR must pass CI and be reviewed by the owner only."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Outside user can legally use the tool and knows how to report a vulnerability (Priority: P1)

A security engineer finds the repository, wants to run it against their own AWS accounts, and needs to know the license terms and how to report a vulnerability privately.

**Why this priority**: Without a license nobody may legally use or contribute to the code; without a private reporting channel, vulnerabilities in a security tool get disclosed in public issues.

**Independent Test**: Open the repository front page: the license is detected, and the Security policy explains private reporting.

**Acceptance Scenarios**:

1. **Given** the repository is public, **When** a visitor opens it, **Then** the license (MIT) is shown and the README links to the license, contributing guide and security policy.
2. **Given** a visitor finds a vulnerability, **When** they try to open an issue, **Then** the issue chooser points them to private vulnerability reporting instead of a public issue.

---

### User Story 2 - Contributor opens a pull request that goes through CI and owner review (Priority: P1)

An outside contributor forks the repository, makes a change and opens a pull request. The change can only reach `main` after all four CI jobs pass and the owner approves it.

**Why this priority**: This is the owner's core requirement: no change reaches `main` without CI and the owner's review.

**Independent Test**: Open a pull request from a fork: its workflows wait for owner approval to run, the merge button stays blocked until the required checks pass and a code-owner approval is present.

**Acceptance Scenarios**:

1. **Given** a pull request from a first-time or outside contributor, **When** it is opened, **Then** CI does not run until the owner approves the workflow run.
2. **Given** a pull request with a failing or missing required check, **When** anyone tries to merge, **Then** merging is blocked.
3. **Given** a pull request with green checks but no approval from the code owner, **When** anyone without admin rights tries to merge, **Then** merging is blocked.
4. **Given** an approved pull request that receives a new push, **When** merging is attempted, **Then** a fresh approval is required.
5. **Given** the owner's own pull request with green checks, **When** the owner merges it, **Then** the review requirement is bypassed (self-approval is impossible on GitHub) but the CI requirement is not.
6. **Given** anyone, including the owner, **When** they push directly, force-push or delete `main`, **Then** the push is rejected.

---

### User Story 3 - Contributor knows what is expected before opening a PR (Priority: P2)

A contributor reads the contributing guide and pull request template and knows how to set up the project, which checks must pass and which project rules (read-only, placeholder account IDs, no secrets) apply.

**Why this priority**: Reduces review round-trips and protects the project's security rules, but the repository is usable without it.

**Independent Test**: Follow CONTRIBUTING.md from a fresh clone and run all checks successfully; open a PR and see the template checklist.

**Acceptance Scenarios**:

1. **Given** a fresh clone, **When** a contributor follows CONTRIBUTING.md, **Then** they can install the project and run the same checks CI runs.
2. **Given** a contributor opens a pull request, **When** the form loads, **Then** it contains a checklist covering checks, tests, docs, read-only rule and secrets.

---

### User Story 4 - Dependencies and code are watched automatically (Priority: P3)

The owner is alerted to vulnerable dependencies, outdated pinned GitHub Actions and code-scanning findings without manual effort.

**Why this priority**: Ongoing hygiene; the existing `pip-audit` CI job already gates merges.

**Independent Test**: After the settings are applied, the Security tab shows Dependabot, secret scanning and code scanning enabled, and Dependabot opens update PRs on its weekly schedule.

**Acceptance Scenarios**:

1. **Given** a weekly schedule, **When** a newer pip dependency or pinned action version exists, **Then** Dependabot opens a pull request that goes through the same CI and review gates.
2. **Given** someone pushes a commit containing a recognised secret, **When** the push reaches GitHub, **Then** push protection blocks it.

### Edge Cases

- The repository is still private on GitHub Free: rulesets cannot be created yet; the runbook says to make the repository public first.
- A required check is renamed in `ci.yml`: the ruleset's required check names must be updated in the same PR, otherwise every PR is blocked waiting for a check that never reports.
- Dependabot PRs touch `.github/workflows/`: they still need CI and owner approval like any other PR.
- A contributor's PR modifies the CI workflow itself: fork PR workflows still require owner approval and run with a read-only token and no secrets.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The repository MUST contain an MIT license file recognised by GitHub.
- **FR-002**: The repository MUST contain a security policy that directs vulnerability reports to GitHub private vulnerability reporting, states the supported version and scope, and asks reporters not to use public issues.
- **FR-003**: The repository MUST contain a contributing guide covering setup, the CI checks, the spec-kit workflow, the project's security rules and the review process.
- **FR-004**: A code owners file MUST assign every path to the owner, so every pull request requests the owner's review.
- **FR-005**: The repository MUST provide a pull request template and issue forms for bug reports and feature requests; blank issues MUST be disabled and the chooser MUST link to private vulnerability reporting.
- **FR-006**: Dependabot MUST be configured for weekly pip and GitHub Actions version updates.
- **FR-007**: The README MUST link to the license, contributing guide and security policy.
- **FR-008**: The feature MUST provide two importable ruleset definitions for `main`: a CI gate (pull request required, the five required checks, up-to-date branch, no force push or deletion, linear history, resolved conversations; no bypass) and a review gate (one approval, code-owner review, stale approvals dismissed, last-push approval; repository admins may bypass for pull requests only).
- **FR-009**: The feature MUST provide a runbook listing every repository setting to apply after the repository is public (merge methods, Actions permissions and fork approval, security features) with the commands or UI paths to apply and verify them.
- **FR-010**: No file added by this feature may contain personal email addresses, real account IDs, credentials or other secrets.

### Key Entities

- **Ruleset definition**: A named set of rules targeting the default branch, with an enforcement mode and an optional list of bypass actors.
- **Repository setting**: A named toggle or value on the repository (merge methods, Actions permissions, security features) with an expected value and a way to verify it.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of changes reaching `main` after the settings are applied arrive through a pull request with all five required checks green.
- **SC-002**: 0 pull requests from people other than the owner can be merged without the owner's approval.
- **SC-003**: A new contributor can go from fresh clone to a full local check run by following only the contributing guide.
- **SC-004**: The owner can apply and verify all post-publication settings by following the runbook in under 15 minutes.

## Assumptions

- The repository stays under the owner's personal account on GitHub Free; no collaborators with write access are added, so only the owner can merge.
- MIT is the chosen license (requested by the owner's go-ahead on the proposed hardening; easily swapped before merge).
- The owner decides separately whether to rewrite commit author emails before publication; this feature does not rewrite history.
- The owner flips visibility to public themself; this feature does not change visibility.
