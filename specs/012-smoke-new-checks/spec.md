# Feature Specification: Smoke Test Coverage for New Checks

**Feature Branch**: `012-smoke-new-checks`
**Created**: 2026-11-20
**Status**: Draft
**Input**: User description: "Features 009-011 added trust-policy, privilege-escalation and credential-report checks, but the emulator smoke test (005) only covers permission and scope scenarios. Extend it so the new checks are exercised end to end through the real CLI."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - New Rules Fire End to End (Priority: P1)

A maintainer wants the smoke test to prove that the trust, privilege-escalation and credential rules produce findings through the full CLI path.

**Why this priority**: Unit tests do not cover collection, analysis and JSON output together for these rules.

**Independent Test**: Run `python scripts/emulator_smoke.py`; it exits 0, and exits 1 if any expected rule finding is missing.

**Acceptance Scenarios**:

1. **Given** role `trust-anyone` trusting `Principal: {"AWS": "*"}`, **Then** a `trust_policy` finding TRUST-001 exists.
2. **Given** role `gh-deploy` trusting the GitHub OIDC provider without a `sub` condition, **Then** TRUST-005 exists.
3. **Given** role `passrole-runner` allowing `iam:PassRole` and `ec2:RunInstances` on `*`, **Then** a `privilege_escalation` finding PE-014 exists.
4. **Given** user `console-no-mfa` with a console password and no MFA, **Then** a `credential` finding CRED-004 exists.

---

### User Story 2 - No False Positives on Clean Principals (Priority: P1)

**Independent Test**: Expected-absence assertions pass in the default run.

**Acceptance Scenarios**:

1. `tight-reader` has no `trust_policy` or `privilege_escalation` findings.
2. `ci-admin` has no `privilege_escalation` findings (full-admin principals are skipped by design).
3. `deploy-bot` has no `credential` findings.
4. No `trust_policy` finding exists for any principal other than `trust-anyone` and `gh-deploy`.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `make_role` MUST accept an optional trust policy (default stays EC2 service trust).
- **FR-002**: The script MUST seed `trust-anyone`, `gh-deploy`, `passrole-runner` and `console-no-mfa` with fake test values only.
- **FR-003**: Module-level tables `EXPECTED_RULES` (principal, category, rule id) and `EXPECTED_ABSENT` (principal, category) MUST drive the checks; rule ids are read from `metadata["rule_id"]`.
- **FR-004**: Scope counts become 11 (default) and 13 (`--include-aws-managed`); all existing checks are kept.
- **FR-005**: README "Local emulator smoke test" MUST mention the new coverage.
- **FR-006**: No changes to `src/`.

### Out of Scope

- Access Advisor coverage (moto limitation, see 005).
- Credential-report rules beyond CRED-004 and trust rules beyond TRUST-001/005.

## Success Criteria *(mandatory)*

- **SC-001**: The script exits 0 with all checks passing.
- **SC-002**: Changing any expected rule id makes the script exit 1.
