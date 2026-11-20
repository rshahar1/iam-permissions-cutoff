# Feature Specification: Trust-policy analysis

**Feature Branch**: `009-trust-policy-analysis` | **Created**: 2026-11-20 | **Status**: Implemented

## Summary

The audit analyzed what roles can do but never who can assume them. A role whose trust policy lets any AWS account, any GitHub repository or any OIDC/SAML/Cognito identity assume it is a direct path into the account. This feature adds a `trust` check (category `trust_policy`) that reads each role's `AssumeRolePolicyDocument` and flags wildcard, cross-account and federated trust flaws.

## User Scenarios & Testing

### User Story 1 — Find roles anyone can assume (Priority: P1)
**Acceptance**: a role trusting `Principal: "*"` (or `{"AWS": "*"}`) with no org/account/ARN restricting condition yields a CRITICAL `TRUST-001` finding; adding such a condition, or using a `Deny` statement, yields none.

### User Story 2 — Review cross-account and federated trust (Priority: P1)
**Acceptance**: foreign-account principals produce `TRUST-003` (HIGH, no ExternalId) or `TRUST-004` (LOW, ExternalId present); GitHub, other OIDC, Cognito and SAML trust without the expected conditions produce `TRUST-005`..`TRUST-009`.

### User Story 3 — Silence known partners (Priority: P2)
**Acceptance**: accounts passed via `--trusted-accounts` (comma-separated, repeatable) and the audited account itself never produce `TRUST-003`/`TRUST-004`.

## Requirements

- **FR-001**: `PolicyStatement` MUST gain `principals` and `not_principals` (`dict[str, list[str]] | None`); the parser normalizes `"*"` to `{"AWS": ["*"]}` and string values to lists.
- **FR-002**: `IAMRole.trust_policy` MUST be filled from `list_roles` (`AssumeRolePolicyDocument`) with no extra API calls; string documents are URL-decoded.
- **FR-003**: Only roles are analyzed; service-linked and `/aws-reserved/` roles are skipped. Only `Allow` statements granting `sts:AssumeRole`, `sts:AssumeRoleWithWebIdentity`, `sts:AssumeRoleWithSAML`, `sts:*` or `*` are examined; condition keys match case-insensitively across all operators.
- **FR-004**: Rules `TRUST-001`..`TRUST-009` are defined as a data table in `analyzers/trust.py`; one finding per statement per rule with metadata `rule_id`, `statement_sid`, `principal`, `condition_keys`.
- **FR-005**: The check runs in `permissions` and `report`; `FindingCategory.TRUST_POLICY` has display name "Trust Policy Findings".
- **FR-006**: JSON output stays additive (`schema_version` 1.0.0), see `contracts/json-schema-delta.md`.

## Success Criteria

- Each rule has a positive and a negative test; full suite, mypy (strict), ruff and the emulator smoke test pass.
