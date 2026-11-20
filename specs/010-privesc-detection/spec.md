# Feature Specification: Privilege-escalation detection

**Feature Branch**: `010-privesc-detection` | **Created**: 2026-11-20 | **Status**: Implemented

## Summary

The permissions analyzer flags wildcard policies but not combinations of narrow permissions that let a principal escalate to administrator (for example `iam:PutRolePolicy`, or `iam:PassRole` + `lambda:CreateFunction`). This feature adds a `privesc` check that evaluates each principal's effective grants (managed, inline and group policies) against a table of 24 well-known escalation techniques.

## User Scenarios & Testing

### User Story 1 — Find escalation paths (Priority: P1)
**Acceptance**: `iam-audit permissions` and `iam-audit report` emit `privilege_escalation` findings, one per principal per matched rule, with severity from the rule table and metadata `rule_id`, `rule_name`, `matched_actions`, `granting_policies`.

### User Story 2 — No noise from scoped or denied grants (Priority: P1)
**Acceptance**: grants limited to specific resources do not fire; an unconditional `Deny` on `*` suppresses the matched actions; a `Deny` with a `Condition` does not; full-admin principals produce no privesc findings (already CRITICAL under `permissions`).

## Requirements

- **FR-001**: An action is granted only by an `Allow` statement that applies to all resources (`"*"` in `Resource` or any `NotResource`), via `Action` patterns (case-insensitive globs) or `NotAction`.
- **FR-002**: A `Deny` removes an action only if it lists `"*"` as a resource and has no `Condition` (`Action` or `NotAction` form).
- **FR-003**: A rule fires only when ALL its `required_actions` are granted; metadata `granting_policies` is the sorted union of policy names granting them.
- **FR-004**: Rules PE-001..PE-024 are defined as data in `analyzers/privesc.py`.
- **FR-005**: New `FindingCategory.PRIVILEGE_ESCALATION` ("Privilege Escalation Findings"); `schema_version` stays 1.0.0.
- **FR-006**: The check runs in `permissions` and `report` and needs policy documents.

## Limitations

Only grants on all resources are evaluated; scoped grants (e.g. `iam:PassRole` on one role) are ignored. Permission boundaries, SCPs, session policies and conditions on `Allow` statements are not evaluated.

## Success Criteria

- Each rule has a positive test; wildcard, NotAction, deny, scoping and group-attribution scenarios are covered.
- Full test suite, mypy (strict), ruff and the emulator smoke test pass.
