# Feature Specification: Fix P0 Analyzer Correctness Bugs

**Feature Branch**: `004-fix-p0-analyzer-bugs`
**Created**: 2026-11-20
**Status**: Draft
**Input**: User description: "A review of the IAM audit tool found five correctness bugs that cause false negatives (missed risky policies) and false positives (noise). A real run produced 3,761 findings for 49 principals; 2,631 were on AWS IAM Identity Center (SSO) reserved roles under `/aws-reserved/sso.amazonaws.com/`."

## Clarifications

### Session 2026-11-20

- Q: Should `--include-aws-managed` also control whether AWS-managed policies are analyzed? → A: No. The flag controls **principal scope only**. AWS-managed policies attached to customer principals are always analyzed, because skipping them would hide e.g. `AdministratorAccess` on a customer role (a critical false negative).
- Q: How are roles under `/aws-reserved/` treated? → A: As AWS-managed. They are Identity Center permission-set roles that cannot be edited in IAM, so they are excluded by default and included only with `--include-aws-managed`.
- Q: Is the JSON output contract changing? → A: Additive only. `schema_version` stays `1.0.0`; permission-finding metadata gains three keys (see `contracts/json-schema-delta.md`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Detect Grants Expressed with NotAction / NotResource (Priority: P1)

A security engineer audits an account where a policy contains `{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}`. This grants nearly every AWS action, but today the tool reports nothing because it reads only `Action` and `Resource`. The engineer needs such statements flagged with a NotAction-specific recommendation.

**Why this priority**: A silent false negative on a near-administrator grant is the most dangerous failure mode of an audit tool.

**Independent Test**: Run the permission analyzer on a policy with an Allow+NotAction statement on `Resource: "*"` and verify a HIGH finding with the NotAction recommendation; repeat with a scoped resource (MEDIUM) and with `NotResource` (treated as all resources).

**Acceptance Scenarios**:

1. **Given** an Allow statement with `NotAction: "iam:*"` and `Resource: "*"`, **When** the permission analysis runs, **Then** a HIGH finding is produced recommending "replace NotAction with an explicit allow-list of actions".
2. **Given** an Allow statement with `NotAction` and a scoped `Resource` ARN, **When** the analysis runs, **Then** a MEDIUM finding is produced.
3. **Given** an Allow statement with `NotResource` (and any `Action`), **When** the analysis runs, **Then** the statement is treated as applying to all resources.
4. **Given** an Allow+NotAction statement, **When** unused-permission analysis runs, **Then** every known service except those wholly excluded via `svc:*` is considered granted; individually excluded actions are not reported as unused.

---

### User Story 2 - Robust Wildcard Classification (Priority: P1)

A team lead wants wildcard severity to be correct regardless of how the policy author wrote it: `Action: "*"` on a single bucket ARN, `["*","s3:GetObject"]` on `"*"`, or `Resource: ["arn:...","*"]` must all be classified by what they really grant.

**Why this priority**: Wrong severity or missing findings undermines trust in every report; it is also a false-negative class.

**Independent Test**: Table-driven classifier tests covering each action/resource combination and expected severity.

**Acceptance Scenarios**:

1. **Given** `Action: ["*","s3:GetObject"]` on `Resource: "*"`, **Then** the finding is CRITICAL.
2. **Given** `Action: "*"` on a single bucket ARN, **Then** the finding is HIGH.
3. **Given** `Resource: ["arn:aws:s3:::b","*"]` with `Action: "*"`, **Then** the finding is CRITICAL (all resources).
4. **Given** `Action: "*:*"`, **Then** it is treated as all actions.
5. **Given** `s3:*` on a scoped resource, **Then** HIGH; `s3:Get*` on a scoped resource, **Then** MEDIUM; more than 5 actions on `"*"`, **Then** HIGH; 2-5 actions on `"*"`, **Then** MEDIUM.

---

### User Story 3 - No False "Unused" Findings for Untracked Actions (Priority: P1)

An operator sees `s3:GetObject` reported as unused on every principal because Access Advisor does not track data-plane actions. They want unused-permission findings to cover only actions Access Advisor actually tracks.

**Why this priority**: These false positives drown real findings and teach users to ignore the report.

**Independent Test**: Feed the unused analyzer a granted `s3:*` with Access Advisor tracking only a few S3 actions; only those tracked actions appear, split into used and unused by threshold.

**Acceptance Scenarios**:

1. **Given** a granted `s3:GetObject` that Access Advisor does not track, **When** the analysis runs, **Then** it is not reported.
2. **Given** a tracked action matching a granted pattern and last accessed within the threshold, **Then** it is "used"; otherwise "unused".
3. **Given** a finding, **Then** its description states only Access Advisor-tracked actions are assessed, and action names use AWS's canonical casing from Access Advisor.

---

### User Story 4 - Correct Case-Insensitive Glob Matching (Priority: P2)

An engineer's policy grants `s3:createbucket` (valid, since IAM action names are case-insensitive) and `s3:Get*Tagging`. Both must match the tracked actions they really cover.

**Why this priority**: Fixes both false positives (used action reported unused) and false negatives (mid-string wildcards matching nothing).

**Independent Test**: Unit tests for `s3:createbucket`, `s3:Get*Tagging`, and `s3:Get?bject`-style patterns against tracked action names.

**Acceptance Scenarios**:

1. **Given** granted `s3:createbucket` and tracked `s3:CreateBucket` used recently, **Then** the action is "used".
2. **Given** granted `s3:Get*Tagging`, **Then** it matches `GetObjectTagging` and `GetBucketTagging`.
3. **Given** a granted pattern with `?`, **Then** `?` matches exactly one character.

---

### User Story 5 - Sensible Default Scope and `--include-aws-managed` Semantics (Priority: P1)

An operator running against an account with IAM Identity Center sees thousands of findings on `/aws-reserved/sso.amazonaws.com/` roles they cannot edit in IAM. By default these roles must be excluded; `--include-aws-managed` brings them back. AWS-managed policies on customer principals are always analyzed, and findings on them recommend detaching and replacing them.

**Why this priority**: Removes ~70% of observed noise (2,631 of 3,761 findings) and fixes misleading help text.

**Independent Test**: Collect roles with moto including a `/aws-reserved/sso.amazonaws.com/` role; verify exclusion by default and inclusion with the flag; verify a customer role with `AdministratorAccess` yields a finding with `policy_is_aws_managed: true`.

**Acceptance Scenarios**:

1. **Given** a role under `/aws-reserved/`, **When** run without `--include-aws-managed`, **Then** it is not scanned.
2. **Given** the same role, **When** run with `--include-aws-managed`, **Then** it is scanned.
3. **Given** a customer role with AWS-managed `AdministratorAccess`, **When** run with default flags, **Then** a CRITICAL finding with `policy_is_aws_managed: true` is produced whose recommendation says to detach it and replace it with a customer-managed least-privilege policy.
4. **Given** `--help`, README and docs, **Then** all describe the flag as controlling AWS-managed principals (service-linked, service, and reserved roles), not policies.

---

### Edge Cases

- Statement with both `Action` and `NotAction` (invalid in AWS): `NotAction` is parsed and analyzed; no crash.
- `NotAction`/`NotResource` given as a single string or a list: both accepted.
- `Allow` + `NotAction` listing only `svc:*` for every known service: grants nothing assessable; no unused findings.
- Deny statements with `NotAction`: not analyzed as grants (existing Deny-note behavior unchanged).
- Action patterns with mixed case or regex-special characters: matched as literal text plus `*`/`?` only.
- Access Advisor returns no tracked actions for a service: service-level findings unchanged; no action-level findings.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The policy parser MUST read `NotAction` and `NotResource` (string or list) into `not_actions` and `not_resources` on `PolicyStatement`, defaulting to empty lists.
- **FR-002**: An Allow statement with `NotAction` MUST be HIGH when it applies to all resources and MEDIUM otherwise, with a recommendation to replace NotAction with an explicit allow-list of actions.
- **FR-003**: An Allow statement with `NotResource` MUST be treated as applying to all resources.
- **FR-004**: Classification MUST treat actions as "all actions" if any action is `*` or `*:*`, and resources as "all resources" if any resource is `*` or NotResource is used.
- **FR-005**: Severity MUST be: CRITICAL = all actions on all resources; HIGH = all actions on scoped resources, a service wildcard (`svc:*`), NotAction on all resources, or more than 5 actions on all resources; MEDIUM = more than 1 action on all resources, a partial wildcard (e.g. `s3:Get*`), or NotAction on scoped resources.
- **FR-006**: The unused-permission analyzer MUST treat an Allow+NotAction statement as granting every known service except those wholly excluded by `svc:*`, and MUST NOT report individually excluded actions as unused.
- **FR-007**: The unused-permission analyzer MUST assess only actions present in Access Advisor's `TrackedActionsLastAccessed`; a tracked action matching any granted pattern is "used" if last accessed within the `--days` threshold, otherwise "unused". Untracked granted actions MUST NOT be reported.
- **FR-008**: Unused-permission finding descriptions MUST state that only Access Advisor-tracked actions are assessed; output action names MUST use AWS's canonical casing.
- **FR-009**: Action matching MUST be case-insensitive glob matching supporting `*` and `?` anywhere in the pattern. The prefix-expansion helper `_expand_wildcard_actions` MUST be removed.
- **FR-010**: `IAMRole` MUST expose `is_aws_reserved`, true for roles whose path starts with `/aws-reserved/`; such roles MUST be excluded unless `--include-aws-managed` is set.
- **FR-011**: AWS-managed policies attached to in-scope principals MUST always be analyzed, regardless of `--include-aws-managed`.
- **FR-012**: Permission findings MUST carry metadata `policy_is_aws_managed`; when true, the recommendation MUST say to detach the policy and replace it with a customer-managed least-privilege policy.
- **FR-013**: CLI help text, README and docs MUST describe `--include-aws-managed` as controlling principal scope only.
- **FR-014**: JSON output changes MUST be additive; `schema_version` MUST remain `1.0.0`.

### Key Entities

- **PolicyStatement**: gains `not_actions` and `not_resources` (lists of strings, default empty).
- **IAMRole**: gains `is_aws_reserved` (bool).
- **Permission finding metadata**: gains `not_actions`, `not_resources`, `policy_is_aws_managed`.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A policy granting `NotAction` produces a finding in 100% of cases where the equivalent allow-list would.
- **SC-002**: Every combination in the wildcard classification table yields its documented severity.
- **SC-003**: On an account with IAM Identity Center, default-run finding count drops by the reserved-role share (about 70% in the reviewed run) with no loss of findings on customer principals.
- **SC-004**: No unused-permission finding names an action that Access Advisor does not track.
- **SC-005**: All regression tests pass, coverage stays at or above 80%, and `ruff` reports no violations.

## Out of Scope (Follow-ups)

- Trust-policy analysis
- Privilege-escalation rules
- Credential report analysis
- Permission boundaries and SCPs
- Finding grouping and stable finding IDs
- API-call efficiency improvements
- Refactor of duplication in `collectors/policies.py`
- Existing mypy errors
