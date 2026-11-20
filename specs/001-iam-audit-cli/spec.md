# Feature Specification: IAM Audit CLI

**Feature Branch**: `001-iam-audit-cli`
**Created**: 2026-03-07
**Status**: Draft
**Input**: User description: "Develop a CLI utility to help teams minimize IAM over-provisioning. The tool must audit any AWS environment, evaluating IAM roles and IAM users to identify redundant entities or bloated policies. It should offer actionable insights to delete dormant objects or trim unused permissions, ensuring a lean, Least Privilege security posture."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Audit IAM Roles and Users for Dormancy (Priority: P1)

A security engineer wants to quickly identify IAM roles and users that have not been used within a configurable time window. They run the CLI tool against their AWS account and receive a clear report listing every dormant entity — those with no login activity, no API calls, and no assumption events — along with the last-activity date and a recommended action (delete or flag for review).

**Why this priority**: Dormant principals are the lowest-hanging fruit for reducing attack surface. Removing them has the highest impact-to-risk ratio because unused entities carry zero operational dependency.

**Independent Test**: Run the tool against an AWS account with a mix of active and dormant roles/users. Verify the output correctly categorizes each entity and that every dormant entity includes a last-activity timestamp and a recommended action.

**Acceptance Scenarios**:

1. **Given** an AWS account with 50 IAM roles (10 unused for 90+ days), **When** the user runs `iam-audit dormancy --days 90`, **Then** the output lists exactly those 10 roles with their last-activity date and a "recommend delete" action.
2. **Given** an AWS account with IAM users where 3 have never logged in, **When** the user runs `iam-audit dormancy`, **Then** the 3 users appear with a "never used" indicator and a "recommend delete" action.
3. **Given** an IAM role that was last assumed 89 days ago with a 90-day threshold, **When** the audit runs, **Then** the role is NOT flagged as dormant.
4. **Given** no valid AWS credentials configured, **When** the user runs any audit command, **Then** the tool exits with a clear, actionable error explaining how to configure credentials.

---

### User Story 2 - Identify Overly Permissive Policies (Priority: P2)

A cloud security team lead wants to detect IAM policies that grant excessively broad permissions — wildcard actions (`*`), wildcard resources (`*`), or overly permissive action patterns (e.g., `s3:*`). The tool analyzes both inline policies and attached managed policies on roles and users, then reports which statements are overly permissive along with a severity rating and a suggestion for tightening.

**Why this priority**: Overly permissive policies are the primary enabler of privilege escalation. Identifying them is essential for achieving least privilege, but the analysis is more complex than dormancy detection.

**Independent Test**: Run the tool against an account with known wildcard policies and known tightly-scoped policies. Verify the report correctly flags only the overly permissive ones and that each finding includes a severity and a tightening suggestion.

**Acceptance Scenarios**:

1. **Given** a role with an inline policy containing `"Action": "*", "Resource": "*"`, **When** the user runs `iam-audit permissions`, **Then** the tool reports this statement as "Critical" severity with a recommendation to scope actions and resources.
2. **Given** a user with an attached managed policy granting `s3:*` on all S3 buckets, **When** the audit runs, **Then** the finding is reported as "High" severity with a suggestion to restrict to specific buckets and actions.
3. **Given** a role with a tightly-scoped policy allowing only `s3:GetObject` on a single bucket ARN, **When** the audit runs, **Then** the role does NOT appear in the overly permissive findings.
4. **Given** a role with both a permissive inline policy and a tight managed policy, **When** the audit runs, **Then** both policies are analyzed independently and only the permissive one is flagged.

---

### User Story 3 - Generate a Consolidated Audit Report (Priority: P3)

An engineering manager wants a single, comprehensive audit report that combines dormancy findings and permission findings into one document. The report must be available in both human-readable (table/text) and machine-readable (JSON) formats so it can be reviewed manually or fed into automation pipelines.

**Why this priority**: Consolidation and export are usability features that amplify the value of P1 and P2. Without them the tool is still functional, but less convenient for organizational workflows and CI/CD integration.

**Independent Test**: Run a full audit and request output in both formats. Verify the JSON output is valid, parseable, and contains the same findings as the human-readable output. Verify the human-readable output is well-formatted and easy to scan.

**Acceptance Scenarios**:

1. **Given** an AWS account with both dormant entities and overly permissive policies, **When** the user runs `iam-audit report --format text`, **Then** the output is a well-structured, human-readable table grouping findings by category (dormancy, permissions) with summary counts.
2. **Given** the same account, **When** the user runs `iam-audit report --format json`, **Then** the output is valid JSON conforming to a documented schema, containing all findings with their metadata.
3. **Given** an account with zero findings, **When** the user runs `iam-audit report`, **Then** the output clearly states "No issues found" rather than producing an empty or confusing output.
4. **Given** a large account (500+ roles), **When** the user runs `iam-audit report`, **Then** the report completes without loading all data into memory at once (pagination) and the output includes a summary section at the top with total counts.

---

### User Story 4 - Scope Audit to Specific Resources (Priority: P4)

A DevOps engineer managing a large multi-team AWS account wants to scope the audit to specific IAM principals — by name pattern, path prefix, or tag — rather than auditing the entire account every time. This allows targeted cleanup of a single team's resources without sifting through irrelevant findings.

**Why this priority**: Filtering is essential for large accounts but is an enhancement over the core audit capability. The tool is fully usable without it for small-to-medium accounts.

**Independent Test**: Run the tool with various filter flags and verify the output includes only matching entities and excludes everything else.

**Acceptance Scenarios**:

1. **Given** an account with roles prefixed `/team-alpha/` and `/team-beta/`, **When** the user runs `iam-audit dormancy --path-prefix /team-alpha/`, **Then** only roles under `/team-alpha/` appear in the results.
2. **Given** an account with tagged roles (`team=platform`), **When** the user runs `iam-audit permissions --tag team=platform`, **Then** only roles with that tag are evaluated.
3. **Given** a name pattern filter `--name "ci-*"`, **When** the audit runs, **Then** only roles and users whose names match the glob pattern are included.

---

### Edge Cases

- What happens when AWS rate limits are hit during large-account scans? The tool must implement exponential backoff and surface a clear progress indicator rather than failing silently.
- What happens when a role has zero policies attached? It should be reported as a finding (role with no purpose) rather than silently skipped.
- What happens when the caller's own IAM permissions are insufficient to read IAM data? The tool must detect this early and report which specific permissions are missing.
- How does the tool handle service-linked roles that cannot be deleted by the user? They must be clearly labeled and excluded from "recommend delete" actions.
- What happens if Access Advisor data is incomplete or unavailable for a region? The tool must note the data gap in the report rather than producing false negatives.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST enumerate all IAM roles and IAM users in the target AWS account.
- **FR-002**: The system MUST determine last-activity date for each role (last assumed) and each user (last console login and last API call) using AWS-provided access data.
- **FR-003**: The system MUST accept a configurable dormancy threshold in days (default: 90 days).
- **FR-004**: The system MUST flag entities whose last activity exceeds the dormancy threshold, or that have never been used.
- **FR-005**: The system MUST analyze all inline policies, attached managed policies, and group policies (for users) on each principal.
- **FR-006**: The system MUST identify overly permissive policy statements: wildcard actions, wildcard resources, and overly broad action patterns (e.g., full-service wildcards like `s3:*`).
- **FR-007**: The system MUST assign a severity level (Critical, High, Medium, Low) to each permission finding based on the breadth of access granted.
- **FR-008**: The system MUST provide a human-readable recommendation for each finding (e.g., "Delete this unused role" or "Restrict s3:* to specific actions").
- **FR-009**: The system MUST support output in both human-readable (text/table) and machine-readable (JSON) formats.
- **FR-010**: The system MUST support filtering by IAM path prefix, name pattern (glob), and resource tags.
- **FR-011**: The system MUST correctly identify and label AWS service-linked roles, excluding them from deletion recommendations.
- **FR-012**: The system MUST handle AWS API rate limiting with automatic retry and exponential backoff.
- **FR-013**: The system MUST validate that the caller has sufficient IAM permissions before starting the audit and report any missing permissions with specific permission names.
- **FR-014**: The system MUST paginate through AWS API responses and MUST NOT load unbounded datasets into memory.
- **FR-015**: The system MUST exit with distinct exit codes: 0 for clean audit (no findings), 1 for findings present, 2 for tool error.

### Key Entities

- **IAM Role**: An AWS IAM role with its ARN, name, path, creation date, last-assumed date, attached policies, inline policies, tags, and whether it is a service-linked role.
- **IAM User**: An AWS IAM user with their ARN, name, path, creation date, last console login, last API key usage date, attached policies, inline policies, group memberships, and tags.
- **Policy Statement**: A single statement within an IAM policy document, with its Effect, Action(s), Resource(s), and Condition(s).
- **Audit Finding**: A discovered issue tied to a specific principal and category (dormancy or permission), with severity, description, and recommended action.
- **Audit Report**: An aggregation of all findings for a single audit run, with metadata (account ID, timestamp, filters applied, summary counts).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can identify all dormant IAM entities in an account within a single command invocation, with zero manual cross-referencing of AWS console screens.
- **SC-002**: The tool detects 100% of wildcard-action and wildcard-resource policy statements in the audited scope.
- **SC-003**: Audit of an account with up to 500 roles and 100 users completes within 5 minutes under normal AWS API conditions.
- **SC-004**: Every finding in the report includes a severity rating and an actionable recommendation that a user can act on without additional research.
- **SC-005**: The JSON output conforms to a documented schema and is parseable by standard JSON tooling without transformation.
- **SC-006**: Users who apply the tool's recommendations reduce the count of overly permissive policy statements by at least 50% in a follow-up audit.
- **SC-007**: The tool produces zero false positives for service-linked roles (never recommends deleting them).
- **SC-008**: 90% of first-time users can complete an audit and interpret the results within 10 minutes, guided only by `--help` output and the report itself.

### Assumptions

- The tool operates in read-only mode; it audits and recommends but does not modify or delete any AWS resources.
- AWS credentials are provided via the standard credential chain (environment variables, shared credentials file, instance profile, SSO). The tool does not manage or store credentials.
- The tool targets a single AWS account per invocation. Multi-account support (AWS Organizations) is out of scope for this feature but the architecture should not preclude it.
- Access Advisor / last-accessed data is available in the target account's region. The tool relies on AWS-provided activity data and does not maintain its own activity log.
- The user is expected to have IAM read permissions (`iam:Get*`, `iam:List*`, `iam:GenerateServiceLastAccessedDetails`, `iam:GetServiceLastAccessedDetails`). The tool does not require write permissions.
