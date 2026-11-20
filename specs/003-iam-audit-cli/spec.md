# Feature Specification: IAM Audit CLI

**Feature Branch**: `003-iam-audit-cli`
**Created**: 2026-03-07
**Status**: Draft
**Input**: User description: "Build a CLI tool to curb IAM over-provisioning. It audits AWS environments, scanning IAM roles and IAM users for redundant entities or bloated policies. It provides clear insights to prune dormant objects and trim permissions, enforcing a 'Least Privilege' posture. Integration with Prometheus enables tracking finding trends over time via custom metrics."

## Clarifications

### Session 2026-03-07

- Q: Should the tool identify specific unused permissions within policies, not just overly broad patterns? → A: Yes. The tool must compare granted actions against AWS Service Last Accessed data and recommend removing specific actions/services that were never used. This is distinct from the static wildcard/breadth analysis in US2.
- Q: Should the tool scan AWS-created roles and policies by default? → A: No. By default, AWS service-linked roles (path `/aws-service-role/`), AWS service roles (path `/service-role/`), and AWS-managed policies (ARN prefix `arn:aws:iam::aws:policy/`) are excluded. A `--include-aws-managed` flag enables their inclusion.

### Session 2026-03-08

- Q: When a policy grants wildcard actions (e.g., `s3:*`) and Access Advisor shows only specific actions were used, should US5 expand the wildcard and recommend a specific replacement action set, or leave wildcards to US2 only? → A: US5 expands wildcards and recommends a specific used-action set as replacement, providing actionable least-privilege guidance.
- Q: Should the `--days` flag also limit the Service Last Accessed lookback window for unused-permissions analysis, or should US5 use full AWS history? → A: Reuse the `--days` flag for both dormancy and unused-permissions lookback, keeping a single threshold concept across the tool.
- Q: How should the tool manage concurrency for the async `GenerateServiceLastAccessedDetails` API? → A: Default concurrency limit (e.g., 10) with a `--concurrency` flag to override for power users with higher API limits.
- Q: Should unused-permission findings include a ready-to-use replacement policy JSON or just list actions to remove/keep? → A: List specific actions/services to remove and the minimal keep-set. No replacement policy JSON — avoids fragility with Conditions, Resources, and multi-statement interactions.
- Q: Where should the tool source the canonical list of actions per AWS service for wildcard expansion? → A: Bundle a static actions map (JSON/dict) versioned with the tool, updated periodically. No runtime dependency on external services.

### Session 2026-03-10

- Q: How should the user specify the HTML output file path? → A: A new `--output <path>` flag is required when `--format html` is used (e.g., `--format html --output report.html`).
- Q: Should `--format html` be available on all subcommands or only `report`? → A: All subcommands (`dormancy`, `permissions`, `report`) support `--format html --output <path>`, consistent with how `--format text` and `--format json` already work.
- Q: Should the HTML report include interactive JavaScript elements or be static HTML+CSS only? → A: Static HTML+CSS only — no JavaScript. Clean, portable, works in all browsers and print/PDF export.
- Q: Should the HTML report include a visual summary dashboard section at the top? → A: Yes. A summary header with severity-colored badges and category breakdown counts at the top, followed by detailed finding tables.

### Session 2026-03-11

- Q: The Prometheus/metrics integration (US5, FR-016–FR-020, `--pushgateway-url`) — keep, deprecate, or remove? → A: Remove entirely. The Prometheus integration is not needed. All related requirements, CLI flags, exit codes, edge cases, and the `prometheus-client` dependency are deleted.
- Q: How should the HTML report collapse/expand feature be implemented — native `<details>`/`<summary>` or JavaScript toggle? → A: Use native HTML `<details>`/`<summary>` elements. No JavaScript. Fully supported in all modern browsers, compatible with print/PDF.
- Q: What should the default state of category sections be when the HTML report opens? → A: All categories collapsed by default. Users expand only the categories they want to inspect. The summary header with badges remains always visible.
- Q: How should the tool handle explicit `Deny` statements when analyzing overly permissive `Allow` statements? → A: Note the presence of Deny statements in findings as context (e.g., "Note: principal also has Deny statements that may restrict effective access") but do not change the severity rating. Severity reflects the Allow statement's grant breadth. Full effective-permission evaluation with Deny interaction is deferred to a future version.
- Q: What should happen when `--output` targets a file that already exists? → A: Silently overwrite the existing file, following standard POSIX CLI behavior.
- Q: How should findings be sorted within each category in report output? → A: Sort by severity descending (Critical → Low), then alphabetically by principal name within the same severity. This applies to all output formats (text, JSON, HTML).

### Session 2026-03-11 (2)

- Q: Should the top-level `--help` show shared flags and include usage examples? → A: Yes. The top-level `iam-audit --help` must display all shared flags (not just subcommand names) and include a usage examples epilog. Subcommand-level help must also include examples. This supports SC-008 (first-time users guided by `--help` alone).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Audit IAM Roles and Users for Dormancy (Priority: P1)

A security engineer wants to quickly identify IAM roles and users that have not been used within a configurable time window. They run the CLI tool against their AWS account and receive a clear report listing every dormant entity — those with no login activity, no API calls, and no assumption events — along with the last-activity date and a recommended action (delete or flag for review).

**Why this priority**: Dormant principals are the lowest-hanging fruit for reducing attack surface. Removing unused entities has the highest impact-to-risk ratio because they carry zero operational dependency yet remain exploitable.

**Independent Test**: Run the tool against an AWS account containing a mix of active and dormant roles/users. Verify the output correctly categorizes each entity, every dormant entity includes a last-activity timestamp and a recommended action, and active entities are excluded from findings.

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

An engineering manager wants a single, comprehensive audit report that combines dormancy findings and permission findings into one document. The report must be available in human-readable (table/text), machine-readable (JSON), and elegantly designed HTML formats so it can be reviewed manually, fed into automation pipelines, or shared as a standalone file.

**Why this priority**: Consolidation and export are usability features that amplify the value of P1 and P2. Without them the tool is still functional, but less convenient for organizational workflows and CI/CD integration.

**Independent Test**: Run a full audit and request output in both formats. Verify the JSON output is valid, parseable, and contains the same findings as the human-readable output. Verify the human-readable output is well-formatted and easy to scan.

**Acceptance Scenarios**:

1. **Given** an AWS account with both dormant entities and overly permissive policies, **When** the user runs `iam-audit report --format text`, **Then** the output is a well-structured, human-readable table grouping findings by category (dormancy, permissions) with summary counts.
2. **Given** the same account, **When** the user runs `iam-audit report --format json`, **Then** the output is valid JSON conforming to a documented schema, containing all findings with their metadata.
3. **Given** an account with zero findings, **When** the user runs `iam-audit report`, **Then** the output clearly states "No issues found" rather than producing an empty or confusing output.
4. **Given** a large account (500+ roles), **When** the user runs `iam-audit report`, **Then** the report completes without loading all data into memory at once and the output includes a summary section at the top with total counts.
5. **Given** an AWS account with findings, **When** the user runs `iam-audit report --format html --output report.html`, **Then** the tool writes a self-contained HTML file to `report.html` that is elegantly styled, groups findings by category with severity color-coding, and includes a summary header with total counts.
6. **Given** `--format html` is used without `--output`, **When** the audit runs, **Then** the tool exits with an error message explaining that `--output` is required for HTML format.
7. **Given** an HTML report with multiple finding categories, **When** the user opens the report, **Then** all category sections are collapsed by default using `<details>`/`<summary>` elements, and the user can expand any category to view its findings while the summary header remains always visible.

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

### User Story 5 - Identify Unused Permissions via Access Advisor Data (Priority: P2)

A security engineer wants to go beyond detecting wildcard policies and identify the specific permissions each principal was granted but never actually used. The tool compares each principal's granted actions against AWS Service Last Accessed data and recommends removing the unused services or actions. This enables precise, surgical permission trimming rather than broad heuristic warnings.

**Why this priority**: This is the core of "Least Privilege" enforcement. Static wildcard detection (US2) catches the obvious cases, but most over-provisioning consists of tightly-scoped policies that grant more services or actions than the principal actually uses. Without usage-based analysis, the tool cannot recommend *what to remove*, only *what looks broad*.

**Independent Test**: Run the tool against an account with principals that have policies granting multiple services but only use a subset. Verify the tool identifies the unused services/actions and recommends specific removals.

**Acceptance Scenarios**:

1. **Given** a role granted `s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject` that has only ever used `s3:GetObject` in the last 90 days, **When** the user runs `iam-audit permissions`, **Then** the tool reports a finding recommending removal of `s3:PutObject` and `s3:DeleteObject` with the last-accessed date for each.
2. **Given** a user with policies granting access to 10 AWS services but Service Last Accessed data shows only 3 were ever used, **When** the audit runs, **Then** the tool reports findings for each of the 7 unused services with a recommendation to remove access.
3. **Given** a service where AWS provides only service-level (not action-level) granularity, **When** the audit runs, **Then** the finding states the unused service and notes that action-level detail is unavailable, recommending service-level removal.
4. **Given** a newly created role (less than 24 hours old) with no access advisor data yet, **When** the audit runs, **Then** the tool notes a data gap for that principal rather than falsely reporting all permissions as unused.
5. **Given** the `--include-aws-managed` flag is NOT set, **When** the audit runs, **Then** AWS-managed policies attached to the principal are excluded from the unused permissions analysis.
6. **Given** a role with a policy granting `s3:*` and Access Advisor shows only `s3:GetObject` and `s3:ListBucket` were used, **When** the audit runs, **Then** the tool expands the wildcard, reports the unused actions, and recommends replacing `s3:*` with the specific used actions (`s3:GetObject`, `s3:ListBucket`).

---

### Edge Cases

- What happens when AWS rate limits are hit during large-account scans? The tool must implement automatic retry with backoff and surface a clear progress indicator rather than failing silently.
- What happens when a role has zero policies attached? It MUST be reported as a Low severity finding per FR-021 (role with no purpose) rather than silently skipped.
- What happens when the caller's own IAM permissions are insufficient to read IAM data? The tool must detect this early and report which specific permissions are missing.
- How does the tool handle service-linked roles that cannot be deleted by the user? They must be clearly labeled and excluded from "recommend delete" actions.
- What happens if activity data is incomplete or unavailable for a region? The tool must note the data gap in the report rather than producing false negatives.
- What happens when `GenerateServiceLastAccessedDetails` times out or returns incomplete data for a principal? The tool must record a data gap for that principal and skip the unused-permissions analysis for it, rather than producing false positives.
- What happens when AWS provides only service-level access data (no action-level granularity) for a service? The tool must report at the service level and note the limitation in the recommendation.
- What happens for principals where all granted permissions are actually used? The tool should produce no finding for that principal's unused-permissions category — confirming least privilege is already achieved.
- What happens when `--include-aws-managed` is used? AWS service-linked roles, service roles, and AWS-managed policies are included in all analysis. The tool should clearly label AWS-managed entities in the output so users can distinguish them from customer-created ones.
- What happens when a principal has both overly permissive Allow statements and explicit Deny statements? The tool notes the Deny presence in the finding but does not reduce severity or attempt effective-permission evaluation. This avoids false confidence from incomplete Deny analysis.
- What happens when the bundled IAM actions map does not contain a newly released AWS service or action? The tool must log a warning that the action could not be resolved for wildcard expansion and skip that action in the unused-permissions recommendation rather than silently omitting it.
- What happens when `--output` points to a path whose parent directory does not exist? The tool must exit with a clear error indicating the directory does not exist, rather than crashing with an OS-level traceback.
- What happens when `--output` targets a file that already exists? The tool silently overwrites it, following standard POSIX CLI conventions. No confirmation prompt or `--force` flag is needed.
- What happens when the HTML report has zero findings? The summary header must show all-zero counts and the body must display a clear "No issues found" message, not an empty page.
- What happens when printing the HTML report? Browsers typically expand all `<details>` elements when printing, ensuring all findings are visible in the printed/PDF version. The CSS should include a `@media print` rule that forces `<details>` elements to the open state.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST enumerate all IAM roles and IAM users in the target AWS account.
- **FR-002**: The system MUST determine last-activity date for each role (last assumed) and each user (last console login and last API call) using the cloud provider's access data.
- **FR-003**: The system MUST accept a configurable dormancy threshold in days (default: 90 days).
- **FR-004**: The system MUST flag entities whose last activity exceeds the dormancy threshold, or that have never been used.
- **FR-005**: The system MUST analyze all inline policies, attached managed policies, and group policies (for users) on each principal.
- **FR-006**: The system MUST identify overly permissive policy statements: wildcard actions, wildcard resources, and overly broad action patterns (e.g., full-service wildcards like `s3:*`).
- **FR-007**: The system MUST assign a severity level (Critical, High, Medium, Low) to each permission finding based on the breadth of access granted. Severity is determined solely by the Allow statement's grant breadth; explicit Deny statements do not reduce severity.
- **FR-036**: When a principal has explicit `Deny` statements in its policies, the system MUST note their presence in the finding context (e.g., "Note: principal also has Deny statements that may restrict effective access"). The tool MUST NOT attempt to evaluate effective permissions through Allow/Deny interaction in the current version.
- **FR-008**: The system MUST provide a human-readable recommendation for each finding (e.g., "Delete this unused role" or "Restrict s3:* to specific actions"). For unused-permissions findings, recommendations MUST list the specific actions/services to remove and the minimal set of actions to keep, without generating replacement policy JSON.
- **FR-009**: The system MUST support output in human-readable (text/table), machine-readable (JSON), and HTML formats via the `--format` flag (`text`, `json`, `html`).
- **FR-037**: The system MUST sort findings by severity descending (Critical → High → Medium → Low), then alphabetically by principal name within the same severity level. This deterministic ordering MUST apply to all output formats (text, JSON, HTML). In grouped formats (text, HTML), findings within each category section follow this order; in flat formats (JSON), all findings are sorted globally.
- **FR-031**: The system MUST accept an optional `--output <path>` flag on all subcommands (`dormancy`, `permissions`, `report`). When `--output` is provided, the report content MUST be written to the specified file path instead of stdout, regardless of format (`text`, `json`, or `html`). When `--format html` is specified, `--output` is **required** — the tool MUST exit with an error if `--output` is omitted when format is `html` (HTML output is not written to stdout).
- **FR-032**: The HTML report MUST be a single self-contained file with all CSS inlined (no external stylesheets or fonts). The report MUST use only static HTML+CSS with no JavaScript. Native HTML elements such as `<details>`/`<summary>` for interactive collapse/expand behavior are permitted. The report MUST ensure portability across all modern browsers and compatibility with print/PDF export.
- **FR-033**: The HTML report MUST include a summary header section at the top displaying: total finding count, finding counts per category (dormancy, permission, unused_permission), and finding counts per severity rendered as color-coded badges (Critical=red, High=orange, Medium=yellow, Low=blue). The summary MUST be followed by detailed finding tables grouped by category.
- **FR-034**: The HTML report MUST render findings in styled tables with columns for principal name/ARN, severity (color-coded), title, and recommendation. Each category section MUST have a visible heading.
- **FR-035**: The HTML report MUST wrap each finding category section in a `<details>`/`<summary>` element. All category sections MUST default to the collapsed state when the report is first opened. The `<summary>` line MUST display the category name and finding count so users can identify relevant sections without expanding them. The summary header with severity badges MUST remain outside `<details>` elements and be always visible. The report MUST include a `@media print` CSS rule that forces all `<details>` elements open so printed/PDF output includes all findings.
- **FR-038**: The CLI `--help` output MUST display all shared flags (`--days`, `--path-prefix`, `--name`, `--tag`, `--include-aws-managed`, `--format`, `--output`, `--concurrency`) at the top level in addition to per-subcommand help. Both the top-level and each subcommand's `--help` MUST include a usage examples section showing common invocations. Help descriptions MUST include default values where applicable.
- **FR-010**: The system MUST support filtering by IAM path prefix, name pattern (glob), and resource tags.
- **FR-011**: The system MUST correctly identify and label AWS service-linked roles, excluding them from deletion recommendations.
- **FR-012**: The system MUST handle cloud provider rate limiting with automatic retry and exponential backoff.
- **FR-013**: The system MUST validate that the caller has sufficient permissions before starting the audit and report any missing permissions with specific permission names.
- **FR-014**: The system MUST paginate through cloud provider responses and MUST NOT load unbounded datasets into memory.
- **FR-015**: The system MUST exit with distinct exit codes: 0 for clean audit (no findings), 1 for findings present, 2 for tool error.
- **FR-021**: The system MUST flag IAM roles and users with zero attached or inline policies as a Low severity finding with the recommendation "Review and attach a policy or delete this entity."
- **FR-022**: The system MUST exclude AWS service-linked roles (path `/aws-service-role/`), AWS service roles (path `/service-role/`), and AWS-managed policies (ARN prefix `arn:aws:iam::aws:policy/`) from all analysis by default.
- **FR-023**: The system MUST provide a `--include-aws-managed` flag that, when set, includes AWS-created roles and AWS-managed policies in the analysis.
- **FR-024**: The system MUST call `GenerateServiceLastAccessedDetails` and `GetServiceLastAccessedDetails` for each principal in scope to retrieve service and action-level usage data.
- **FR-025**: The system MUST compare each principal's granted actions/services against Service Last Accessed data and generate findings for permissions that were granted but never used within the `--days` threshold window (same value used for dormancy analysis, default 90 days).
- **FR-026**: When AWS provides only service-level granularity (no action-level data), the system MUST report the unused service and note the limitation in the recommendation.
- **FR-027**: The system MUST record a data gap when Service Last Accessed data is unavailable or incomplete for a principal (e.g., newly created entities, API timeout), rather than producing false positives.
- **FR-028**: When the unused-permissions analysis (US5) encounters wildcard actions (e.g., `s3:*`), the system MUST expand the wildcard by enumerating the known actions for that service, compare each against Service Last Accessed data, and recommend a specific replacement action set containing only the actions actually used.
- **FR-029**: The system MUST limit concurrent `GenerateServiceLastAccessedDetails` API jobs to a default of 10 and MUST accept a `--concurrency` flag to override this limit.
- **FR-030**: The system MUST bundle a static IAM actions map (JSON or dictionary) that enumerates known actions per AWS service, used for wildcard expansion in unused-permissions analysis. This map MUST be versioned with the tool and updated periodically.

### Key Entities

- **IAM Role**: An AWS IAM role with its ARN, name, path, creation date, last-assumed date, attached policies, inline policies, tags, and whether it is a service-linked role.
- **IAM User**: An AWS IAM user with their ARN, name, path, creation date, last console login, last API key usage date, attached policies, inline policies, group memberships, and tags.
- **Policy Statement**: A single statement within an IAM policy document, with its Effect, Action(s), Resource(s), and Condition(s).
- **Audit Finding**: A discovered issue tied to a specific principal and category (dormancy, permission, or unused_permissions), with severity, description, and recommended action.
- **Service Last Accessed Record**: Per-principal data from AWS Access Advisor showing which services (and for supported services, which actions) were actually used, with the last-accessed timestamp.
- **Audit Report**: An aggregation of all findings for a single audit run, with metadata (account ID, timestamp, filters applied, summary counts).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can identify all dormant IAM entities in an account within a single command invocation, with zero manual cross-referencing of console screens.
- **SC-002**: The tool detects 100% of wildcard-action and wildcard-resource policy statements in the audited scope.
- **SC-003**: Audit of an account with up to 500 roles and 100 users completes within 5 minutes under normal conditions.
- **SC-004**: Every finding in the report includes a severity rating and an actionable recommendation that a user can act on without additional research.
- **SC-005**: The JSON output conforms to a documented schema and is parseable by standard JSON tooling without transformation.
- **SC-006**: Users who apply the tool's recommendations reduce the count of overly permissive policy statements by at least 50% in a follow-up audit.
- **SC-007**: The tool produces zero false positives for service-linked roles (never recommends deleting them).
- **SC-008**: 90% of first-time users can complete an audit and interpret the results within 10 minutes, guided only by `--help` output and the report itself.
- **SC-009**: The tool identifies unused services and actions for at least 90% of principals where Service Last Accessed data is available, enabling surgical permission trimming.
- **SC-010**: By default, the tool produces zero findings for AWS service-linked roles, AWS service roles, and AWS-managed policy content, avoiding noise from entities the user cannot modify.
- **SC-011**: The HTML report opens correctly in Chrome, Firefox, and Safari without external network requests, and contains identical finding data to the equivalent JSON output for the same audit run.

### Assumptions

- The tool operates in read-only mode; it audits and recommends but does not modify or delete any AWS resources.
- AWS credentials are provided via the standard credential chain (environment variables, shared credentials file, instance profile, SSO). The tool does not manage or store credentials.
- The tool targets a single AWS account per invocation. Multi-account support (AWS Organizations) is out of scope for this feature but the architecture should not preclude it.
- Activity data (last-accessed, last-assumed) is available in the target account's region. The tool relies on cloud-provider-supplied activity data and does not maintain its own activity log.
- The user is expected to have IAM read permissions (`iam:Get*`, `iam:List*`, `iam:GenerateServiceLastAccessedDetails`, `iam:GetServiceLastAccessedDetails`). The tool does not require write permissions.
- AWS provides action-level Service Last Accessed granularity for a subset of services (e.g., S3, EC2, IAM, Lambda, KMS, STS). For all other services, only service-level data is available. The tool adapts its recommendations accordingly.
- `GenerateServiceLastAccessedDetails` is an asynchronous API — the tool must call it, then poll `GetServiceLastAccessedDetails` until the job completes. This adds latency proportional to the number of principals.
- By default, AWS-created roles (service-linked and service roles) and AWS-managed policies are excluded from analysis. The `--include-aws-managed` flag overrides this behavior.
