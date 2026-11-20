# Tasks: IAM Audit CLI

**Input**: Design documents from `/specs/003-iam-audit-cli/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: Included — Constitution III requires ≥80% line coverage.

**Organization**: Tasks grouped by user story (US1–US5) for independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story (US1–US5)
- Exact file paths included

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [x] T001 Create project structure: `src/iam_audit/` with `__init__.py`, `__main__.py`, `collectors/`, `analyzers/`, `reporters/`, `data/`; `tests/unit/`, `tests/integration/`
- [x] T002 Initialize Python project with `pyproject.toml`: entry point `iam-audit`, dependency `boto3`, dev deps `pytest`, `ruff`, `pip-audit`
- [x] T003 [P] Create `requirements.txt` (boto3) and `requirements-dev.txt` (pytest, ruff, pip-audit)
- [x] T004 [P] Configure ruff linting in `pyproject.toml` (line-length 120, Python 3.12 target)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core models, AWS client, CLI skeleton, and output formatters that ALL user stories depend on

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [x] T005 Implement all data model dataclasses in `src/iam_audit/models.py`: Principal, IAMRole, IAMUser, AttachedPolicy, InlinePolicy, PolicyDocument, PolicyStatement, ServiceLastAccessedRecord, ActionLastAccessed, Finding (with `has_deny_statements` in permission metadata), AuditReport, FiltersApplied, DataGap, ReportSummary, FindingCategory enum, Severity enum with sort ordering
- [x] T006 Implement AWS client factory in `src/iam_audit/aws_client.py`: `create_session()`, `create_iam_client()` with botocore standard retry (10 attempts), `get_account_id()`
- [x] T007 Implement CLI skeleton in `src/iam_audit/cli.py`: argparse with `dormancy`, `permissions`, `report` subcommands. Shared flags: `--days`, `--path-prefix`, `--name`, `--tag`, `--include-aws-managed`, `--format {text,json,html}`, `--output`, `--concurrency`, `--version`. Implement `_validate_output_args()` (html requires --output, parent dir exists), `_write_output_file()` (silent overwrite per R11), `_output_report()` routing. Entry point in `src/iam_audit/__main__.py`
- [x] T008 [P] Implement text reporter in `src/iam_audit/reporters/text.py`: `format_text_report(report: AuditReport) -> str` with severity-grouped tables, summary header, findings sorted per FR-037 (severity desc, then principal name asc)
- [x] T009 [P] Implement JSON reporter in `src/iam_audit/reporters/json_reporter.py`: `format_json_report(report: AuditReport) -> str` with schema_version "1.0.0", findings sorted per FR-037, metadata by category including `has_deny_statements`
- [x] T010 [P] Unit tests for models — sort ordering and Finding equality verified via JSON reporter and HTML reporter tests
- [x] T011 [P] Unit tests for AWS client in `tests/unit/test_aws_client.py`: session creation, client factory with retry config, `get_account_id()` with mocked session

**Checkpoint**: Foundation ready — CLI accepts all flags, models are defined, text/JSON reporters work, sort order implemented

---

## Phase 3: User Story 1 — Audit IAM Roles and Users for Dormancy (Priority: P1) 🎯 MVP

**Goal**: Identify all IAM roles and users inactive beyond a configurable threshold, with last-activity dates and recommended actions.

**Independent Test**: Run `iam-audit dormancy --days 90` against a stubbed AWS account and verify correct dormancy classification, boundary conditions, and exit codes.

### Implementation for User Story 1

- [x] T012 [P] [US1] Implement role collector in `src/iam_audit/collectors/roles.py`: paginated `list_roles()` → `get_role()` for accurate `RoleLastUsed`, build IAMRole dataclass. Exclude `/aws-service-role/` and `/service-role/` paths by default, include with `--include-aws-managed`. Fetch tags via `list_role_tags()`
- [x] T013 [P] [US1] Implement user collector in `src/iam_audit/collectors/users.py`: paginated `list_users()`, `list_access_keys()` + `get_access_key_last_used()` for each user, `password_last_used` from user metadata, `list_groups_for_user()`. Build IAMUser dataclass with `last_activity = max(password_last_used, access_key_last_used)`
- [x] T014 [US1] Implement dormancy analyzer in `src/iam_audit/analyzers/dormancy.py`: compare `last_activity` against `--days` threshold, flag entities exceeding threshold or never used. Assign severity Low. Generate recommendation ("Delete this unused role/user"). Handle never-used entities with "never used" indicator. Exclude service-linked roles from deletion recommendations (FR-011). Flag zero-policy entities as Low (FR-021)
- [x] T015 [US1] Wire dormancy subcommand in `src/iam_audit/cli.py`: `_run_dormancy()` calls collectors → analyzer → reporter, handles `_validate_output_args()`, routes to `_output_report()`. Exit code 0 (no findings), 1 (findings), 2 (error)
- [x] T016 [P] [US1] Unit tests for role collector in `tests/unit/test_collectors.py`: stub `list_roles`, `get_role`, `list_role_tags`. Test pagination, service-linked exclusion, `--include-aws-managed` inclusion, accurate `RoleLastUsed` from `get_role`
- [x] T017 [P] [US1] Unit tests for user collector in `tests/unit/test_collectors.py`: stub `list_users`, `list_access_keys`, `get_access_key_last_used`. Test `last_activity` derivation, never-logged-in users
- [x] T018 [P] [US1] Unit tests for dormancy analyzer in `tests/unit/test_dormancy_analyzer.py`: threshold boundary (89 vs 90 days), never-used entities, service-linked role exclusion
- [x] T019 [US1] Integration test for dormancy CLI in `tests/integration/test_cli.py`: run `dormancy` subcommand with stubbed AWS, verify text output, JSON output, exit codes 0/1/2, `--output` file write

**Checkpoint**: `iam-audit dormancy` fully functional — MVP complete

---

## Phase 4: User Story 2 — Identify Overly Permissive Policies (Priority: P2)

**Goal**: Detect wildcard actions, wildcard resources, and overly broad patterns in IAM policies with severity ratings, tightening suggestions, and Deny statement awareness.

**Independent Test**: Run `iam-audit permissions` against stubbed policies with known wildcards and verify correct severity classification, Deny context notes, and sorted output.

### Implementation for User Story 2

- [x] T020 [P] [US2] Implement policy collector in `src/iam_audit/collectors/policies.py`: fetch inline policies (`list_role_policies` + `get_role_policy`), attached managed policies (`list_attached_role_policies` + `get_policy` + `get_policy_version`), group policies for users. Parse policy documents into PolicyDocument/PolicyStatement dataclasses. Normalize single-string actions/resources to lists
- [x] T021 [US2] Implement permissions analyzer in `src/iam_audit/analyzers/permissions.py`: classify severity per R6 heuristic (Critical: `Action:* + Resource:*`, High: `service:*` or `Resource:*`, Medium: broad patterns >5 actions, Low: minor). Detect Deny statements (FR-036): scan all PolicyStatements for `effect=="Deny"`, set `has_deny_statements=True` in metadata, append context note to description. Generate recommendations per FR-008
- [x] T022 [US2] Wire permissions subcommand in `src/iam_audit/cli.py`: `_run_permissions()` calls role/user collectors → policy collector → permissions analyzer → reporter. Sort findings per FR-037
- [x] T023 [P] [US2] Unit tests for policy collector in `tests/unit/test_collectors.py`: stub inline/attached/group policy APIs, test policy document parsing, action/resource normalization
- [x] T024 [P] [US2] Unit tests for permissions analyzer in `tests/unit/test_permissions_analyzer.py`: all 4 severity levels, Deny detection and context note, tightly-scoped policy not flagged, mixed permissive+tight policies on same principal

**Checkpoint**: `iam-audit permissions` identifies overly permissive policies with severity and Deny awareness

---

## Phase 5: User Story 5 — Identify Unused Permissions via Access Advisor (Priority: P2)

**Goal**: Compare granted actions/services against Service Last Accessed data to identify specific unused permissions, including wildcard expansion.

**Independent Test**: Run permissions audit against stubbed Access Advisor data showing partial service usage and verify unused services/actions are correctly identified with recommendations.

**Depends on**: Phase 4 (policy collector, permissions analyzer infrastructure)

### Implementation for User Story 5

- [x] T025 [P] [US5] Implement Access Advisor collector in `src/iam_audit/collectors/access_advisor.py`: `GenerateServiceLastAccessedDetails` with `Granularity="ACTION_LEVEL"`, exponential backoff polling per R2 (1s initial, 2x multiplier, 30s max, 10min timeout), `ThreadPoolExecutor(max_workers=concurrency)`. Record DataGap on failure/timeout. Build ServiceLastAccessedRecord dataclasses
- [x] T026 [P] [US5] Create IAM actions map in `src/iam_audit/data/iam_actions.json`: static `{"service_prefix": ["Action1", ...]}` per R4. Include major services (s3, ec2, iam, lambda, kms, sts, dynamodb, rds, ecs, eks, cloudformation). Log warning for unknown service prefixes
- [x] T027 [US5] Implement unused permissions analyzer in `src/iam_audit/analyzers/unused.py`: compare granted actions per service against Access Advisor data within `--days` window. For wildcard actions (e.g., `s3:*`): expand using iam_actions.json, compare each against tracked actions, recommend replacement set (FR-028). Handle service-level-only granularity (FR-026). Severity per R6: IAM/KMS/STS unused=High, most services=Medium, read-only=Low
- [x] T028 [US5] Integrate unused analysis into permissions subcommand in `src/iam_audit/cli.py`: after policy analysis, run Access Advisor collection → unused analyzer. Merge findings from both analyzers, sort combined list per FR-037
- [x] T029 [P] [US5] Unit tests for Access Advisor collector in `tests/unit/test_collectors.py`: stub Generate/Get APIs, test polling lifecycle (IN_PROGRESS → COMPLETED), timeout handling (DataGap), concurrent job execution
- [x] T030 [P] [US5] Unit tests for unused permissions analyzer in `tests/unit/test_unused_analyzer.py`: unused service detection, unused action detection, wildcard expansion, service-level-only granularity, data gap recording, newly created principal handling, `--days` window filtering

**Checkpoint**: `iam-audit permissions` now identifies both overly permissive policies AND unused permissions

---

## Phase 6: User Story 3 — Generate Consolidated Audit Report (Priority: P3)

**Goal**: Combine dormancy and permissions findings into one report with text, JSON, and HTML output including collapsible category sections.

**Independent Test**: Run `iam-audit report --format html --output report.html` and verify the HTML file has summary badges, collapsed `<details>` sections, severity-sorted findings, and correct `@media print` rule.

**Depends on**: Phase 3 (dormancy), Phase 4+5 (permissions)

### Implementation for User Story 3

- [x] T031 [US3] Implement HTML reporter in `src/iam_audit/reporters/html.py`: `format_html_report(report: AuditReport) -> str` using `string.Template` per R8. Inline CSS with severity colors (Critical=#dc3545, High=#fd7e14, Medium=#ffc107, Low=#0d6efd). Summary header with badges (always visible, outside `<details>`). Each category section wrapped in `<details>`/`<summary>` (FR-035): collapsed by default (no `open` attribute), `<summary>` shows category name + count. `@media print` rule forces `<details>` content visible. All dynamic content through `html.escape()`. Zero findings: show "No issues found" message, no `<details>` sections
- [x] T032 [US3] Implement report subcommand in `src/iam_audit/cli.py`: `_run_report()` runs both dormancy and permissions analysis, merges findings into single AuditReport, sorts all findings per FR-037, routes to selected reporter
- [x] T033 [P] [US3] Unit tests for HTML reporter in `tests/unit/test_html_reporter.py`: HTML structure validity, summary badges present, `<details>`/`<summary>` elements for each category (collapsed by default), severity color-coding, `html.escape()` XSS prevention, `@media print` rule present, zero findings "No issues found", finding count in `<summary>`, data equivalence with JSON output (SC-011)
- [x] T034 [P] [US3] Unit tests for text reporter in `tests/unit/test_text_reporter.py`: summary header, category grouping, severity-sorted tables, zero findings message
- [x] T035 [P] [US3] Unit tests for JSON reporter in `tests/unit/test_json_reporter.py`: valid JSON, schema_version present, severity-sorted findings, `has_deny_statements` in permission metadata
- [x] T036 [US3] Integration tests for report subcommand and --output in `tests/integration/test_cli.py`: `report` subcommand produces all 3 formats, `--output` writes file for text/json/html, `--format html` without `--output` exits code 2, non-existent parent dir exits code 2, existing file silently overwritten

**Checkpoint**: `iam-audit report` produces consolidated output in text, JSON, and HTML with collapsible category sections

---

## Phase 7: User Story 4 — Scope Audit to Specific Resources (Priority: P4)

**Goal**: Filter audit scope by IAM path prefix, name pattern (glob), or resource tags.

**Independent Test**: Run `iam-audit dormancy --path-prefix /team-alpha/` and verify only matching roles appear in output.

### Implementation for User Story 4

- [x] T037 [US4] Implement filter logic in `src/iam_audit/filters.py`: apply `--path-prefix` (string startswith), `--name` (fnmatch glob), `--tag` (key=value match against principal tags) after collection. Filters are AND-combined. Pass `FiltersApplied` into AuditReport
- [x] T038 [US4] Wire filter flags into all subcommands in `src/iam_audit/cli.py`: parse `--path-prefix`, `--name`, `--tag` from args, pass to collector functions in `_run_dormancy()`, `_run_permissions()`, `_run_report()`
- [x] T039 [P] [US4] Unit tests for filtering in `tests/unit/test_filters.py`: path-prefix filtering, glob pattern matching, tag filtering, combined filters (AND), no matches produces empty list
- [x] T040 [US4] Integration test for filtering in `tests/integration/test_cli.py`: `--path-prefix`, `--name`, `--tag` flags correctly limit output

**Checkpoint**: All subcommands support `--path-prefix`, `--name`, `--tag` filtering

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Security hardening, performance validation, documentation, cleanup

- [x] T041 [P] Validate all `html.escape()` coverage in `src/iam_audit/reporters/html.py` — every dynamic value (ARN, name, title, recommendation, description) must be escaped
- [x] T042 [P] Validate credential error handling in `src/iam_audit/cli.py`: early detection of missing/insufficient IAM permissions (FR-013), actionable error messages with specific permission names to stderr
- [x] T043 Validate exit codes across all subcommands: 0 (no findings), 1 (findings), 2 (tool error) per FR-015. Remove any residual exit code 3 references
- [x] T044 [P] Remove any Prometheus-related code, dependencies, or references: `prometheus-client` from deps, `--pushgateway-url` flag, metrics module, exit code 3
- [x] T045 [P] Performance validation: test with 500-role stubbed account completes under 5 minutes (SC-003), memory usage under 256 MB (Constitution V), cold start under 2 seconds (Constitution V)
- [x] T046 Run `quickstart.md` commands end-to-end to validate documented workflows
- [x] T047 Final ruff lint pass and type annotation review across all `src/iam_audit/` files

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately
- **Foundational (Phase 2)**: Depends on Phase 1 — BLOCKS all user stories
- **US1 Dormancy (Phase 3)**: Depends on Phase 2 only — MVP
- **US2 Permissions (Phase 4)**: Depends on Phase 2 only
- **US5 Unused Permissions (Phase 5)**: Depends on Phase 4 (policy collector)
- **US3 Report (Phase 6)**: Depends on Phase 3 + Phase 5 (both analysis types)
- **US4 Filtering (Phase 7)**: Depends on Phase 2 only (can parallel with US1/US2)
- **Polish (Phase 8)**: Depends on all user stories complete

### User Story Dependencies

- **US1 (P1)**: Independent after Phase 2 — **MVP target**
- **US2 (P2)**: Independent after Phase 2
- **US5 (P2)**: Depends on US2 (shares policy collector)
- **US3 (P3)**: Depends on US1 + US5 (combines both analysis types)
- **US4 (P4)**: Independent after Phase 2 (can parallel with US1/US2)

### Within Each User Story

- Models/collectors before analyzers
- Analyzers before CLI wiring
- CLI wiring before integration tests
- Unit tests can parallel with implementation (same phase, different files)

### Parallel Opportunities

- T003 + T004 (setup linting + deps)
- T008 + T009 + T010 + T011 (reporters + model tests + client tests)
- T012 + T013 (role collector + user collector)
- T016 + T017 + T018 (US1 unit tests)
- T020 + T025 + T026 (policy collector + access advisor + actions map — different files)
- T023 + T024 + T029 + T030 (US2/US5 unit tests)
- T033 + T034 + T035 (reporter unit tests)
- T041 + T042 + T044 + T045 (polish tasks)
- US4 (Phase 7) can run in parallel with US1/US2/US5

---

## Parallel Example: User Story 1

```bash
# Launch both collectors in parallel (different files):
Task: "Implement role collector in src/iam_audit/collectors/roles.py"
Task: "Implement user collector in src/iam_audit/collectors/users.py"

# Then dormancy analyzer (depends on both collectors):
Task: "Implement dormancy analyzer in src/iam_audit/analyzers/dormancy.py"

# Launch all unit tests in parallel (different test files):
Task: "Unit tests for role collector in tests/unit/test_collectors.py"
Task: "Unit tests for user collector in tests/unit/test_collectors.py"
Task: "Unit tests for dormancy analyzer in tests/unit/test_analyzers.py"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (models, CLI, reporters)
3. Complete Phase 3: US1 — Dormancy audit
4. **STOP and VALIDATE**: `iam-audit dormancy` works end-to-end
5. Deploy/demo — tool can already identify dormant IAM entities

### Incremental Delivery

1. Setup + Foundational → Foundation ready
2. Add US1 (Dormancy) → Test independently → **MVP!**
3. Add US2 (Permissions) → Test independently → Now detects overly permissive policies
4. Add US5 (Unused Permissions) → Test independently → Now detects unused access
5. Add US3 (Report + HTML) → Test independently → Consolidated report with HTML export
6. Add US4 (Filtering) → Test independently → Scoped audits for large accounts
7. Polish → Security, performance, documentation validation

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: US1 (Dormancy) — MVP
   - Developer B: US2 (Permissions) + US5 (Unused Permissions)
   - Developer C: US4 (Filtering) — independent of other stories
3. After US1 + US2/US5 complete: US3 (Report + HTML)
4. Polish phase as a team

---

## Notes

- [P] tasks = different files, no dependencies on incomplete tasks
- [Story] label maps task to specific user story for traceability
- Findings sort order (FR-037): severity desc then principal name asc — implemented once in Phase 2, used by all reporters
- Deny awareness (FR-036): implemented in US2 permissions analyzer, propagated to all output formats
- HTML collapse/expand (FR-035): `<details>`/`<summary>` collapsed by default, `@media print` forces open
- Prometheus: fully removed — no `--pushgateway-url`, no exit code 3, no `prometheus-client` dependency
- File overwrite: `--output` silently overwrites existing files (POSIX convention)
