# Research: IAM Audit CLI

**Branch**: `003-iam-audit-cli` | **Date**: 2026-03-11

## R1: boto3 Retry and Rate Limiting Strategy

**Decision**: Use botocore `standard` retry mode with `total_max_attempts=10`. Add application-level concurrency control via `threading.Semaphore` for bulk API calls.

**Rationale**: Standard mode retries throttling exceptions (`ThrottlingException`, HTTP 429, `RequestLimitExceeded`) with exponential backoff capped at 20 seconds. It includes a circuit breaker and covers more retryable errors than legacy mode. IAM per-operation rate limits are not publicly documented, so relying on SDK-level retry plus app-level throttling is the practical approach.

**Alternatives considered**:
- Legacy mode: Fewer retryable error codes, no circuit breaker. Rejected.
- Adaptive mode: Adds token-bucket rate limiting but is marked experimental by AWS. Rejected for stability.
- Custom retry handler: Unnecessary complexity given standard mode covers IAM throttling.

**Configuration**:
```python
from botocore.config import Config
config = Config(retries={"total_max_attempts": 10, "mode": "standard"})
iam = boto3.client("iam", config=config)
```

---

## R2: GenerateServiceLastAccessedDetails Polling Pattern

**Decision**: Exponential backoff polling — initial delay 1s, multiplier 2x, max delay 30s, overall timeout 10 minutes per job.

**Rationale**: Jobs typically complete in seconds to a few minutes. Exponential backoff balances responsiveness for fast jobs against API courtesy for slow ones. The 10-minute timeout catches hung jobs without blocking the entire audit.

**Alternatives considered**:
- Fixed 1s polling: Wastes API calls when jobs are slow. Rejected.
- Fixed 30s polling: Too slow for fast jobs. Rejected.
- No timeout: Risks infinite blocking. Rejected.

**Job lifecycle**:
1. Call `GenerateServiceLastAccessedDetails(Arn=principal_arn, Granularity="ACTION_LEVEL")` → returns `JobId`
2. Poll `GetServiceLastAccessedDetails(JobId=job_id)` until `JobStatus` is `COMPLETED` or `FAILED`
3. Possible `JobStatus` values: `IN_PROGRESS`, `COMPLETED`, `FAILED`
4. On `FAILED`: record data gap, skip unused-permissions analysis for that principal
5. On timeout: same as FAILED — record data gap

**Concurrency**: Default 10 concurrent jobs (`--concurrency` flag overrides). Use `concurrent.futures.ThreadPoolExecutor(max_workers=concurrency)` to manage parallel Generate+Poll flows.

---

## R3: Access Advisor API Data Structure

**Decision**: Always request `Granularity="ACTION_LEVEL"` to get the richest data available. Fall back gracefully when action-level data is absent for a service.

**Rationale**: ACTION_LEVEL returns both service-level and action-level data where supported. Using SERVICE_LEVEL would miss action-level detail for the 200+ services that support it.

**Key response fields**:
- `ServicesLastAccessed[].ServiceNamespace` — service prefix (e.g., `s3`, `ec2`)
- `ServicesLastAccessed[].LastAuthenticated` — timestamp or `null` if never accessed
- `ServicesLastAccessed[].TrackedActionsLastAccessed[]` — present only for ACTION_LEVEL-supported services
  - `.ActionName` — e.g., `CreateBucket`
  - `.LastAccessedTime` — timestamp or `null`

**Action-level support**: 200+ services support action-level granularity, including S3, EC2, IAM, Lambda, KMS, STS, DynamoDB, RDS, ECS, EKS, CloudFormation, and many more. Full list is maintained in AWS docs.

**Data retention**: Up to ~400 days (service-level). Action-level tracking started between April 2020 and May 2023 depending on the service.

**Principals with no activity**: Job completes successfully with `ServicesLastAccessed` listing services but `LastAuthenticated=null`. Empty `ServicesLastAccessed` only when the principal has no permissions at all.

---

## R4: IAM Actions Map — Source and Maintenance

**Decision**: Bundle a static JSON file (`iam_actions.json`) derived from Parliament's `iam_definition.json` data. Structure: `{"service_prefix": ["Action1", "Action2", ...]}`. Update via automated CI job weekly.

**Rationale**: Parliament (duo-labs/parliament) maintains a comprehensive, scraped-from-AWS-docs mapping of all IAM actions per service (~350+ services, ~15,000–20,000+ actions). The data is already Python-ecosystem-friendly. Extracting just the `{prefix: [actions]}` map keeps the bundled file small (~200KB) while providing everything needed for wildcard expansion.

**Alternatives considered**:
- Depend on Parliament as runtime dependency: Brings in more code than needed. Rejected — vendor the data only.
- IAM Policy Simulator API: Does not enumerate actions; it evaluates specific action-resource pairs. Not suitable.
- Policy Sentry: Similar scraping approach but heavier dependency for this use case. Rejected.
- Manual maintenance: Too error-prone given the pace of new AWS actions. Rejected.

**Update strategy**:
1. CI job runs weekly
2. Executes a scraping script (based on Parliament's approach) against AWS Service Authorization Reference docs
3. Produces updated `iam_actions.json`
4. Opens PR if changes detected
5. Tool logs a warning at runtime if an encountered service prefix is not in the map

---

## R5: [REMOVED] Prometheus Pushgateway Integration

**Status**: Removed per Session 2026-03-11 clarification. The `prometheus-client` dependency and all Pushgateway-related code, CLI flags (`--pushgateway-url`), exit codes (code 3), and metrics contracts have been deleted. No replacement needed — the tool is a batch CLI with file-based output.

---

## R6: Severity Classification Heuristic

**Decision**: Four-tier severity based on policy statement breadth.

**Rationale**: Aligns with spec acceptance scenarios (US2) and provides clear, deterministic classification.

| Severity | Criteria | Examples |
|----------|----------|---------|
| Critical | `Action: "*"` AND `Resource: "*"` | Full admin access |
| High | Full-service wildcard (`service:*`) OR `Resource: "*"` with specific actions | `s3:*`, `ec2:*` on all resources |
| Medium | Broad action patterns (>5 actions on a service) or `Resource: "*"` with narrow actions | `s3:Get*` on `*`, 8 specific DynamoDB actions on `*` |
| Low | Minor over-provisioning or zero-policy entities | Role with no policies (FR-021), 1-2 unused actions |

**For unused-permissions findings (US5)**: Severity is based on the sensitivity of the unused service — unused access to IAM, KMS, or STS is High; unused access to most other services is Medium; unused access to read-only services is Low.

**Deny statement handling (FR-036)**: Severity is determined solely by the Allow statement's breadth. Explicit Deny statements do not reduce severity. When Deny statements are present on a principal, a contextual note is appended to the finding (e.g., "Note: principal also has Deny statements that may restrict effective access").

---

## R7: Memory Management for Large Accounts

**Decision**: Generator-based pagination for all AWS list operations. Findings accumulated in a list (bounded by account size) but individual API responses are never fully loaded.

**Rationale**: For 500 roles with ~10 policies each, the finding list is at most ~5,000 entries — well within 256 MB. The memory concern is AWS API response pages (each ~1MB max), which are processed one page at a time via generators.

**Pattern**: Use boto3 paginators (`get_paginator()`) which yield one page at a time. Process each page, extract needed fields, discard the page.

---

## R8: HTML Report Generation — Approach and Styling

**Decision**: Use Python stdlib `html.escape` for output encoding and `string.Template` for the HTML skeleton. Inline all CSS in a `<style>` block within the HTML `<head>`. No external dependencies.

**Rationale**: The HTML report is a single self-contained file (FR-032). Using stdlib avoids new dependencies and keeps the tool lightweight. The report structure is simple enough (summary header + categorized tables) that a full templating engine (Jinja2, Mako) would be over-engineering. `string.Template` provides safe substitution with `$variable` syntax, keeping the HTML template readable.

**Alternatives considered**:
- Jinja2: Powerful but adds a dependency for a single template. Rejected — violates constitution II (minimize dependencies) for negligible benefit.
- f-strings with HTML: Works but mixes logic and markup, harder to maintain. Rejected.
- Raw string concatenation: Error-prone for HTML structure. Rejected.

**CSS design decisions**:
- Color palette for severity badges: Critical=#dc3545 (red), High=#fd7e14 (orange), Medium=#ffc107 (yellow on dark text), Low=#0d6efd (blue)
- Font: `system-ui, -apple-system, sans-serif` (no external fonts)
- Max-width container (1200px) for readability on wide screens
- Zebra-striped table rows for scannability
- Print-friendly: `@media print` rules to remove background colors and ensure legibility

**Security**: All finding text (principal names, titles, recommendations) MUST be passed through `html.escape()` before insertion into HTML to prevent XSS if report data contains special characters (e.g., `<`, `>`, `&` in policy names or ARNs).

**Collapse/expand (FR-035)**: Each finding category section is wrapped in a `<details>`/`<summary>` element. All sections are collapsed by default (no `open` attribute). The `<summary>` line displays the category name and finding count (e.g., "Dormancy Findings (5)") so users can identify relevant sections without expanding. The summary header with severity badges remains outside `<details>` elements and is always visible.

**Print support**: A `@media print` CSS rule forces all `<details>` elements open via `details[open] { display: block; }` and `details { display: block; }` plus `details > summary { display: none; }` pattern, or more simply `details { open: true; }` — however, CSS cannot set the `open` attribute. The practical approach is: `@media print { details { display: block; } details > * { display: block; } }` which forces content visible regardless of collapsed state.

**Structure of generated HTML**:
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>IAM Audit Report — {account_id}</title>
  <style>
    /* all CSS inlined here */
    @media print { details > * { display: block !important; } }
  </style>
</head>
<body>
  <header><!-- summary badges: total, by-category, by-severity --></header>
  <main>
    <details>
      <summary>Dormancy Findings (N)</summary>
      <!-- dormancy findings table -->
    </details>
    <details>
      <summary>Permission Findings (N)</summary>
      <!-- permission findings table -->
    </details>
    <details>
      <summary>Unused Permission Findings (N)</summary>
      <!-- unused permission findings table -->
    </details>
    <section class="data-gaps"><!-- data gaps if any --></section>
  </main>
  <footer><!-- audit metadata: timestamp, threshold, filters --></footer>
</body>
</html>
```

---

## R9: Finding Sort Order (FR-037)

**Decision**: Sort findings within each category by severity descending (Critical → High → Medium → Low), then alphabetically by principal name within the same severity level. Apply to all output formats.

**Rationale**: Putting highest-severity findings first ensures the most critical issues are immediately visible. Alphabetical secondary sort provides deterministic, stable ordering for test assertions and diffing between audit runs.

**Implementation**: Define a severity order mapping (`{"Critical": 0, "High": 1, "Medium": 2, "Low": 3}`). Sort the findings list using `sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.principal_name))`. Apply once in the report generation layer before passing to any formatter.

**Alternatives considered**:
- Sort by principal name only: Buries critical findings. Rejected.
- Sort by discovery order: Non-deterministic. Rejected.

---

## R10: Deny Statement Awareness (FR-036)

**Decision**: Detect the presence of `Deny` effect statements in a principal's policies and append a contextual note to permission findings. Do not modify severity or attempt effective-permission evaluation.

**Rationale**: Full Allow/Deny interaction evaluation requires resolving Conditions, resource-level matching, and cross-policy statement ordering — significant complexity that risks false confidence if incomplete. Noting Deny presence provides useful context (the user knows the Allow may be partially restricted) without misleading them.

**Implementation**: During policy analysis in `analyzers/permissions.py`, scan all `PolicyStatement` objects for `effect == "Deny"`. If any Deny statements exist on the principal, set a flag (`has_deny_statements=True`) on the finding metadata. The reporter appends: "Note: principal also has Deny statements that may restrict effective access."

**Alternatives considered**:
- Reduce severity when Deny exists: Risk of false confidence from incomplete analysis. Rejected.
- Ignore Deny entirely: Loses useful context. Rejected.
- Full effective-permission evaluation: Significant scope expansion, deferred to future version.

---

## R11: File Overwrite Behavior for --output

**Decision**: Silently overwrite existing files when `--output` targets a path that already exists.

**Rationale**: Follows standard POSIX CLI behavior (matching `>` redirect, `cp`, `jq --output`). The primary use case is re-running audits to refresh reports. Adding a `--force` flag would create friction for the most common workflow. Users who need protection can use timestamped filenames.

**Implementation**: Use `pathlib.Path(path).write_text(content, encoding="utf-8")` which overwrites by default. No additional checks needed.
