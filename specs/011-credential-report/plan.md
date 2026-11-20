# Implementation Plan: Credential report hygiene checks

**Branch**: `011-credential-report` | **Date**: 2026-11-20 | **Spec**: [spec.md](spec.md)

## Technical Context

Python 3.12, stdlib plus boto3. New modules `collectors/credential_report.py` and `analyzers/credentials.py`; `models.py` (new category) and `pipeline.py` (check + subcommand) updated. Reporters untouched.

## Design

- Collector: `collect_credential_report(client, sleep, timeout)` returns `(rows, data_gaps)`; rows are `CredentialReportRow` with two `AccessKeyInfo` slots.
- Analyzer: rules are `CredentialRule` data (id, severity, title, description, recommendation); small functions per scope (`_root_rules`, `_user_rules`, `_key_findings`). `run(ctx)` selects rows (users in `ctx.principals` by ARN; root only if `path_prefix`, `name`, `tag` are all unset) and uses `ctx.now`.
- Pipeline: `Check("credentials", run, add_arguments=...)` appended to `CHECKS`; `credentials` appended to `report`; new `credentials` `Subcommand` at the end. `FindingCategory.CREDENTIAL` with display name "Credential Findings".
- Root findings use `principal_type` `root` and name `<root_account>`.
- Extra IAM permissions: `iam:GenerateCredentialReport`, `iam:GetCredentialReport` (README).

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Functions ≤ 40 lines, files ≤ 400 lines, typed and documented, rules as data. |
| II. Security | PASS | Read-only calls; credential report holds no secrets; no credentials in code or tests. |
| III. Testing | PASS | Scenario-named unit tests; only AWS I/O is stubbed; one moto-backed report test. |
| IV. UX Consistency | PASS | Same options, formats and exit codes; new `--key-max-age` documented in help and README. |
| V. Performance | PASS | Two extra API calls per run (plus bounded polling). |
