# Feature Specification: Local AWS Emulator Smoke Test

**Feature Branch**: `005-emulator-smoke-test`
**Created**: 2026-11-20
**Status**: Draft
**Input**: User description: "Task T022 of feature 004 required running the fixed tool against an account to confirm the P0 fixes on realistic data. A manual run against a local moto emulator did that; make it reusable and run it in CI so regressions in the end-to-end CLI path are caught."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Run the Real CLI End-to-End Against an Emulator (Priority: P1)

A maintainer wants one command that seeds a local IAM emulator with realistic scenarios, runs the real `iam-audit` CLI against it, and reports pass/fail, without any AWS account.

**Why this priority**: Unit tests do not exercise the full collect, analyze, report path; this is the only end-to-end regression check.

**Independent Test**: Run `python scripts/emulator_smoke.py`; it exits 0 when all expectations hold and 1 (listing each mismatch) when a finding is missing or has the wrong severity.

**Acceptance Scenarios**:

1. **Given** the seeded scenarios, **When** the default run completes, **Then** the highest permission severity per principal matches the expectations table (see FR-004).
2. **Given** the default run, **Then** exactly 7 principals are scanned and the reserved SSO role and service-linked role are excluded.
3. **Given** `--include-aws-managed`, **Then** 9 principals are scanned and the SSO role has a CRITICAL finding.
4. **Given** the emulator cannot start or seeding fails, **Then** the script exits 2 with a clear message.

---

### User Story 2 - Guaranteed Isolation from Real AWS (Priority: P1)

An operator with real AWS credentials in their shell runs the smoke test and must be certain it can never touch their account.

**Why this priority**: A test harness that could reach a real account is a security risk.

**Independent Test**: Run with `AWS_PROFILE`/`AWS_ACCESS_KEY_ID` set to real-looking values; verify the CLI only talks to the localhost endpoint and ignores them. Point the endpoint at a non-localhost host and verify the script aborts.

**Acceptance Scenarios**:

1. **Given** `AWS_*` variables in the environment, **When** the script runs, **Then** all are removed and dummy credentials are used.
2. **Given** user config/credentials files, **Then** they are not read (null-device paths).
3. **Given** an endpoint whose host is not localhost, **Then** the script aborts before any call.

---

### User Story 3 - Blocking CI Gate (Priority: P2)

A reviewer wants every pull request to run the smoke test so end-to-end regressions block merge.

**Why this priority**: Value of the script is realized only when it runs automatically.

**Independent Test**: Open a PR; the `smoke` job runs and fails if the script exits non-zero.

**Acceptance Scenarios**:

1. **Given** a pull request, **Then** a blocking `smoke` job runs on Python 3.12 with a read-only token and the same pinned actions as other jobs.
2. **Given** lint runs, **Then** `scripts/` is linted by ruff.

---

### Edge Cases

- Free port selection collides: the script picks a free port at start; a bind failure is a setup error (exit 2).
- `--keep-reports DIR`: both JSON reports are saved for inspection; otherwise they are discarded.
- Freshly created principals are flagged "never used" (HIGH) by the dormancy analysis; dormancy findings are not asserted.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `scripts/emulator_smoke.py` MUST start moto in-process (`ThreadedMotoServer` on 127.0.0.1, free port, `MOTO_IAM_LOAD_MANAGED_POLICIES=true`) and stop it on exit.
- **FR-002**: The script MUST seed IAM scenarios, then run `python -m iam_audit report --format json` twice: default scope and `--include-aws-managed`.
- **FR-003**: Exit codes MUST be 0 (all expectations met), 1 (expectation mismatch), 2 (setup error). Optional `--keep-reports DIR` MUST save the reports.
- **FR-004**: Expectations live in a module-level table: highest permission severity per principal in the default run:

  | Principal | Grant | Expected |
  |-----------|-------|----------|
  | `ci-admin` | AWS-managed `AdministratorAccess` | critical, `policy_is_aws_managed` true |
  | `mixed-star` | `["*","s3:GetObject"]` on `*` | critical |
  | `bucket-star` | `*` on one bucket | high |
  | `power-notaction` | Allow NotAction `iam:*` on `*` | high |
  | `mixed-resource` | 2 IAM actions on `["arn...","*"]` | medium |
  | user `deploy-bot` | group policy `s3:Get*` on scoped ARN | medium |
  | `tight-reader` | scoped `s3:GetObject` | no finding |

- **FR-005**: Scope expectations: default run scans 7 principals and excludes `AWSReservedSSO_Admin_abc123` (`/aws-reserved/sso.amazonaws.com/`) and service-linked `AWSServiceRoleForECS`; `--include-aws-managed` scans 9 and the SSO role has a CRITICAL finding.
- **FR-006**: The script MUST remove every `AWS_*` environment variable, use dummy credentials, set `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` to the null device, pass an explicit localhost endpoint, and abort if the endpoint host is not localhost.
- **FR-007**: CI MUST include a blocking `smoke` job (Python 3.12, same pinned actions, read-only token), and ruff MUST lint `scripts/`.
- **FR-008**: `requirements-dev.txt` MUST depend on `moto[iam,server]` (same version range as before).
- **FR-009**: README MUST document the script in a "Local emulator smoke test" subsection under Development.

### Known Limitations

- moto does not implement Access Advisor (`generate_service_last_accessed_details` raises NotImplementedError), so unused-permission analysis (feature 004 bugs 3 and 4) is not exercised end-to-end; it stays covered by unit tests only. LocalStack's free edition builds IAM on moto, so it does not close the gap.
- Dormancy findings and data gaps are not asserted.

### Out of Scope / Follow-ups

- Grace period for newly created principals (every fresh role/user is flagged HIGH "never used", a real false-positive source).
- End-to-end Access Advisor coverage (needs a recorded-response stub or a real account).
- Multi-scenario fixtures for trust policies once that analysis exists.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A single command reproduces the 004 T022 verification with no AWS account and exits 0.
- **SC-002**: Reintroducing any 004 permission-classification or scope bug makes the script exit 1 and the `smoke` job fail.
- **SC-003**: In 100% of runs the script makes zero requests to non-localhost endpoints.
