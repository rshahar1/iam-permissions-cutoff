<!--
Sync Impact Report
===================
Version change: 0.0.0 → 1.0.0 (initial ratification)
Modified principles: N/A (initial version)
Added sections:
  - Principle I: Code Quality & Maintainability
  - Principle II: Security by Default
  - Principle III: Testing Standards
  - Principle IV: User Experience Consistency
  - Principle V: Performance Requirements
  - Section: Compliance & Enforcement
  - Section: Development Workflow
  - Section: Governance
Removed sections: N/A
Templates requiring updates:
  - .specify/templates/plan-template.md ✅ reviewed (no changes needed — Constitution Check section is dynamic)
  - .specify/templates/spec-template.md ✅ reviewed (no changes needed — requirements section is generic)
  - .specify/templates/tasks-template.md ✅ reviewed (no changes needed — Polish phase already covers security, performance, testing)
Follow-up TODOs: none
-->

# IAM Permissions Cut-Off Constitution

## Core Principles

### I. Code Quality & Maintainability

All code MUST be clear, consistent, and maintainable. This is non-negotiable.

- Every module, function, and class MUST have a single, well-defined responsibility.
- Functions MUST NOT exceed 40 lines of logic; files MUST NOT exceed 400 lines. Violations require documented justification in the PR.
- All public APIs MUST include type annotations (or equivalent static typing) and concise docstrings that describe purpose, parameters, and return values.
- Dead code, unused imports, and commented-out code MUST NOT be merged to main. Linting and formatting tools MUST run in CI and block merge on failure.
- Naming MUST be descriptive and domain-aligned. Abbreviations are forbidden except for universally understood terms (e.g., `id`, `url`, `http`).
- Code duplication across modules MUST be refactored into shared utilities once a pattern appears three or more times.

**Rationale**: IAM permission logic is high-stakes — ambiguity or inconsistency in code leads directly to security misconfigurations.

### II. Security by Default

Security MUST be a first-class concern in every decision, not a bolt-on phase.

- All external input MUST be validated at the trust boundary using schema-based validation. No exceptions.
- Secrets (API keys, credentials, tokens) MUST NOT appear in source code, configuration files, or logs. Use a secrets manager; environment variables are an acceptable fallback.
- All database interactions MUST use parameterized queries or a safe ORM. String-concatenated SQL is forbidden.
- IAM policies generated or managed by this project MUST follow the principle of least privilege. Wildcard (`*`) actions and resources MUST be flagged and require explicit documented justification.
- Dependency versions MUST be pinned. CI MUST run vulnerability scanning (e.g., `pip-audit`, `safety`, `npm audit`) and block merge on High or Critical findings in the direct or transitive dependency graph.
- Cryptographic operations MUST use maintained libraries with AEAD primitives (AES-GCM, ChaCha20-Poly1305). MD5, SHA1, DES, 3DES, and RC4 are forbidden.

**Rationale**: This project directly manages IAM permissions — a security flaw here has blast radius across the entire AWS account.

### III. Testing Standards

Every feature MUST be verified through automated tests before it is considered complete.

- Unit tests MUST cover all public functions and all branching logic. Minimum coverage threshold: 80% line coverage, enforced in CI.
- Integration tests MUST exist for every external boundary: API endpoints, database interactions, IAM API calls, and cross-service communication.
- Tests MUST be deterministic, isolated, and repeatable. Flaky tests MUST be quarantined and fixed within one sprint or removed.
- Test names MUST describe the scenario and expected outcome (e.g., `test_deny_policy_when_action_is_wildcard`).
- Edge cases — empty inputs, maximum-size payloads, malformed data, permission boundary conflicts — MUST have explicit test cases.
- Mocks and stubs MUST only replace external I/O; business logic MUST NOT be mocked away.

**Rationale**: IAM permission changes are difficult to roll back. Automated tests are the primary safety net preventing incorrect policies from reaching production.

### IV. User Experience Consistency

All interfaces — CLI, API, or UI — MUST deliver a predictable, coherent experience.

- Error messages MUST be actionable: they MUST state what went wrong, why, and how to fix it. Generic messages like "An error occurred" are forbidden in user-facing output.
- CLI tools MUST follow POSIX conventions: arguments via flags, structured output via `--format json`, human-readable output by default, errors to stderr.
- API responses MUST use a consistent envelope structure with predictable field names, HTTP status codes, and error schemas across all endpoints.
- All user-facing changes MUST be backward-compatible or accompanied by a documented migration path and deprecation notice at least one minor version in advance.
- Documentation MUST be updated in the same PR as the feature it describes. Undocumented features MUST NOT be merged.

**Rationale**: Operators managing IAM permissions need to trust their tooling. Inconsistent behavior erodes trust and increases the likelihood of misconfiguration.

### V. Performance Requirements

The system MUST meet defined performance baselines and MUST NOT regress without justification.

- API responses MUST complete within 500ms at p95 under expected load. Operations exceeding this threshold MUST be made asynchronous with a polling or callback mechanism.
- Batch operations (e.g., evaluating permissions across multiple roles) MUST support pagination and MUST NOT load unbounded datasets into memory.
- Memory usage MUST remain below 256 MB for typical workloads. Deviations require profiling evidence and documented justification.
- Performance-critical paths MUST have benchmark tests that run in CI. Any regression greater than 10% MUST block merge and require investigation.
- Cold start time (CLI invocation to first useful output) MUST be under 2 seconds.

**Rationale**: IAM tooling is often invoked in automation pipelines and CI/CD. Slow or resource-hungry operations become pipeline bottlenecks and degrade developer productivity.

## Compliance & Enforcement

- All pull requests MUST pass CI checks for linting, type checking, test coverage, vulnerability scanning, and performance benchmarks before merge.
- Code reviews MUST verify adherence to all five principles. Reviewers MUST use the constitution as a checklist.
- Any new dependency MUST be reviewed for license compatibility, maintenance status, and known vulnerabilities before adoption.
- IAM policy outputs MUST be validated against AWS IAM policy grammar and tested with the IAM policy simulator or equivalent before deployment.
- Logging MUST be structured (JSON), MUST NOT contain secrets or PII, and MUST include correlation IDs for traceability.

## Development Workflow

- All features MUST be developed on feature branches and merged via pull request with at least one approving review.
- Commits MUST be atomic and descriptive. Squash-merge is the default merge strategy.
- The main branch MUST always be in a deployable state. Broken builds MUST be fixed or reverted within one hour.
- Feature flags MUST be used for incomplete features that are merged to main. Flag cleanup MUST be tracked as a follow-up task.
- Releases MUST follow semantic versioning (MAJOR.MINOR.PATCH) with a changelog entry for every version.

## Governance

This constitution is the authoritative source of project standards. It supersedes informal practices, verbal agreements, and ad-hoc decisions.

- Amendments MUST be proposed via pull request with a rationale, reviewed by at least one maintainer, and merged before taking effect.
- Each amendment MUST increment the constitution version following semantic versioning: MAJOR for principle removals or redefinitions, MINOR for new principles or material expansions, PATCH for clarifications and wording fixes.
- Compliance with this constitution MUST be verified during every code review. Persistent violations MUST be raised as issues and tracked to resolution.
- An annual review of all principles MUST be conducted to ensure they remain relevant and proportionate.

**Version**: 1.0.0 | **Ratified**: 2026-03-07 | **Last Amended**: 2026-03-07
