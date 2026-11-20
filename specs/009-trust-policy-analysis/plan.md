# Implementation Plan: Trust-policy analysis

**Branch**: `009-trust-policy-analysis` | **Date**: 2026-11-20 | **Spec**: [spec.md](spec.md)

## Technical Context

Python 3.12, stdlib only. New module `src/iam_audit/analyzers/trust.py`; `models.py`, `collectors/policies.py`, `collectors/roles.py`, `pipeline.py` and the README updated. Reporters are untouched (they read `FindingCategory.display_name`).

## Design

- Models: `PolicyStatement.principals` / `not_principals`, `IAMRole.trust_policy`, `FindingCategory.TRUST_POLICY` (last member, display name last).
- Collector: `list_roles` already returns the trust document; `collect_roles` parses it through the new public `load_policy_document`.
- Analyzer: each `TrustRule` is a data row (id, severity, title, description, recommendation) plus a detector `StatementView -> list[offending principals]`. `analyze_role_trust` filters statements (`Allow` + assume action) and runs every rule; one finding per statement per rule.
- Pipeline: `Check("trust", run, add_arguments=add_trust_arguments)` appended last to `CHECKS` and to the `permissions` and `report` subcommands; `--trusted-accounts` validates 12-digit IDs.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Rules are data; functions ≤ 40 lines, trust.py ≈ 330 lines; typed and documented. |
| II. Security | PASS | Read-only, no new API calls; flags wildcard and unconstrained federated trust; account IDs validated at the CLI boundary. |
| III. Testing | PASS | `test_trust_analyzer.py` (each rule positive/negative, flag, scoping) and `test_trust_collection.py` (parser, stubbed `list_roles` collector, registry); only AWS I/O is stubbed. |
| IV. UX Consistency | PASS | Same finding shape and report sections; one new optional flag documented in the README. |
| V. Performance | PASS | No additional API calls; analysis is linear in trust statements. |
