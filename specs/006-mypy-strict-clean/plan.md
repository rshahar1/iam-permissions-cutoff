# Implementation Plan: Mypy Strict Clean

**Branch**: `006-mypy-strict-clean` | **Date**: 2026-11-20 | **Spec**: `specs/006-mypy-strict-clean/spec.md`

## Summary

Annotate the remaining untyped code (mostly boto3 clients in collectors), replace invalid `boto3.client` annotations with stub types, fix a handful of `Any` returns and one `replace()` typing problem, then make the CI mypy step blocking.

## Technical Context

**Language/Version**: Python 3.12+
**Primary Dependencies**: boto3, boto3-stubs[iam,sts] (dev only)
**Testing**: existing pytest suite, ruff, smoke script, pip-audit
**Constraints**: no behavior change; functions <= 40 lines

## Design Decisions

1. **Stub types under `TYPE_CHECKING`**: `IAMClient`/`STSClient` imported only for type checking (no runtime dependency on stubs; `from __future__ import annotations` is already used).
2. **Policy documents**: a small `_load_document(raw: object) -> dict[str, Any]` helper replaces four copies of the "decode string else use as-is" snippet, with an explicit `cast` for the TypedDict/Any union.
3. **`replace()` on `Principal`**: `collect_policies_for_principal` branches on `isinstance(principal, IAMUser)` and calls `replace` with all fields at once so the checker sees `IAMUser`.
4. **Raw responses**: `dict[str, Any]` plus `cast` for Access Advisor responses; `str()`/annotated local for STS account id and `json.loads` result.
5. **CI**: remove `continue-on-error` from the mypy step.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Full annotations; no `type: ignore`; duplicated decode snippet consolidated. |
| II. Security by Default | PASS | No secrets; pip-audit stays clean; no new runtime dependencies. |
| III. Testing Standards | PASS | Existing tests and smoke test unchanged and passing; type check becomes a gate. |
| IV. User Experience | PASS | No CLI or output change. |
| V. Performance | PASS | No runtime impact. |

## Project Structure

```text
src/iam_audit/{aws_client,cli,logging_config}.py
src/iam_audit/analyzers/unused.py
src/iam_audit/collectors/{users,roles,policies,access_advisor}.py
.github/workflows/ci.yml
requirements-dev.txt
```
