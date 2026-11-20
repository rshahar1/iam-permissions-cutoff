# Implementation Plan: Fix P0 Analyzer Correctness Bugs

**Branch**: `004-fix-p0-analyzer-bugs` | **Date**: 2026-11-20 | **Spec**: `specs/004-fix-p0-analyzer-bugs/spec.md`
**Input**: Feature specification from `/specs/004-fix-p0-analyzer-bugs/spec.md`

## Summary

Fix five analyzer correctness bugs in the existing `iam-audit` CLI: ignored `NotAction`/`NotResource`, fragile wildcard classification, unused-permission false positives from untracked actions, case-sensitive/prefix-only action matching, and misleading `--include-aws-managed` semantics (including SSO-reserved roles). Approach: extend two dataclasses, normalize classification into small helpers, switch the unused analyzer to Access Advisor's tracked-action list with case-insensitive `fnmatch`-style matching, and scope the flag to principals. JSON changes are additive.

## Technical Context

**Language/Version**: Python 3.12+
**Primary Dependencies**: boto3; stdlib `fnmatch` (no new dependencies)
**Storage**: N/A
**Testing**: pytest, botocore Stubber, moto (already used by roles collector tests); coverage >= 80%
**Target Platform**: Linux/macOS CLI
**Project Type**: CLI tool (existing)
**Performance Goals**: No regression; matching is O(granted x tracked) per service, trivial at scale
**Constraints**: Functions <= 40 lines, files <= 400 lines; ruff clean
**Scale/Scope**: Touches `models.py`, `collectors/policies.py`, `collectors/roles.py`, `analyzers/permissions.py`, `analyzers/unused.py`, `cli.py` (help), README/docs

## Design Decisions

1. **Normalization before classification** (`analyzers/permissions.py`): helpers `_has_all_actions(actions)` (any of `*`, `*:*`) and `_applies_to_all_resources(stmt)` (any `*` resource or non-empty `not_resources`). `_classify_statement` becomes a small decision table matching FR-005; NotAction handled in its own branch.
2. **Parser** (`collectors/policies.py::_parse_policy_document`): accept string-or-list for `NotAction`/`NotResource` via the existing list-normalizing helper.
3. **Unused analyzer** (`analyzers/unused.py`): iterate Access Advisor tracked actions; an action is in scope if `_matches_any(granted_patterns, name)`. Each Allow statement becomes per-service `ServiceGrant(include, exclude)` patterns; matching uses `fnmatch.fnmatchcase` on lowercased strings (`*`, `?` supported; `[` is escaped so only `*`/`?` are special). NotAction statements grant every known service minus wholly excluded `svc:*` services, and individually excluded actions are carried in `exclude` so they are never reported as unused. `_expand_wildcard_actions` deleted.
4. **Flag semantics**: `IAMRole.is_aws_reserved` set in the roles collector from path prefix `/aws-reserved/`; the AWS-managed principal filter (service-linked, service, reserved) is the single place the flag acts. Policy analyzers never consult it. Permission finding metadata adds `policy_is_aws_managed` (ARN prefix `arn:aws:iam::aws:policy/`), which switches the recommendation text.
5. **Contract**: additive keys only; see `contracts/json-schema-delta.md`.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Code Quality | PASS | Small single-purpose helpers; dead helper `_expand_wildcard_actions` removed; type annotations and docstrings on new functions; no new duplication. |
| II. Security by Default | PASS | Fixes false negatives on wildcard/NotAction grants and AWS-managed admin policies; no secrets; read-only AWS calls; patterns matched via safe glob translation (no user-controlled regex). |
| III. Testing Standards | PASS | Regression tests for every bug, table-driven classifier cases, moto-based collector test, outdated unused tests corrected; coverage >= 80%. |
| IV. User Experience | PASS | Help text/README/docs corrected; JSON change additive with documented delta, `schema_version` unchanged; recommendations actionable. |
| V. Performance | PASS | No extra API calls; in-memory matching only; no regression. |

No violations; no complexity tracking entries needed.

## Project Structure

### Documentation (this feature)

```text
specs/004-fix-p0-analyzer-bugs/
├── spec.md
├── plan.md
├── tasks.md
├── checklists/
│   └── requirements.md
└── contracts/
    └── json-schema-delta.md
```

### Source Code (repository root)

```text
src/iam_audit/
├── models.py                  # PolicyStatement.not_actions/not_resources; IAMRole.is_aws_reserved
├── cli.py                     # --include-aws-managed help text
├── collectors/
│   ├── policies.py            # parse NotAction/NotResource
│   └── roles.py               # set is_aws_reserved; exclude by default
├── analyzers/
│   ├── permissions.py         # normalized classification, NotAction, policy_is_aws_managed
│   └── unused.py              # tracked-only, case-insensitive glob, NotAction handling
└── reporters/json_reporter.py # emit new metadata keys (if metadata is not passed through)

tests/unit/                    # parser, classifier, unused, roles collector, reporter
README.md, docs                # flag semantics
```

**Structure Decision**: Existing single-project layout; no new modules.
