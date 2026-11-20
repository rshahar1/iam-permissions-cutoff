# iam-audit — project guide

`iam-audit` is a read-only Python 3.12+ CLI (`iam-audit = iam_audit.cli:main`, also `python -m iam_audit`) that audits
AWS IAM roles and users for over-provisioning: dormant principals, wildcard policies, unused permissions
(Access Advisor), privilege-escalation paths, credential hygiene and risky role trust policies. It only calls
IAM/STS read APIs and never modifies, deletes or remediates any AWS resource. The only runtime dependency is boto3.

## Commands

Setup (Python 3.12+; CI runs 3.12 and 3.13):

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt -e .
```

Checks (these are exactly what CI runs; all four CI jobs — `test` on 3.12 + 3.13, `typecheck`, `audit`, `smoke` — must pass):

```bash
ruff check src tests scripts                                # lint
mypy                                                        # strict; config in pyproject.toml (packages = iam_audit)
pytest --cov=iam_audit --cov-report=term-missing            # coverage gate: fail_under = 80
pip-audit -r requirements-dev.txt --strict                  # dependency vulnerabilities
python scripts/emulator_smoke.py                            # end-to-end CLI run against a local moto server
```

Single test / subset:

```bash
pytest tests/unit/test_trust_analyzer.py::test_trust_001_fires_for_bare_string_principal_star  # one test
pytest tests/unit -k privesc                                # by keyword
pytest tests/integration                                    # moto-backed CLI tests
pytest -m benchmark                                         # performance benchmarks
```

Run the CLI (needs AWS credentials via the standard chain; exit codes: 0 no findings, 1 findings, 2 tool error):

```bash
iam-audit dormancy [--days N]            # inactive principals
iam-audit permissions                    # wildcards, unused permissions, privesc, trust policies
iam-audit credentials [--key-max-age N]  # credential report: root, MFA, access keys, passwords
iam-audit report --format json           # all checks; --format text|json|html, --output PATH (required for html)
```

Shared options: `--days`, `--path-prefix`, `--name`, `--tag KEY=VALUE`, `--include-aws-managed`, `--format`,
`--output`, `--concurrency`, plus check-specific ones (`--key-max-age`, `--trusted-accounts`). See `README.md` for the
full table and `iam-audit <subcommand> --help`.

## Architecture

Pipeline: collect -> analyze -> report. `cli.py` builds the argparse parser from the registry in `pipeline.py`,
authenticates (`aws_client.py`), collects and filters principals (`filters.py`), runs the subcommand's checks, builds an
`AuditReport` (`models.py`) and hands it to a reporter. Logging is structured JSON (`logging_config.py`).

- `collectors/` — all AWS I/O. `roles.py`, `users.py` (paginated enumeration), `policies.py` (inline, managed, group
  policy documents), `access_advisor.py` (concurrent via ThreadPoolExecutor), `credential_report.py` (generate + parse CSV).
- `analyzers/` — pure logic over collected data, no AWS calls except where a check receives the client via the context.
- `reporters/` — `text.py`, `json_reporter.py` (versioned schema), `html.py` (static, `html.escape`, no JavaScript).
- `models.py` — dataclasses (`Principal`, `IAMRole`, `IAMUser`, `Finding`, `DataGap`, `AuditReport`, ...),
  `Severity` and `FindingCategory` enums.
- `data/iam_actions.json` — bundled IAM action map for wildcard expansion in unused-permission analysis.

Analyzers and finding categories (`FindingCategory`):

| Analyzer | Category | What it does |
|----------|----------|--------------|
| `analyzers/dormancy.py` | `dormancy` | Principals idle > `--days`; never-used principals get a grace period from creation |
| `analyzers/permissions.py` | `permission` | Wildcard actions/resources and broad service wildcards, Deny-aware notes |
| `analyzers/unused.py` | `unused_permission` | Granted actions never used per Access Advisor, with wildcard expansion |
| `analyzers/privesc.py` | `privilege_escalation` | Rules PE-001..PE-024 on all-resource grants |
| `analyzers/credentials.py` | `credential` | Rules CRED-001..CRED-008 from the credential report |
| `analyzers/trust.py` | `trust_policy` | Rules TRUST-001..TRUST-009 on role trust policies |

`analyzers/grants.py` holds shared statement-level helpers (which actions a statement allows or denies).

Adding a new check (documented in the `pipeline.py` module docstring; reporters and `cli.py` need no edits):

1. Write `run(ctx: AuditContext) -> list[Finding]` in a new `analyzers/<name>.py`; model rules as data rows
   (id, severity, title, recommendation) plus small detector functions, as in `trust.py` and `credentials.py`.
2. Add a new member and display name to `FindingCategory` in `models.py` if it is a new category.
3. Register `Check("<name>", run, needs_policies=..., add_arguments=...)` in `CHECKS` in `pipeline.py`
   (`needs_policies=True` if it reads policy documents; `add_arguments` for new CLI flags).
4. Add the name to the `checks` tuple of each `Subcommand` that should run it, or add a new `Subcommand` (with epilog).
5. Add unit tests in `tests/unit/`, an integration test if it touches a new AWS call, a row in the expectations
   tables of `scripts/emulator_smoke.py`, README docs (rule table, required IAM permissions) and a JSON schema delta
   in the feature's `contracts/`.

## Code conventions

- Ruff: `E,F,W,I,N,UP,B,A,SIM,TCH`, line length 120, target py312. Use `from __future__ import annotations` and put
  type-only imports under `TYPE_CHECKING` (rule `TCH`).
- mypy `strict = true`: full annotations everywhere (`boto3-stubs[iam,sts]` provides client types); `mypy` must be clean.
- Public functions, classes and modules get concise docstrings (purpose, parameters, return value).
- Functions <= 40 lines of logic, files <= 400 lines (justify exceptions in the PR). Check file sizes before adding to
  large modules such as `analyzers/trust.py` (~340 lines).
- Descriptive, domain-aligned names; no abbreviations except `id`, `url`, `http`. No dead code, unused imports or
  commented-out code. Refactor duplication once a pattern appears three times.
- Errors are actionable (what went wrong, why, how to fix), printed to stderr; stdout carries only report output.
  Every new output must work with `--format json`; keep the JSON schema backward compatible.
- Tests: names state scenario and outcome (`test_deny_policy_when_action_is_wildcard`); deterministic and isolated;
  mock only external I/O (moto or boto stubs), never business logic; cover empty and malformed inputs.
- Logging is structured JSON with correlation IDs and never contains secrets or PII.
- Update README and docs in the same PR as the feature.

## Security rules

- Read-only: never add a write/mutating IAM call; update the "Required AWS Permissions" list in `README.md` whenever a
  new read call is added.
- Never commit credentials, tokens, real account IDs or real principal names. Local output (`audit.json`, `/reports/`)
  is gitignored for that reason; `.env*` and `.claude/` are ignored too. Use the placeholder account `123456789012` in
  tests, examples and docs. Check staged changes for secrets before every commit.
- Dependencies are pinned to ranges in `requirements*.txt` / `pyproject.toml`; `pip-audit --strict` gates CI. Any new
  dependency needs justification (license, maintenance, vulnerabilities); the runtime stays boto3 + stdlib.
- Escape all dynamic content in HTML output with `html.escape`.

## Workflow (spec-kit, mandatory)

- Every feature or fix gets its own branch `NNN-short-name` and a directory `specs/NNN-short-name/` with `spec.md`,
  `plan.md` (including a Constitution Check table, one row per principle I-V) and `tasks.md`; optional `contracts/`.
- Flow: `/speckit-specify` -> `/speckit-clarify` -> `/speckit-plan` -> `/speckit-tasks` -> `/speckit-analyze` ->
  `/speckit-implement`. Keep spec status, plan and task checkboxes in sync with what was actually built.
- Helpers in `.specify/scripts/bash/`: `create-new-feature.sh [--json] [--short-name <name>] [--number N] "<description>"`
  (creates the branch and spec directory), `check-prerequisites.sh [--json] [--require-tasks] [--include-tasks]
  [--paths-only]`, `setup-plan.sh`, and `update-agent-context.sh [agent_type]` (maintains the last two sections of
  this file). Templates live in `.specify/templates/`.
- Open a PR into `main` (never push directly), wait for the four CI jobs, squash-merge.
- The constitution (`.specify/memory/constitution.md`) is authoritative and wins over this file on any conflict.

## Gotchas

- moto does not implement Access Advisor (`generate_service_last_accessed_details`): unused-permission analysis cannot
  be exercised end to end in the smoke test; unit tests feed it simulated last-accessed data.
- `scripts/emulator_smoke.py` sets `MOTO_IAM_LOAD_MANAGED_POLICIES=true` before importing moto (hence `noqa: E402`),
  scrubs every `AWS_*` variable and forces the endpoint to a local moto server, so real AWS is never contacted. All
  seeded principals are brand new, so the default run must show no dormancy findings. Add scenarios in `seed()` and a
  row in `EXPECTED_PERMISSION` / `EXPECTED_RULES` / `EXPECTED_ABSENT`. Exit codes: 0 ok, 1 mismatch, 2 setup error.
- Integration tests use `@mock_aws`; shared builders and fixtures (`make_role`, `make_user`, `make_finding`,
  `make_policy_document`, ...) live in `tests/conftest.py` and use account `123456789012`.
- `--format html` requires `--output`. Credential checks need `iam:GenerateCredentialReport` and
  `iam:GetCredentialReport`; if denied the run continues and records a data gap.
- The root account is audited by credential checks only when no `--path-prefix`, `--name` or `--tag` filter is set.
- `--include-aws-managed` widens which principals are scanned; AWS-managed policies attached to your own principals
  are always analyzed.
- Privilege-escalation checks only evaluate grants on all resources; permission boundaries, SCPs and Allow-statement
  conditions are not evaluated (documented limitation).
- `examples/` and `docs/images/` are generated from the smoke-test emulator account; regenerate them together.

## Active Technologies
- Python 3.12+ with boto3 (AWS SDK); everything else from the stdlib. Dev: pytest, pytest-cov, moto, ruff, mypy, boto3-stubs, pip-audit.

## Recent Changes
- 013-readme-example-images: README shows real text/HTML report images; examples/ and docs/images/ regenerated from the emulator.
- 012-smoke-new-checks: emulator smoke test extended to the trust-policy, privilege-escalation and credential-report checks.
