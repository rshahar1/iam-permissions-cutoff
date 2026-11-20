# Contributing to iam-audit

Thanks for your interest in improving `iam-audit`. You can contribute by opening issues (please use the issue
forms) or by sending pull requests from a fork. Contributions are accepted under the project's MIT license.

## Development setup

Python 3.12+ is required.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt -e .
```

## Checks

These are exactly what CI runs. All four CI jobs (`test` on 3.12 and 3.13, `typecheck`, `audit`, `smoke`) must pass.

```bash
ruff check src tests scripts                                # lint
mypy                                                        # strict; config in pyproject.toml (packages = iam_audit)
pytest --cov=iam_audit --cov-report=term-missing            # coverage gate: fail_under = 80
pip-audit -r requirements-dev.txt --strict                  # dependency vulnerabilities
python scripts/emulator_smoke.py                            # end-to-end CLI run against a local moto server
```

## Workflow

1. Branch from `main`.
2. For features or behavior changes, add a `specs/NNN-short-name/` directory with `spec.md`, `plan.md` and
   `tasks.md`, following the spec-kit flow described in [CLAUDE.md](CLAUDE.md) (specify, clarify, plan, tasks,
   analyze, implement). Small fixes and docs changes can skip the spec; a maintainer may ask for one.
3. Open a pull request into `main`.

## Code conventions

See the "Code conventions" section of [CLAUDE.md](CLAUDE.md) and the authoritative
[constitution](.specify/memory/constitution.md). In short:

- Strict typing (`mypy --strict`) and concise docstrings on public code.
- Functions of at most 40 lines of logic, files of at most 400 lines.
- Test names state scenario and outcome (for example `test_deny_policy_when_action_is_wildcard`).
- Every new output must work with `--format json`, and the JSON schema stays backward compatible.
- Update the README and docs in the same pull request.

## Security rules

- The tool is read-only. Never add a mutating IAM or AWS call. When you add a read call, update "Required AWS
  Permissions" in the README.
- Never commit credentials, real account IDs or real principal names. Use the placeholder account `123456789012`.
- The runtime stays boto3 plus the standard library; any new dependency needs justification.

To report a security issue, see [SECURITY.md](SECURITY.md).

## Review process

- [CODEOWNERS](.github/CODEOWNERS) routes every pull request to the maintainer.
- CI runs on pull requests from outside contributors need maintainer approval before they start.
- Pull requests need all required checks green and maintainer approval.
- Pull requests are squash-merged.
