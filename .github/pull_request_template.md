## Summary

<!-- What does this change and why? -->

## Related issue / spec

<!-- Link the issue and/or specs/NNN-short-name/ directory. -->

## Type of change

- [ ] Bug fix
- [ ] New feature or check
- [ ] Behavior change
- [ ] Documentation
- [ ] CI / tooling / dependencies

## Checklist

- [ ] `ruff check src tests scripts`, `mypy`, `pytest --cov=iam_audit`, `pip-audit -r requirements-dev.txt --strict` and `python scripts/emulator_smoke.py` pass locally
- [ ] Tests added or updated (names state scenario and outcome)
- [ ] README and docs updated
- [ ] No mutating AWS calls added (README "Required AWS Permissions" updated for any new read call)
- [ ] No secrets, real account IDs or real principal names (placeholder account `123456789012` only)
- [ ] `--format json` output stays backward compatible
- [ ] Spec directory added or updated for features
