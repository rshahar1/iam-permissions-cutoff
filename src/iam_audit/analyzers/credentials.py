"""Credential hygiene rules (CRED-001..CRED-008) over the IAM credential report."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from iam_audit.collectors.credential_report import (
    AccessKeyInfo,
    CredentialReportRow,
    collect_credential_report,
)
from iam_audit.models import Finding, FindingCategory, IAMUser, Severity

if TYPE_CHECKING:
    import argparse
    from collections.abc import Iterable

    from iam_audit.pipeline import AuditContext

DEFAULT_KEY_MAX_AGE_DAYS = 90


@dataclass(frozen=True)
class CredentialRule:
    """Static description of a rule; findings fill in the dynamic parts."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    recommendation: str


@dataclass(frozen=True)
class RuleSettings:
    """Time reference and thresholds shared by all rules."""

    now: datetime
    days: int
    key_max_age: int


RULES: dict[str, CredentialRule] = {
    rule.rule_id: rule
    for rule in (
        CredentialRule(
            "CRED-001", Severity.CRITICAL, "Root account has an active access key",
            "The root user has an active access key. Root keys grant unrestricted access "
            "to the whole account and cannot be limited by IAM policies.",
            "Delete the root access keys and use IAM roles or users with least-privilege "
            "policies instead.",
        ),
        CredentialRule(
            "CRED-002", Severity.CRITICAL, "Root account has no MFA device",
            "The root user does not have multi-factor authentication enabled.",
            "Enable a hardware or virtual MFA device for the root user.",
        ),
        CredentialRule(
            "CRED-003", Severity.MEDIUM, "Root account used recently",
            "The root user signed in with its password within the audit window. "
            "Root should only be used for the few tasks that require it.",
            "Use an IAM role or user for day-to-day work and review why root was used.",
        ),
        CredentialRule(
            "CRED-004", Severity.HIGH, "Console access without MFA",
            "The user has a console password but no MFA device, so a stolen or guessed "
            "password is enough to sign in.",
            "Require this user to enrol an MFA device, or remove the console password.",
        ),
        CredentialRule(
            "CRED-005", Severity.MEDIUM, "Access key not rotated",
            "An active access key has not been rotated within the maximum allowed age.",
            "Create a new access key, switch applications to it and delete the old one.",
        ),
        CredentialRule(
            "CRED-006", Severity.MEDIUM, "Access key never used",
            "An active access key has never been used since it was created.",
            "Deactivate and delete the access key if it is not needed.",
        ),
        CredentialRule(
            "CRED-007", Severity.LOW, "User has two active access keys",
            "Both access key slots are active, which usually means a rotation was never "
            "finished.",
            "Delete or deactivate the access key that is no longer in use.",
        ),
        CredentialRule(
            "CRED-008", Severity.MEDIUM, "Console password never used",
            "The user has a console password that has never been used.",
            "Remove the console password if the user does not need console access.",
        ),
    )
}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _older_than(value: datetime | None, now: datetime, days: int) -> bool:
    return value is not None and now - value > timedelta(days=days)


def _finding(
    row: CredentialReportRow, rule_id: str, title: str | None = None, **metadata: object
) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        principal_arn=row.arn,
        principal_name=row.user,
        principal_type="root" if row.is_root else "user",
        category=FindingCategory.CREDENTIAL,
        severity=rule.severity,
        title=title or rule.title,
        description=rule.description,
        recommendation=rule.recommendation,
        metadata={"rule_id": rule_id, **metadata},
    )


def _root_rules(row: CredentialReportRow, cfg: RuleSettings) -> list[Finding]:
    findings: list[Finding] = []
    active = [key.slot for key in row.active_keys]
    if active:
        findings.append(_finding(row, "CRED-001", active_key_slots=active))
    if not row.mfa_active:
        findings.append(_finding(row, "CRED-002", mfa_active=False))
    last_used = row.password_last_used
    if last_used is not None and not _older_than(last_used, cfg.now, cfg.days):
        findings.append(
            _finding(row, "CRED-003", password_last_used=_iso(last_used), threshold_days=cfg.days)
        )
    return findings


def _key_findings(row: CredentialReportRow, key: AccessKeyInfo, cfg: RuleSettings) -> list[Finding]:
    meta = {
        "key_slot": key.slot,
        "last_rotated": _iso(key.last_rotated),
        "last_used_date": _iso(key.last_used_date),
    }
    findings: list[Finding] = []
    if _older_than(key.last_rotated, cfg.now, cfg.key_max_age):
        title = f"Access key {key.slot} not rotated in over {cfg.key_max_age} days"
        findings.append(_finding(row, "CRED-005", title, **meta, max_age_days=cfg.key_max_age))
    if key.last_used_date is None and _older_than(key.last_rotated, cfg.now, cfg.days):
        title = f"Access key {key.slot} has never been used"
        findings.append(_finding(row, "CRED-006", title, **meta, threshold_days=cfg.days))
    return findings


def _user_rules(row: CredentialReportRow, cfg: RuleSettings) -> list[Finding]:
    findings: list[Finding] = []
    has_password = row.password_enabled is True
    if has_password and not row.mfa_active:
        findings.append(_finding(row, "CRED-004", password_enabled=True, mfa_active=False))
    for key in row.active_keys:
        findings.extend(_key_findings(row, key, cfg))
    if len(row.active_keys) == 2:
        findings.append(_finding(row, "CRED-007", active_key_slots=[1, 2]))
    if (
        has_password
        and row.password_last_used is None
        and _older_than(row.user_creation_time, cfg.now, cfg.days)
    ):
        findings.append(
            _finding(
                row, "CRED-008", password_enabled=True, password_last_used=None,
                user_creation_time=_iso(row.user_creation_time), threshold_days=cfg.days,
            )
        )
    return findings


def analyze_credentials(
    rows: Iterable[CredentialReportRow], now: datetime, days: int, key_max_age: int
) -> list[Finding]:
    """Apply every credential rule to the given report rows."""
    cfg = RuleSettings(now=now, days=days, key_max_age=key_max_age)
    findings: list[Finding] = []
    for row in rows:
        findings.extend(_root_rules(row, cfg) if row.is_root else _user_rules(row, cfg))
    return findings


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Register the credential check's CLI options."""
    parser.add_argument(
        "--key-max-age", type=int, default=DEFAULT_KEY_MAX_AGE_DAYS, metavar="N",
        help="Flag active access keys not rotated in N days (default: 90)",
    )


def _filters_applied(ctx: AuditContext) -> bool:
    options = ctx.options
    return bool(
        getattr(options, "path_prefix", None)
        or getattr(options, "name", None)
        or getattr(options, "tag", None)
    )


def select_rows(
    rows: list[CredentialReportRow], ctx: AuditContext
) -> list[CredentialReportRow]:
    """Keep rows of in-scope users, plus the root row when no principal filter is applied."""
    user_arns = {p.arn for p in ctx.principals if isinstance(p, IAMUser)}
    include_root = not _filters_applied(ctx)
    return [row for row in rows if row.arn in user_arns or (row.is_root and include_root)]


def run(ctx: AuditContext) -> list[Finding]:
    """Check entry point: collect the credential report and evaluate in-scope rows."""
    rows, gaps = collect_credential_report(ctx.iam_client)
    ctx.data_gaps.extend(gaps)
    scoped = select_rows(rows, ctx)
    key_max_age = getattr(ctx.options, "key_max_age", DEFAULT_KEY_MAX_AGE_DAYS)
    return analyze_credentials(scoped, ctx.now, ctx.options.days, key_max_age)
