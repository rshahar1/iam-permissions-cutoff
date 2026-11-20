"""Dormancy analysis: flag principals idle longer than the configured threshold.

A principal with no recorded activity is treated as inactive since its creation, so a
brand-new principal is not reported until it has existed for the whole threshold.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from iam_audit.models import Finding, FindingCategory, IAMRole, IAMUser, Principal, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable

ROLE_TRACKING_WINDOW_DAYS = 400
ROLE_WINDOW_NOTE = (
    "IAM only tracks role activity for about 400 days, so this role may have been "
    "used before that window."
)


def _as_utc(value: datetime) -> datetime:
    """Return ``value`` as an aware datetime, treating naive values as UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _severity(days_inactive: int, threshold_days: int) -> Severity:
    """HIGH from twice the threshold, MEDIUM from the threshold."""
    return Severity.HIGH if days_inactive >= 2 * threshold_days else Severity.MEDIUM


def _has_password(principal: Principal) -> bool:
    """Whether the principal is a user that has used its console password."""
    return isinstance(principal, IAMUser) and principal.password_last_used is not None


def _recommendation(principal: Principal) -> str:
    """Return the standard cleanup recommendation."""
    return f"Delete this {principal.principal_type} or investigate if it is still needed."


def _never_used_finding(principal: Principal, age_days: int, threshold_days: int) -> Finding:
    """Build the finding for a principal with no activity since creation."""
    description = ""
    if isinstance(principal, IAMRole) and age_days > ROLE_TRACKING_WINDOW_DAYS:
        description = ROLE_WINDOW_NOTE
    return Finding(
        principal_arn=principal.arn,
        principal_name=principal.name,
        principal_type=principal.principal_type,
        category=FindingCategory.DORMANCY,
        severity=_severity(age_days, threshold_days),
        title=(
            f"{principal.principal_type} '{principal.name}' has never been used "
            f"(created {age_days} days ago)"
        ),
        description=description,
        recommendation=_recommendation(principal),
        metadata={
            "last_activity": None,
            "days_inactive": age_days,
            "has_password": _has_password(principal),
            "created_days_ago": age_days,
        },
    )


def _inactive_finding(
    principal: Principal, last_activity: datetime, days_inactive: int, threshold_days: int
) -> Finding:
    """Build the finding for a principal whose last activity is too old."""
    return Finding(
        principal_arn=principal.arn,
        principal_name=principal.name,
        principal_type=principal.principal_type,
        category=FindingCategory.DORMANCY,
        severity=_severity(days_inactive, threshold_days),
        title=f"{principal.principal_type} '{principal.name}' unused for {days_inactive} days",
        description="",
        recommendation=_recommendation(principal),
        metadata={
            "last_activity": last_activity.isoformat(),
            "days_inactive": days_inactive,
            "has_password": _has_password(principal),
        },
    )


def analyze_dormancy(
    principals: Iterable[Principal],
    threshold_days: int,
    now: datetime | None = None,
) -> list[Finding]:
    """Return dormancy findings for principals idle for at least ``threshold_days``."""
    current = _as_utc(now) if now is not None else datetime.now(UTC)
    findings: list[Finding] = []

    for principal in principals:
        last_activity = principal.last_activity
        if last_activity is None:
            age_days = (current - _as_utc(principal.created_date)).days
            if age_days >= threshold_days:
                findings.append(_never_used_finding(principal, age_days, threshold_days))
            continue

        last_activity = _as_utc(last_activity)
        days_inactive = (current - last_activity).days
        if days_inactive >= threshold_days:
            findings.append(
                _inactive_finding(principal, last_activity, days_inactive, threshold_days)
            )

    return findings
