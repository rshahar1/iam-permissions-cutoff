from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from iam_audit.models import Finding, FindingCategory, IAMUser, Principal, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable


def analyze_dormancy(principals: Iterable[Principal], threshold_days: int) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(UTC)

    for principal in principals:
        last_activity = principal.last_activity
        has_password = (
            isinstance(principal, IAMUser) and principal.password_last_used is not None
        )

        if last_activity is None:
            findings.append(
                Finding(
                    principal_arn=principal.arn,
                    principal_name=principal.name,
                    principal_type=principal.principal_type,
                    category=FindingCategory.DORMANCY,
                    severity=Severity.HIGH,
                    title=f"{principal.principal_type} '{principal.name}' has never been used",
                    description="",
                    recommendation=(
                        f"Delete this unused {principal.principal_type} or investigate "
                        "if it is still needed."
                    ),
                    metadata={
                        "last_activity": None,
                        "days_inactive": None,
                        "has_password": has_password,
                    },
                )
            )
            continue

        if last_activity.tzinfo is None:
            last_activity = last_activity.replace(tzinfo=UTC)
        days_inactive = (now - last_activity).days
        if days_inactive < threshold_days:
            continue

        severity = (
            Severity.HIGH
            if days_inactive >= 2 * threshold_days
            else Severity.MEDIUM
        )
        findings.append(
            Finding(
                principal_arn=principal.arn,
                principal_name=principal.name,
                principal_type=principal.principal_type,
                category=FindingCategory.DORMANCY,
                severity=severity,
                title=f"{principal.principal_type} '{principal.name}' unused for {days_inactive} days",
                description="",
                recommendation=(
                    f"Delete this {principal.principal_type} or investigate "
                    "if it is still needed."
                ),
                metadata={
                    "last_activity": last_activity.isoformat(),
                    "days_inactive": days_inactive,
                    "has_password": has_password,
                },
            )
        )

    return findings
