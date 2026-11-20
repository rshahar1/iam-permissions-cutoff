from __future__ import annotations

import importlib.resources
import json
import logging
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, NamedTuple

from iam_audit.models import Finding, FindingCategory, IAMUser, Severity

if TYPE_CHECKING:
    from iam_audit.models import PolicyStatement, Principal, ServiceLastAccessedRecord

SENSITIVE_SERVICES: frozenset[str] = frozenset(
    {"iam", "kms", "sts", "organizations", "secretsmanager"}
)

_ALL_ACTIONS = frozenset({"*", "*:*"})

TRACKED_ONLY_NOTE = "Only actions tracked by AWS Access Advisor are assessed."

logger = logging.getLogger(__name__)


class ServiceGrant(NamedTuple):
    """Action-name glob patterns one statement allows within a single service.

    Patterns are lowercased because IAM action names are case-insensitive.
    ``exclude`` holds patterns removed by a NotAction element.
    """

    include: frozenset[str]
    exclude: frozenset[str] = frozenset()

    def matches(self, action_name: str) -> bool:
        """Return True if this grant allows ``action_name`` (e.g. "GetObject")."""
        name = action_name.lower()
        if not any(fnmatchcase(name, pattern) for pattern in self.include):
            return False
        return not any(fnmatchcase(name, pattern) for pattern in self.exclude)


class _UsageResult(NamedTuple):
    unused: list[str]
    keep: list[str]
    last_accessed: str | None
    granularity: str


def load_actions_map() -> dict[str, list[str]]:
    """Load the bundled service → known-actions catalog."""
    data = (
        importlib.resources.files("iam_audit") / "data" / "iam_actions.json"
    ).read_text()
    result: dict[str, list[str]] = json.loads(data)
    return result


def _split_by_service(patterns: list[str]) -> dict[str, set[str]]:
    """Group "service:action" patterns into lowercased action patterns per service."""
    result: dict[str, set[str]] = {}
    for pattern in patterns:
        parts = pattern.split(":", 1)
        if len(parts) == 2:
            # IAM wildcards are only "*" and "?": escape "[" so fnmatch treats it literally.
            action_pattern = parts[1].lower().replace("[", "[[]")
            result.setdefault(parts[0].lower(), set()).add(action_pattern)
    return result


def _grants_for_statement(
    stmt: PolicyStatement, known_services: list[str]
) -> dict[str, ServiceGrant]:
    """Translate one Allow statement (Action or NotAction form) into per-service grants."""
    grants: dict[str, ServiceGrant] = {}
    if any(a in _ALL_ACTIONS for a in stmt.actions):
        return {svc: ServiceGrant(frozenset({"*"})) for svc in known_services}
    for service, patterns in _split_by_service(stmt.actions).items():
        grants[service] = ServiceGrant(frozenset(patterns))
    if stmt.not_actions and not any(a in _ALL_ACTIONS for a in stmt.not_actions):
        excluded = _split_by_service(stmt.not_actions)
        for service in known_services:
            service_excluded = excluded.get(service, set())
            if "*" not in service_excluded:
                grants[service] = ServiceGrant(frozenset({"*"}), frozenset(service_excluded))
    return grants


def _extract_service_grants(
    principal: Principal, actions_map: dict[str, list[str]] | None = None
) -> dict[str, list[ServiceGrant]]:
    """Collect every Allow grant of a principal, keyed by lowercased service namespace."""
    known_services = list(actions_map or {})
    policies = list(principal.attached_policies) + list(principal.inline_policies)
    if isinstance(principal, IAMUser):
        policies += list(principal.group_policies)

    result: dict[str, list[ServiceGrant]] = {}
    for policy in policies:
        for stmt in policy.document.statements:
            if stmt.effect != "Allow":
                continue
            for service, grant in _grants_for_statement(stmt, known_services).items():
                result.setdefault(service, []).append(grant)
    return result


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _compare_tracked_actions(
    grants: list[ServiceGrant], access_record: ServiceLastAccessedRecord, cutoff: datetime
) -> _UsageResult | None:
    """Compare granted actions with Access Advisor's tracked actions (untracked ones are skipped)."""
    used: set[str] = set()
    unused: set[str] = set()
    last_accessed: datetime | None = None
    for tracked in access_record.tracked_actions or []:
        if not any(g.matches(tracked.action_name) for g in grants):
            continue
        accessed_at = _ensure_utc(tracked.last_accessed_time)
        if accessed_at and accessed_at >= cutoff:
            used.add(tracked.action_name)
            if last_accessed is None or accessed_at > last_accessed:
                last_accessed = accessed_at
        else:
            unused.add(tracked.action_name)
    if not unused:
        return None
    last_str = last_accessed.isoformat() if last_accessed else None
    return _UsageResult(sorted(unused), sorted(used), last_str, "ACTION_LEVEL")


def _compare_service_usage(
    grants: list[ServiceGrant],
    access_record: ServiceLastAccessedRecord,
    threshold_days: int,
) -> _UsageResult | None:
    cutoff = datetime.now(UTC) - timedelta(days=threshold_days)
    if access_record.tracked_actions:
        return _compare_tracked_actions(grants, access_record, cutoff)

    last_auth = _ensure_utc(access_record.last_authenticated)
    if last_auth and last_auth >= cutoff:
        return None
    return _UsageResult([], [], last_auth.isoformat() if last_auth else None, "SERVICE_LEVEL")


def _severity_for_unused(
    service: str, unused_actions: list[str], granularity: str
) -> Severity:
    if service in SENSITIVE_SERVICES:
        return Severity.HIGH
    if granularity == "SERVICE_LEVEL":
        return Severity.MEDIUM
    if len(unused_actions) <= 2:
        return Severity.LOW
    return Severity.MEDIUM


def _never_accessed_finding(principal: Principal, service: str) -> Finding:
    return Finding(
        principal_arn=principal.arn,
        principal_name=principal.name,
        principal_type=principal.principal_type,
        category=FindingCategory.UNUSED_PERMISSION,
        severity=_severity_for_unused(service, [], "SERVICE_LEVEL"),
        title=f"Unused service access: {service}",
        description=f"Principal has permissions for {service} but has never accessed it.",
        recommendation=f"Remove unused {service} permissions from policies.",
        metadata={
            "service_namespace": service,
            "unused_actions": None,
            "keep_actions": None,
            "last_accessed": None,
            "granularity": "SERVICE_LEVEL",
        },
    )


def _usage_finding(principal: Principal, service: str, usage: _UsageResult) -> Finding:
    action_level = usage.granularity == "ACTION_LEVEL"
    unused = usage.unused
    title_suffix = f": {', '.join(unused[:5])}{'...' if len(unused) > 5 else ''}" if unused else ""
    description = f"Principal has {len(unused) if unused else 'service'} unused permission(s) for {service}."
    if action_level:
        description += f" {TRACKED_ONLY_NOTE}"
    return Finding(
        principal_arn=principal.arn,
        principal_name=principal.name,
        principal_type=principal.principal_type,
        category=FindingCategory.UNUSED_PERMISSION,
        severity=_severity_for_unused(service, unused, usage.granularity),
        title=f"Unused {service} permissions{title_suffix}",
        description=description,
        recommendation=f"Remove unused {service} permissions from policies.",
        metadata={
            "service_namespace": service,
            "granularity": usage.granularity,
            "last_accessed": usage.last_accessed,
            "unused_actions": unused if action_level else None,
            "keep_actions": usage.keep if action_level else None,
        },
    )


def analyze_unused_permissions(
    principals: list[Principal],
    access_data: dict[str, list[ServiceLastAccessedRecord]],
    threshold_days: int,
    data_gap_arns: set[str] | None = None,
) -> list[Finding]:
    """Report granted permissions not used within ``threshold_days`` per Access Advisor."""
    data_gap_arns = data_gap_arns or set()
    actions_map = load_actions_map()
    findings: list[Finding] = []

    for principal in principals:
        if principal.arn in data_gap_arns:
            continue
        records = access_data.get(principal.arn, [])
        access_by_service = {r.service_namespace.lower(): r for r in records}

        for service, grants in _extract_service_grants(principal, actions_map).items():
            access_record = access_by_service.get(service)
            if access_record is None:
                findings.append(_never_accessed_finding(principal, service))
                continue
            usage = _compare_service_usage(grants, access_record, threshold_days)
            if usage is not None:
                findings.append(_usage_finding(principal, service, usage))

    return findings
