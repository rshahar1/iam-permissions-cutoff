from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from iam_audit.models import (
    Finding,
    FindingCategory,
    IAMUser,
    PolicyStatement,
    Principal,
    Severity,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

_ALL_ACTIONS = frozenset({"*", "*:*"})


class _PolicyEntry(NamedTuple):
    """A single statement together with the policy it came from."""

    policy_name: str
    policy_type: str
    is_aws_managed: bool
    statement: PolicyStatement


def _is_service_wildcard(action: str) -> bool:
    parts = action.split(":", 1)
    return len(parts) == 2 and parts[1] == "*"


def _is_wildcardish_action(action: str) -> bool:
    parts = action.split(":", 1)
    if len(parts) != 2:
        return False
    return "*" in parts[1] or "?" in parts[1]


def _grants_all_actions(statement: PolicyStatement) -> bool:
    """True when any action element is a full wildcard ("*" or "*:*")."""
    return any(a in _ALL_ACTIONS for a in statement.actions)


def _applies_to_all_resources(statement: PolicyStatement) -> bool:
    """True when any resource is "*" or the statement uses NotResource (all-except)."""
    return "*" in statement.resources or bool(statement.not_resources)


def _classify_statement(statement: PolicyStatement) -> Severity | None:
    """Return the risk severity of an Allow statement, or None if it is not overly permissive."""
    if statement.effect != "Allow":
        return None
    actions = statement.actions
    resources_all = _applies_to_all_resources(statement)
    if _grants_all_actions(statement):
        return Severity.CRITICAL if resources_all else Severity.HIGH
    if statement.not_actions:
        return Severity.HIGH if resources_all else Severity.MEDIUM
    if any(_is_service_wildcard(a) for a in actions):
        return Severity.HIGH
    if resources_all and len(actions) > 5:
        return Severity.HIGH
    if resources_all and len(actions) > 1:
        return Severity.MEDIUM
    if any(_is_wildcardish_action(a) for a in actions):
        return Severity.MEDIUM
    return None


def _recommendation_for_severity(severity: Severity) -> str:
    if severity == Severity.CRITICAL:
        return (
            "Remove this policy or replace with least-privilege permissions. "
            "Action '*' and Resource '*' grants full access."
        )
    if severity == Severity.HIGH:
        return (
            "Restrict permissions: use specific actions instead of service wildcards "
            "(e.g. s3:*), and scope resources to specific ARNs where possible."
        )
    if severity == Severity.MEDIUM:
        return (
            "Review and narrow permissions: prefer specific actions over wildcards "
            "and restrict resources to required ARNs."
        )
    return ""


def _recommendation_for(entry: _PolicyEntry, severity: Severity) -> str:
    """Build a recommendation tailored to the statement shape and policy ownership."""
    if entry.statement.not_actions:
        base = (
            "Replace NotAction with an explicit allow-list of the actions this principal needs: "
            "NotAction grants every action not listed, including future AWS actions."
        )
    else:
        base = _recommendation_for_severity(severity)
    if entry.is_aws_managed:
        base += (
            " This is an AWS-managed policy and cannot be edited: detach it and attach a "
            "customer-managed least-privilege policy instead."
        )
    return base


def _iterate_policies(principal: Principal) -> Iterable[_PolicyEntry]:
    for ap in principal.attached_policies:
        for stmt in ap.document.statements:
            yield _PolicyEntry(ap.name, "managed", ap.is_aws_managed, stmt)
    for ip in principal.inline_policies:
        for stmt in ip.document.statements:
            yield _PolicyEntry(ip.name, "inline", False, stmt)
    if isinstance(principal, IAMUser):
        for gp in principal.group_policies:
            for stmt in gp.document.statements:
                yield _PolicyEntry(gp.name, "group", gp.is_aws_managed, stmt)


def _has_deny_statements(policies: list[_PolicyEntry]) -> bool:
    return any(entry.statement.effect == "Deny" for entry in policies)


def _no_policies_finding(principal: Principal) -> Finding:
    return Finding(
        principal_arn=principal.arn,
        principal_name=principal.name,
        principal_type=principal.principal_type,
        category=FindingCategory.PERMISSION,
        severity=Severity.LOW,
        title="Principal has no policies attached",
        description="",
        recommendation=(
            "Attach appropriate policies or add inline policies "
            "if this principal should have access."
        ),
        metadata={},
    )


def _statement_finding(
    principal: Principal, entry: _PolicyEntry, severity: Severity, deny_present: bool
) -> Finding:
    stmt = entry.statement
    meta: dict[str, object] = {
        "policy_name": entry.policy_name,
        "policy_type": entry.policy_type,
        "policy_is_aws_managed": entry.is_aws_managed,
        "statement_sid": stmt.sid,
        "actions": stmt.actions,
        "resources": stmt.resources,
        "not_actions": stmt.not_actions,
        "not_resources": stmt.not_resources,
        "has_deny_statements": deny_present,
    }
    description = (
        "Note: this principal also has Deny statements that may restrict effective permissions."
        if deny_present
        else ""
    )
    return Finding(
        principal_arn=principal.arn,
        principal_name=principal.name,
        principal_type=principal.principal_type,
        category=FindingCategory.PERMISSION,
        severity=severity,
        title=f"Overly permissive policy: {entry.policy_name}",
        description=description,
        recommendation=_recommendation_for(entry, severity),
        metadata=meta,
    )


def analyze_permissions(principals: Iterable[Principal]) -> list[Finding]:
    """Flag overly permissive Allow statements across managed, inline and group policies."""
    findings: list[Finding] = []
    for principal in principals:
        policies = list(_iterate_policies(principal))
        if not policies:
            findings.append(_no_policies_finding(principal))
            continue
        deny_present = _has_deny_statements(policies)
        for entry in policies:
            severity = _classify_statement(entry.statement)
            if severity is not None:
                findings.append(_statement_finding(principal, entry, severity, deny_present))
    return findings
