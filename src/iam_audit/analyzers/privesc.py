"""Privilege-escalation detection from the effective grants of each principal.

An action counts as granted only through an ``Allow`` statement that applies to all
resources (``"*"`` in Resource, or any NotResource), via ``Action`` patterns or
``NotAction``. A ``Deny`` removes it only when it lists ``"*"`` as a resource and has no
Condition. Grants scoped to specific resources are intentionally ignored (documented
limitation); permission boundaries, SCPs and Allow-statement conditions are not evaluated.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from iam_audit.analyzers.grants import statement_covers_action
from iam_audit.analyzers.permissions import _applies_to_all_resources, _grants_all_actions
from iam_audit.models import Finding, FindingCategory, IAMUser, Severity

if TYPE_CHECKING:
    from iam_audit.models import PolicyStatement, Principal
    from iam_audit.pipeline import AuditContext


class PrivescRule(NamedTuple):
    """One escalation technique: every action in ``required_actions`` must be granted."""

    rule_id: str
    name: str
    severity: Severity
    required_actions: tuple[str, ...]
    description: str
    recommendation: str


_C, _H, _M = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM
_PASS = "iam:PassRole"
_REC_SCOPE = "Remove this permission or scope it to specific resources with a Condition, and restrict who can use it."
_REC_PASS = "Scope iam:PassRole to specific role ARNs and add an iam:PassedToService condition."

RULES: tuple[PrivescRule, ...] = (
    PrivescRule(
        "PE-001", "Create a new policy version", _C, ("iam:CreatePolicyVersion",),
        "Can rewrite a managed policy attached to the principal itself to grant any permission.",
        "Remove iam:CreatePolicyVersion or restrict it to policies not attached to the principal.",
    ),
    PrivescRule(
        "PE-002", "Set the default policy version", _H, ("iam:SetDefaultPolicyVersion",),
        "Can switch a managed policy to an older, more permissive version.",
        "Remove iam:SetDefaultPolicyVersion or delete unused permissive policy versions.",
    ),
    PrivescRule(
        "PE-003", "Attach a policy to a user", _C, ("iam:AttachUserPolicy",),
        "Can attach any managed policy (e.g. AdministratorAccess) to a user, including itself.", _REC_SCOPE,
    ),
    PrivescRule(
        "PE-004", "Attach a policy to a group", _C, ("iam:AttachGroupPolicy",),
        "Can attach any managed policy to a group the principal belongs to.", _REC_SCOPE,
    ),
    PrivescRule(
        "PE-005", "Attach a policy to a role", _C, ("iam:AttachRolePolicy",),
        "Can attach any managed policy to a role the principal can assume.", _REC_SCOPE,
    ),
    PrivescRule(
        "PE-006", "Put an inline policy on a user", _C, ("iam:PutUserPolicy",),
        "Can write an arbitrary inline policy on a user, including itself.", _REC_SCOPE,
    ),
    PrivescRule(
        "PE-007", "Put an inline policy on a group", _C, ("iam:PutGroupPolicy",),
        "Can write an arbitrary inline policy on a group the principal belongs to.", _REC_SCOPE,
    ),
    PrivescRule(
        "PE-008", "Put an inline policy on a role", _C, ("iam:PutRolePolicy",),
        "Can write an arbitrary inline policy on a role the principal can assume.", _REC_SCOPE,
    ),
    PrivescRule(
        "PE-009", "Add a user to a group", _H, ("iam:AddUserToGroup",),
        "Can add itself to a more privileged group.",
        "Restrict iam:AddUserToGroup to specific group ARNs.",
    ),
    PrivescRule(
        "PE-010", "Update a role trust policy", _C, ("iam:UpdateAssumeRolePolicy",),
        "Can change who may assume any role and then assume a privileged role.",
        "Remove iam:UpdateAssumeRolePolicy or scope it to specific role ARNs.",
    ),
    PrivescRule(
        "PE-011", "Create access keys for other users", _H, ("iam:CreateAccessKey",),
        "Can mint credentials for another, more privileged user.",
        "Scope iam:CreateAccessKey to the principal's own user (${aws:username}).",
    ),
    PrivescRule(
        "PE-012", "Create a console password for a user", _H, ("iam:CreateLoginProfile",),
        "Can set a console password for a privileged user that has none.",
        "Remove iam:CreateLoginProfile or scope it to specific users.",
    ),
    PrivescRule(
        "PE-013", "Reset a console password", _H, ("iam:UpdateLoginProfile",),
        "Can reset the console password of a privileged user.",
        "Remove iam:UpdateLoginProfile or scope it to the principal's own user.",
    ),
    PrivescRule(
        "PE-014", "Pass a role to a new EC2 instance", _H, (_PASS, "ec2:RunInstances"),
        "Can launch an instance with a privileged instance profile and read its credentials.", _REC_PASS,
    ),
    PrivescRule(
        "PE-015", "Pass a role to a new Lambda function", _H, (_PASS, "lambda:CreateFunction"),
        "Can create a function that runs with a privileged role.", _REC_PASS,
    ),
    PrivescRule(
        "PE-016", "Overwrite Lambda function code", _H, ("lambda:UpdateFunctionCode",),
        "Can replace the code of an existing function and run as its role.",
        "Scope lambda:UpdateFunctionCode to specific functions.",
    ),
    PrivescRule(
        "PE-017", "Pass a role to a new CloudFormation stack", _H, (_PASS, "cloudformation:CreateStack"),
        "Can create a stack that provisions resources using a privileged role.", _REC_PASS,
    ),
    PrivescRule(
        "PE-018", "Pass a role to a new CodeBuild project", _H, (_PASS, "codebuild:CreateProject"),
        "Can create a build project that runs arbitrary commands as a privileged role.", _REC_PASS,
    ),
    PrivescRule(
        "PE-019", "Pass a role to a new ECS task", _H, (_PASS, "ecs:RegisterTaskDefinition", "ecs:RunTask"),
        "Can register and run a task whose task role is privileged.", _REC_PASS,
    ),
    PrivescRule(
        "PE-020", "Pass a role to a new Glue dev endpoint", _H, (_PASS, "glue:CreateDevEndpoint"),
        "Can create a dev endpoint with a privileged role and open a shell on it.", _REC_PASS,
    ),
    PrivescRule(
        "PE-021", "Update a Glue dev endpoint", _H, ("glue:UpdateDevEndpoint",),
        "Can add an SSH key to an existing dev endpoint and use its role.",
        "Remove glue:UpdateDevEndpoint or scope it to specific endpoints.",
    ),
    PrivescRule(
        "PE-022", "Run commands through SSM", _H, ("ssm:SendCommand",),
        "Can run commands on managed instances and use their instance roles.",
        "Scope ssm:SendCommand to specific instances and documents.",
    ),
    PrivescRule(
        "PE-023", "Start SSM sessions", _H, ("ssm:StartSession",),
        "Can open a shell on managed instances and use their instance roles.",
        "Scope ssm:StartSession to specific instances.",
    ),
    PrivescRule(
        "PE-024", "Assume any role", _M, ("sts:AssumeRole",),
        "Can assume any role whose trust policy trusts this account.",
        "Scope sts:AssumeRole to specific role ARNs.",
    ),
)


class _Source(NamedTuple):
    """A statement together with the name of the policy it came from."""

    policy_name: str
    statement: PolicyStatement


def _sources(principal: Principal) -> list[_Source]:
    """Statements of managed, inline and (for users) group policies."""
    sources = [_Source(p.name, s) for p in principal.attached_policies for s in p.document.statements]
    sources += [_Source(p.name, s) for p in principal.inline_policies for s in p.document.statements]
    if isinstance(principal, IAMUser):
        sources += [_Source(p.name, s) for p in principal.group_policies for s in p.document.statements]
    return sources


def _is_effective_deny(statement: PolicyStatement) -> bool:
    """An unconditional Deny that explicitly lists "*" as a resource always applies."""
    return statement.effect == "Deny" and "*" in statement.resources and not statement.conditions


def _granting_policies(sources: list[_Source], action: str) -> set[str]:
    """Names of policies granting ``action`` on all resources; empty if denied or not granted."""
    if any(_is_effective_deny(s.statement) and statement_covers_action(s.statement, action) for s in sources):
        return set()
    return {
        s.policy_name
        for s in sources
        if s.statement.effect == "Allow"
        and _applies_to_all_resources(s.statement)
        and statement_covers_action(s.statement, action)
    }


def _is_full_admin(sources: list[_Source]) -> bool:
    """True if the principal has Allow * on all resources and no unconditional Deny narrows it."""
    has_allow = any(
        s.statement.effect == "Allow" and _grants_all_actions(s.statement) and _applies_to_all_resources(s.statement)
        for s in sources
    )
    return has_allow and not any(_is_effective_deny(s.statement) for s in sources)


def _match_rule(sources: list[_Source], rule: PrivescRule, cache: dict[str, set[str]]) -> set[str] | None:
    """Return the granting policy names if every required action is granted, else None."""
    policies: set[str] = set()
    for action in rule.required_actions:
        if action not in cache:
            cache[action] = _granting_policies(sources, action)
        if not cache[action]:
            return None
        policies |= cache[action]
    return policies


def _finding(principal: Principal, rule: PrivescRule, policies: set[str]) -> Finding:
    return Finding(
        principal_arn=principal.arn,
        principal_name=principal.name,
        principal_type=principal.principal_type,
        category=FindingCategory.PRIVILEGE_ESCALATION,
        severity=rule.severity,
        title=f"Privilege escalation path: {rule.name}",
        description=rule.description,
        recommendation=rule.recommendation,
        metadata={
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "matched_actions": list(rule.required_actions),
            "granting_policies": sorted(policies),
        },
    )


def analyze_privilege_escalation(principals: list[Principal]) -> list[Finding]:
    """Return one finding per principal per escalation rule fully granted on all resources."""
    findings: list[Finding] = []
    for principal in principals:
        sources = _sources(principal)
        if not sources or _is_full_admin(sources):
            continue
        cache: dict[str, set[str]] = {}
        for rule in RULES:
            policies = _match_rule(sources, rule, cache)
            if policies is not None:
                findings.append(_finding(principal, rule, policies))
    return findings


def run(ctx: AuditContext) -> list[Finding]:
    """Pipeline entry point for the ``privesc`` check."""
    return analyze_privilege_escalation(ctx.principals)
