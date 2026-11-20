"""Rule-level tests for the privilege-escalation analyzer: one scenario per rule and grant shape."""

from __future__ import annotations

import pytest

from iam_audit.analyzers.privesc import RULES, analyze_privilege_escalation
from iam_audit.models import (
    AttachedPolicy,
    FindingCategory,
    IAMUser,
    InlinePolicy,
    PolicyDocument,
    PolicyStatement,
    Principal,
    Severity,
)
from tests.conftest import make_role, make_user


def _allow(actions: list[str], resources: list[str] | None = None, **kwargs: object) -> PolicyStatement:
    return PolicyStatement(
        effect="Allow", actions=actions, resources=resources if resources is not None else ["*"], **kwargs  # type: ignore[arg-type]
    )


def _deny(actions: list[str], conditions: dict | None = None, **kwargs: object) -> PolicyStatement:  # type: ignore[type-arg]
    return PolicyStatement(
        effect="Deny", actions=actions, resources=["*"], conditions=conditions, **kwargs  # type: ignore[arg-type]
    )


def _role_with(*statements: PolicyStatement, policy_name: str = "pol") -> Principal:
    role = make_role()
    role.inline_policies = [InlinePolicy(policy_name, PolicyDocument("2012-10-17", list(statements)))]
    return role


def _rule_ids(principal: Principal) -> set[str]:
    return {str(f.metadata["rule_id"]) for f in analyze_privilege_escalation([principal])}


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.rule_id)
def test_rule_fires_when_exactly_its_required_actions_are_granted_on_all_resources(rule) -> None:  # type: ignore[no-untyped-def]
    findings = analyze_privilege_escalation([_role_with(_allow(list(rule.required_actions)))])
    matched = [f for f in findings if f.metadata["rule_id"] == rule.rule_id]
    assert len(matched) == 1
    finding = matched[0]
    assert finding.category is FindingCategory.PRIVILEGE_ESCALATION
    assert finding.severity is rule.severity
    assert finding.title == f"Privilege escalation path: {rule.name}"
    assert finding.metadata["matched_actions"] == list(rule.required_actions)
    assert finding.metadata["granting_policies"] == ["pol"]
    assert finding.metadata["rule_name"] == rule.name
    assert finding.recommendation


@pytest.mark.parametrize(
    "rule", [r for r in RULES if len(r.required_actions) > 1], ids=lambda r: r.rule_id
)
def test_multi_action_rule_does_not_fire_when_one_required_action_is_missing(rule) -> None:  # type: ignore[no-untyped-def]
    for missing in rule.required_actions:
        granted = [a for a in rule.required_actions if a != missing]
        assert rule.rule_id not in _rule_ids(_role_with(_allow(granted)))


def test_rule_table_has_unique_ids_and_expected_severities() -> None:
    ids = [r.rule_id for r in RULES]
    assert ids == [f"PE-{n:03d}" for n in range(1, 25)]
    by_id = {r.rule_id: r.severity for r in RULES}
    assert by_id["PE-001"] is Severity.CRITICAL
    assert by_id["PE-002"] is Severity.HIGH
    assert by_id["PE-024"] is Severity.MEDIUM


@pytest.mark.parametrize(
    ("actions", "expected_subset"),
    [
        (["iam:*"], {"PE-001", "PE-003", "PE-008", "PE-010", "PE-011"}),
        (["iam:Put*"], {"PE-006", "PE-007", "PE-008"}),
        (["IAM:putrolepolicy"], {"PE-008"}),
        (["iam:Create?ccessKey"], {"PE-011"}),
        (["sts:Assume*"], {"PE-024"}),
        (["ssm:S*"], {"PE-022", "PE-023"}),
    ],
)
def test_wildcard_action_grants_fire_matching_rules(actions: list[str], expected_subset: set[str]) -> None:
    assert expected_subset <= _rule_ids(_role_with(_allow(actions)))


def test_iam_put_wildcard_does_not_fire_attach_rules() -> None:
    ids = _rule_ids(_role_with(_allow(["iam:Put*"])))
    assert ids == {"PE-006", "PE-007", "PE-008"}


def test_passrole_wildcard_plus_run_instances_fires_pe_014_only() -> None:
    ids = _rule_ids(_role_with(_allow(["iam:Pass*", "ec2:Run*"])))
    assert ids == {"PE-014"}


@pytest.mark.parametrize(
    "statement",
    [
        _allow(["iam:PutRolePolicy"], ["arn:aws:iam::123456789012:role/one"]),
        _allow(["iam:PutRolePolicy"], []),
    ],
    ids=["scoped-resource", "no-resource"],
)
def test_scoped_resource_grant_does_not_fire(statement: PolicyStatement) -> None:
    assert _rule_ids(_role_with(statement)) == set()


def test_not_resource_allow_counts_as_all_resources() -> None:
    stmt = _allow(["iam:PutRolePolicy"], [], not_resources=["arn:aws:iam::123456789012:role/protected"])
    assert _rule_ids(_role_with(stmt)) == {"PE-008"}


def test_deny_on_all_resources_suppresses_matching_rule() -> None:
    principal = _role_with(_allow(["iam:*"]), _deny(["iam:PutRolePolicy"]))
    ids = _rule_ids(principal)
    assert "PE-008" not in ids
    assert "PE-006" in ids


def test_deny_wildcard_suppresses_all_matching_rules() -> None:
    assert _rule_ids(_role_with(_allow(["iam:*"]), _deny(["iam:*"]))) == set()


def test_deny_with_condition_does_not_suppress() -> None:
    deny = _deny(["iam:PutRolePolicy"], conditions={"Bool": {"aws:MultiFactorAuthPresent": "false"}})
    assert "PE-008" in _rule_ids(_role_with(_allow(["iam:*"]), deny))


def test_deny_scoped_to_specific_resource_does_not_suppress() -> None:
    deny = PolicyStatement("Deny", ["iam:PutRolePolicy"], ["arn:aws:iam::123456789012:role/x"])
    assert "PE-008" in _rule_ids(_role_with(_allow(["iam:*"]), deny))


def test_deny_on_one_required_action_suppresses_multi_action_rule() -> None:
    principal = _role_with(_allow(["iam:PassRole", "ec2:RunInstances"]), _deny(["ec2:RunInstances"]))
    assert _rule_ids(principal) == set()


def test_not_action_allow_grants_actions_not_excluded() -> None:
    ids = _rule_ids(_role_with(_allow([], not_actions=["iam:PutRolePolicy", "s3:*"])))
    assert "PE-008" not in ids
    assert {"PE-006", "PE-022", "PE-024"} <= ids


def test_not_action_deny_suppresses_everything_except_listed_actions() -> None:
    deny = _deny([], not_actions=["sts:AssumeRole"])
    assert _rule_ids(_role_with(_allow(["iam:*", "sts:*"]), deny)) == {"PE-024"}


def test_full_admin_principal_yields_no_findings() -> None:
    assert _rule_ids(_role_with(_allow(["*"]))) == set()


def test_admin_with_unconditional_deny_is_still_evaluated() -> None:
    ids = _rule_ids(_role_with(_allow(["*"]), _deny(["iam:*"])))
    assert "PE-008" not in ids
    assert {"PE-022", "PE-024"} <= ids


def test_principal_without_policies_yields_no_findings() -> None:
    assert analyze_privilege_escalation([make_role()]) == []


def test_allow_with_condition_still_counts_as_granted() -> None:
    stmt = _allow(["iam:PutRolePolicy"], conditions={"StringEquals": {"aws:RequestedRegion": "us-east-1"}})
    assert _rule_ids(_role_with(stmt)) == {"PE-008"}


def test_grants_split_across_policies_combine_and_list_both_policies() -> None:
    role = make_role()
    doc = lambda a: PolicyDocument("2012-10-17", [_allow([a])])  # noqa: E731
    role.attached_policies = [AttachedPolicy("arn:aws:iam::aws:policy/p", "managed-pass", True, doc("iam:PassRole"))]
    role.inline_policies = [InlinePolicy("inline-run", doc("ec2:RunInstances"))]
    findings = analyze_privilege_escalation([role])
    assert [f.metadata["rule_id"] for f in findings] == ["PE-014"]
    assert findings[0].metadata["granting_policies"] == ["inline-run", "managed-pass"]


def test_group_policy_grant_is_attributed_to_the_group_policy_name() -> None:
    user: IAMUser = make_user()
    user.group_policies = [
        AttachedPolicy("arn:aws:iam::123456789012:policy/g", "group-pol", False,
                       PolicyDocument("2012-10-17", [_allow(["iam:AttachUserPolicy"])]))
    ]
    findings = analyze_privilege_escalation([user])
    assert [f.metadata["rule_id"] for f in findings] == ["PE-003"]
    assert findings[0].metadata["granting_policies"] == ["group-pol"]
    assert findings[0].principal_type == "user"


def test_group_policy_deny_suppresses_user_allow() -> None:
    user: IAMUser = make_user()
    user.inline_policies = [InlinePolicy("allow", PolicyDocument("2012-10-17", [_allow(["iam:AttachUserPolicy"])]))]
    user.group_policies = [
        AttachedPolicy("arn:aws:iam::123456789012:policy/g", "deny", False,
                       PolicyDocument("2012-10-17", [_deny(["iam:AttachUserPolicy"])]))
    ]
    assert analyze_privilege_escalation([user]) == []
