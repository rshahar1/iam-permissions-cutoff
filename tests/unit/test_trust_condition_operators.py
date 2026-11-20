"""Only condition operators that actually constrain a key may suppress trust findings."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from iam_audit.analyzers.trust import analyze_role_trust, is_constraining_operator
from iam_audit.collectors.policies import _parse_policy_document
from iam_audit.models import Finding, IAMRole

ACCOUNT = "123456789012"
OTHER = "999988887777"
GH = "token.actions.githubusercontent.com"
GH_ARN = f"arn:aws:iam::{ACCOUNT}:oidc-provider/{GH}"

NON_CONSTRAINING = [
    "StringNotEquals", "StringNotLike", "ArnNotEquals", "ArnNotLike",
    "ForAnyValue:StringNotLike", "Null", "StringEqualsIfExists", "StringLikeIfExists",
]
CONSTRAINING = ["StringEquals", "StringLike", "ArnEquals", "ArnLike", "ForAnyValue:StringLike"]


def _ids(statement: dict[str, object]) -> list[str]:
    doc = _parse_policy_document({"Version": "2012-10-17", "Statement": [statement]})
    role = IAMRole(
        arn=f"arn:aws:iam::{ACCOUNT}:role/r", name="r", path="/",
        created_date=datetime(2025, 1, 1, tzinfo=UTC), trust_policy=doc,
    )
    findings: list[Finding] = analyze_role_trust(role, ACCOUNT, frozenset())
    return [str(f.metadata["rule_id"]) for f in findings]


@pytest.mark.parametrize("operator", CONSTRAINING)
def test_constraining_operators_are_recognised(operator: str) -> None:
    assert is_constraining_operator(operator)


@pytest.mark.parametrize("operator", NON_CONSTRAINING)
def test_negated_null_and_ifexists_operators_are_not_constraining(operator: str) -> None:
    assert not is_constraining_operator(operator)


@pytest.mark.parametrize("operator", NON_CONSTRAINING)
def test_trust_001_still_fires_when_restricting_key_uses_non_constraining_operator(operator: str) -> None:
    statement = {
        "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "*"},
        "Condition": {operator: {"aws:PrincipalOrgID": "o-abc"}},
    }
    assert _ids(statement) == ["TRUST-001"]


def test_trust_003_still_fires_when_external_id_is_only_negated() -> None:
    statement = {
        "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": f"arn:aws:iam::{OTHER}:root"},
        "Condition": {"StringNotEquals": {"sts:ExternalId": "secret"}},
    }
    assert _ids(statement) == ["TRUST-003"]


def test_trust_005_still_fires_when_github_sub_uses_if_exists() -> None:
    statement = {
        "Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": {"Federated": GH_ARN},
        "Condition": {
            "StringLikeIfExists": {f"{GH}:sub": "repo:my-org/my-repo:*"},
            "StringEquals": {f"{GH}:aud": "sts.amazonaws.com"},
        },
    }
    assert _ids(statement) == ["TRUST-005"]
