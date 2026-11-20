from __future__ import annotations

import pytest

from iam_audit.analyzers.permissions import analyze_permissions
from iam_audit.models import Severity
from tests.conftest import (
    make_attached_policy,
    make_inline_policy,
    make_policy_document,
    make_role,
    make_user,
)

BUCKET = "arn:aws:s3:::b"
OBJECTS = "arn:aws:s3:::b/*"
MANY = ["s3:GetObject", "s3:PutObject", "ec2:Describe*x", "iam:GetUser", "sqs:SendMessage", "sns:Publish"]

CASES = [
    # (actions, resources, not_actions, not_resources, effect, expected)
    (["*"], ["*"], None, None, "Allow", Severity.CRITICAL),
    (["*:*"], ["*"], None, None, "Allow", Severity.CRITICAL),
    (["*", "s3:GetObject"], ["*"], None, None, "Allow", Severity.CRITICAL),
    (["*"], [BUCKET, "*"], None, None, "Allow", Severity.CRITICAL),
    (["*"], [], None, [BUCKET], "Allow", Severity.CRITICAL),
    (["*"], [OBJECTS], None, None, "Allow", Severity.HIGH),
    ([], ["*"], ["s3:DeleteBucket"], None, "Allow", Severity.HIGH),
    (["s3:*"], [OBJECTS], None, None, "Allow", Severity.HIGH),
    (["s3:*"], ["*"], None, None, "Allow", Severity.HIGH),
    (MANY, ["*"], None, None, "Allow", Severity.HIGH),
    ([], [OBJECTS], ["s3:DeleteBucket"], None, "Allow", Severity.MEDIUM),
    (["s3:GetObject", "s3:PutObject"], ["*"], None, None, "Allow", Severity.MEDIUM),
    (MANY[:5], ["*"], None, None, "Allow", Severity.MEDIUM),
    (["s3:GetObject", "s3:PutObject"], [OBJECTS, "*"], None, None, "Allow", Severity.MEDIUM),
    (["s3:Get*"], [OBJECTS], None, None, "Allow", Severity.MEDIUM),
    (["s3:?etObject"], [OBJECTS], None, None, "Allow", Severity.MEDIUM),
    (["s3:GetObject"], [OBJECTS], None, None, "Allow", None),
    (["*"], ["*"], None, None, "Deny", None),
    ([], ["*"], ["s3:DeleteBucket"], None, "Deny", None),
]


@pytest.mark.parametrize(
    ("actions", "resources", "not_actions", "not_resources", "effect", "expected"),
    CASES,
)
def test_statement_classification_matches_expected_severity(
    actions, resources, not_actions, not_resources, effect, expected
) -> None:
    doc = make_policy_document(
        actions=actions,
        resources=resources,
        effect=effect,
        not_actions=not_actions,
        not_resources=not_resources,
    )
    role = make_role(attached_policies=[make_attached_policy(document=doc)])
    findings = analyze_permissions([role])
    if expected is None:
        assert findings == []
    else:
        assert len(findings) == 1
        assert findings[0].severity == expected


def test_notaction_finding_metadata_includes_not_elements() -> None:
    doc = make_policy_document(not_actions=["s3:DeleteBucket"], not_resources=[BUCKET])
    role = make_role(attached_policies=[make_attached_policy(document=doc)])
    finding = analyze_permissions([role])[0]
    assert finding.metadata["not_actions"] == ["s3:DeleteBucket"]
    assert finding.metadata["not_resources"] == [BUCKET]


def test_notaction_recommendation_mentions_notaction() -> None:
    doc = make_policy_document(not_actions=["s3:DeleteBucket"])
    role = make_role(attached_policies=[make_attached_policy(document=doc)])
    finding = analyze_permissions([role])[0]
    assert "NotAction" in finding.recommendation


@pytest.mark.parametrize(
    ("kind", "expected"),
    [("aws", True), ("customer", False), ("inline", False)],
)
def test_policy_is_aws_managed_metadata_reflects_policy_source(kind: str, expected: bool) -> None:
    doc = make_policy_document(actions=["*"], resources=["*"])
    if kind == "inline":
        role = make_role(inline_policies=[make_inline_policy(document=doc)])
    else:
        policy = make_attached_policy(is_aws_managed=(kind == "aws"), document=doc)
        role = make_role(attached_policies=[policy])
    finding = analyze_permissions([role])[0]
    assert finding.metadata["policy_is_aws_managed"] is expected


def test_aws_managed_policy_recommendation_says_cannot_be_edited() -> None:
    doc = make_policy_document(actions=["*"], resources=["*"])
    role = make_role(
        attached_policies=[make_attached_policy("AdministratorAccess", True, doc)]
    )
    findings = analyze_permissions([role])
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "AWS-managed policy and cannot be edited" in findings[0].recommendation


def test_customer_managed_policy_recommendation_omits_aws_managed_note() -> None:
    doc = make_policy_document(actions=["*"], resources=["*"])
    user = make_user(attached_policies=[make_attached_policy(document=doc)])
    finding = analyze_permissions([user])[0]
    assert "cannot be edited" not in finding.recommendation


def test_json_report_emits_new_permission_metadata_keys() -> None:
    import json
    from datetime import UTC, datetime

    from iam_audit.models import AuditReport, FiltersApplied
    from iam_audit.reporters.json_reporter import format_json_report

    doc = make_policy_document(not_actions=["iam:*"], resources=["*"])
    policy = make_attached_policy(name="PowerUserAccess", is_aws_managed=True, document=doc)
    role = make_role(attached_policies=[policy])
    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime.now(UTC),
        threshold_days=90,
        filters_applied=FiltersApplied(),
        include_aws_managed=False,
        findings=analyze_permissions([role]),
    )
    report.compute_summary(principals_scanned=1)
    data = json.loads(format_json_report(report))
    meta = data["findings"][0]["metadata"]
    assert data["schema_version"] == "1.0.0"
    assert meta["not_actions"] == ["iam:*"]
    assert meta["not_resources"] == []
    assert meta["policy_is_aws_managed"] is True
