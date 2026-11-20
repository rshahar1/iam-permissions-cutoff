from __future__ import annotations

from iam_audit.analyzers.permissions import analyze_permissions
from iam_audit.models import FindingCategory, PolicyDocument, PolicyStatement, Severity
from tests.conftest import (
    S3_WILDCARD_POLICY_DOC,
    TIGHT_S3_POLICY_DOC,
    WILDCARD_POLICY_DOC,
    make_attached_policy,
    make_inline_policy,
    make_policy_document,
    make_role,
    make_user,
)


def test_wildcard_action_wildcard_resource_critical() -> None:
    role = make_role(
        attached_policies=[make_attached_policy(name="Admin", document=WILDCARD_POLICY_DOC)],
    )
    findings = analyze_permissions([role])
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.PERMISSION
    assert findings[0].severity == Severity.CRITICAL


def test_s3_wildcard_on_all_resources_high() -> None:
    role = make_role(
        attached_policies=[make_attached_policy(name="S3Full", document=S3_WILDCARD_POLICY_DOC)],
    )
    findings = analyze_permissions([role])
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.PERMISSION
    assert findings[0].severity == Severity.HIGH


def test_tight_s3_get_object_not_flagged() -> None:
    role = make_role(
        attached_policies=[
            make_attached_policy(
                name="TightS3",
                document=TIGHT_S3_POLICY_DOC,
            )
        ],
    )
    findings = analyze_permissions([role])
    assert len(findings) == 0


def test_inline_and_managed_analyzed_independently() -> None:
    role = make_role(
        inline_policies=[make_inline_policy(document=TIGHT_S3_POLICY_DOC)],
        attached_policies=[make_attached_policy(name="Admin", document=WILDCARD_POLICY_DOC)],
    )
    findings = analyze_permissions([role])
    assert len(findings) == 1


def test_zero_policy_entity_low() -> None:
    role = make_role(attached_policies=[], inline_policies=[])
    findings = analyze_permissions([role])
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.PERMISSION
    assert findings[0].severity == Severity.LOW


def test_deny_statements_skipped() -> None:
    deny_doc = make_policy_document(actions=["*"], resources=["*"], effect="Deny")
    role = make_role(
        attached_policies=[make_attached_policy(name="DenyAll", document=deny_doc)],
    )
    findings = analyze_permissions([role])
    assert len(findings) == 0


def test_deny_awareness_flagged_in_metadata() -> None:
    """FR-036: findings include has_deny_statements when Deny stmts present."""
    allow_doc = make_policy_document(actions=["*"], resources=["*"], effect="Allow")
    deny_doc = make_policy_document(actions=["s3:DeleteBucket"], resources=["*"], effect="Deny")
    combined_doc = PolicyDocument(
        version="2012-10-17",
        statements=allow_doc.statements + deny_doc.statements,
    )
    role = make_role(
        attached_policies=[make_attached_policy(name="MixedPolicy", document=combined_doc)],
    )
    findings = analyze_permissions([role])
    assert len(findings) == 1
    assert findings[0].metadata["has_deny_statements"] is True
    assert "Deny" in findings[0].description


def test_no_deny_statements_metadata_false() -> None:
    role = make_role(
        attached_policies=[make_attached_policy(name="Admin", document=WILDCARD_POLICY_DOC)],
    )
    findings = analyze_permissions([role])
    assert len(findings) == 1
    assert findings[0].metadata["has_deny_statements"] is False


def test_multiple_statements_multiple_findings() -> None:
    double_bad_doc = PolicyDocument(
        version="2012-10-17",
        statements=[
            PolicyStatement(effect="Allow", actions=["*"], resources=["*"], sid="First"),
            PolicyStatement(effect="Allow", actions=["s3:*"], resources=["*"], sid="Second"),
        ],
    )
    role = make_role(
        attached_policies=[make_attached_policy(name="MultiBad", document=double_bad_doc)],
    )
    findings = analyze_permissions([role])
    assert len(findings) == 2


def test_user_group_policies_analyzed() -> None:
    user = make_user()
    user.group_policies = [
        make_attached_policy(name="GroupAdmin", document=WILDCARD_POLICY_DOC)
    ]
    findings = analyze_permissions([user])
    assert len(findings) == 1
    assert findings[0].principal_type == "user"
    assert findings[0].metadata.get("policy_type") == "group"
