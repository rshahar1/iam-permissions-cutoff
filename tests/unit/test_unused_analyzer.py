from __future__ import annotations

from datetime import UTC, datetime, timedelta

from iam_audit.analyzers.unused import analyze_unused_permissions, load_actions_map
from iam_audit.models import (
    ActionLastAccessed,
    FindingCategory,
    ServiceLastAccessedRecord,
)
from tests.conftest import make_attached_policy, make_policy_document, make_role


def test_role_with_3_s3_actions_only_1_used() -> None:
    role = make_role(
        attached_policies=[
            make_attached_policy(
                document=make_policy_document(
                    actions=["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                    resources=["*"],
                )
            )
        ],
    )
    access_data = {
        role.arn: [
            ServiceLastAccessedRecord(
                service_namespace="s3",
                service_name="Amazon S3",
                last_authenticated=datetime.now(UTC) - timedelta(days=10),
                tracked_actions=[
                    ActionLastAccessed(
                        action_name="GetObject",
                        last_accessed_time=datetime.now(UTC) - timedelta(days=10),
                    ),
                    ActionLastAccessed(action_name="PutObject", last_accessed_time=None),
                    ActionLastAccessed(action_name="DeleteObject", last_accessed_time=None),
                ],
            )
        ]
    }
    findings = analyze_unused_permissions(
        [role], access_data, threshold_days=90
    )
    assert len(findings) == 1
    assert findings[0].metadata["unused_actions"] == ["DeleteObject", "PutObject"]
    assert findings[0].metadata["keep_actions"] == ["GetObject"]
    assert findings[0].category == FindingCategory.UNUSED_PERMISSION


def test_wildcard_s3_expansion_with_partial_usage() -> None:
    role = make_role(
        attached_policies=[
            make_attached_policy(
                document=make_policy_document(actions=["s3:*"], resources=["*"])
            )
        ],
    )
    actions_map = load_actions_map()
    s3_actions = set(actions_map["s3"])
    used_actions = {"GetObject", "PutObject"}
    unused_expected = sorted(s3_actions - used_actions)

    access_data = {
        role.arn: [
            ServiceLastAccessedRecord(
                service_namespace="s3",
                service_name="Amazon S3",
                last_authenticated=datetime.now(UTC) - timedelta(days=10),
                tracked_actions=[
                    ActionLastAccessed(
                        action_name=name,
                        last_accessed_time=(
                            datetime.now(UTC) - timedelta(days=10) if name in used_actions else None
                        ),
                    )
                    for name in sorted(s3_actions)
                ],
            )
        ]
    }
    findings = analyze_unused_permissions(
        [role], access_data, threshold_days=90
    )
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.UNUSED_PERMISSION
    assert findings[0].metadata["unused_actions"] == unused_expected
    assert set(findings[0].metadata["keep_actions"]) == used_actions


def test_service_level_only_granularity() -> None:
    role = make_role(
        attached_policies=[
            make_attached_policy(
                document=make_policy_document(actions=["s3:GetObject"], resources=["*"])
            )
        ],
    )
    access_data = {
        role.arn: [
            ServiceLastAccessedRecord(
                service_namespace="s3",
                service_name="Amazon S3",
                last_authenticated=None,
                tracked_actions=None,
            )
        ]
    }
    findings = analyze_unused_permissions(
        [role], access_data, threshold_days=90
    )
    assert len(findings) == 1
    assert findings[0].metadata["granularity"] == "SERVICE_LEVEL"
    assert findings[0].metadata["unused_actions"] is None
    assert findings[0].metadata["keep_actions"] is None


def test_newly_created_role_with_data_gap() -> None:
    role = make_role(
        attached_policies=[
            make_attached_policy(
                document=make_policy_document(
                    actions=["s3:GetObject", "s3:PutObject"],
                    resources=["*"],
                )
            )
        ],
    )
    access_data = {
        role.arn: [
            ServiceLastAccessedRecord(
                service_namespace="s3",
                service_name="Amazon S3",
                last_authenticated=None,
                tracked_actions=None,
            )
        ]
    }
    data_gap_arns = {role.arn}
    findings = analyze_unused_permissions(
        [role], access_data, threshold_days=90, data_gap_arns=data_gap_arns
    )
    assert len(findings) == 0


def test_all_permissions_used_no_finding() -> None:
    role = make_role(
        attached_policies=[
            make_attached_policy(
                document=make_policy_document(
                    actions=["s3:GetObject"],
                    resources=["*"],
                )
            )
        ],
    )
    access_data = {
        role.arn: [
            ServiceLastAccessedRecord(
                service_namespace="s3",
                service_name="Amazon S3",
                last_authenticated=datetime.now(UTC) - timedelta(days=10),
                tracked_actions=[
                    ActionLastAccessed(
                        action_name="GetObject",
                        last_accessed_time=datetime.now(UTC) - timedelta(days=10),
                    )
                ],
            )
        ]
    }
    findings = analyze_unused_permissions(
        [role], access_data, threshold_days=90
    )
    assert len(findings) == 0


def test_load_actions_map() -> None:
    actions_map = load_actions_map()
    assert isinstance(actions_map, dict)
    assert "s3" in actions_map
    assert isinstance(actions_map["s3"], list)
    assert all(isinstance(a, str) for a in actions_map["s3"])
