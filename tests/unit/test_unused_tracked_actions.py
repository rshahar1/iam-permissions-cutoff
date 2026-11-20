from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from iam_audit.analyzers.unused import analyze_unused_permissions
from iam_audit.models import (
    ActionLastAccessed,
    FindingCategory,
    ServiceLastAccessedRecord,
)
from tests.conftest import make_attached_policy, make_policy_document, make_role, make_user

RECENT = datetime.now(UTC) - timedelta(days=5)
OLD = datetime.now(UTC) - timedelta(days=200)


def _record(service: str, tracked: dict[str, datetime | None]) -> ServiceLastAccessedRecord:
    return ServiceLastAccessedRecord(
        service_namespace=service,
        service_name=service,
        last_authenticated=RECENT,
        tracked_actions=[ActionLastAccessed(action_name=n, last_accessed_time=t) for n, t in tracked.items()],
    )


def _role(**doc_kwargs):
    return make_role(attached_policies=[make_attached_policy(document=make_policy_document(**doc_kwargs))])


def _run(principal, records, threshold=90):
    return analyze_unused_permissions([principal], {principal.arn: records}, threshold_days=threshold)


def test_granted_action_not_tracked_is_never_reported_unused() -> None:
    role = _role(actions=["s3:GetObject"], resources=["*"])
    findings = _run(role, [_record("s3", {"CreateBucket": None, "DeleteBucket": None})])
    assert findings == []


def test_no_unused_in_scope_action_yields_no_finding() -> None:
    role = _role(actions=["s3:CreateBucket"], resources=["*"])
    assert _run(role, [_record("s3", {"CreateBucket": RECENT})]) == []


def test_tracked_action_with_old_access_time_is_unused() -> None:
    role = _role(actions=["s3:CreateBucket", "s3:DeleteBucket"], resources=["*"])
    findings = _run(role, [_record("s3", {"CreateBucket": OLD, "DeleteBucket": RECENT})])
    assert len(findings) == 1
    assert findings[0].metadata["unused_actions"] == ["CreateBucket"]
    assert findings[0].metadata["keep_actions"] == ["DeleteBucket"]


def test_case_insensitive_grant_uses_canonical_tracked_casing_and_sorted_lists() -> None:
    role = _role(actions=["s3:createbucket", "s3:deletebucket", "s3:listbucket"], resources=["*"])
    findings = _run(
        role,
        [_record("s3", {"ListBucket": RECENT, "DeleteBucket": None, "CreateBucket": None})],
    )
    assert findings[0].metadata["unused_actions"] == ["CreateBucket", "DeleteBucket"]
    assert findings[0].metadata["keep_actions"] == ["ListBucket"]


@pytest.mark.parametrize("pattern", ["s3:Get*Tagging", "s3:?etBucketTagging"])
def test_glob_pattern_matches_only_corresponding_tracked_actions(pattern: str) -> None:
    role = _role(actions=[pattern], resources=["*"])
    findings = _run(role, [_record("s3", {"GetBucketTagging": None, "PutBucketTagging": None})])
    assert len(findings) == 1
    assert findings[0].metadata["unused_actions"] == ["GetBucketTagging"]


def test_notaction_excludes_denied_action_from_unused_report() -> None:
    role = _role(not_actions=["s3:DeleteBucket"], resources=["*"])
    findings = _run(
        role, [_record("s3", {"DeleteBucket": None, "CreateBucket": None, "ListBucket": RECENT})]
    )
    s3 = [f for f in findings if f.metadata.get("service_namespace") == "s3"]
    assert len(s3) == 1
    assert s3[0].metadata["unused_actions"] == ["CreateBucket"]
    assert "DeleteBucket" not in s3[0].metadata["unused_actions"]


def test_notaction_of_whole_service_grants_nothing_in_that_service() -> None:
    role = _role(not_actions=["s3:*"], resources=["*"])
    findings = _run(role, [_record("s3", {"CreateBucket": None})])
    assert all(f.metadata.get("service_namespace") != "s3" for f in findings)


@pytest.mark.parametrize("factory", [make_role, make_user])
def test_notaction_only_principal_still_gets_grants_for_other_services(factory) -> None:
    doc = make_policy_document(not_actions=["s3:*"], resources=["*"])
    principal = factory(attached_policies=[make_attached_policy(document=doc)])
    findings = _run(principal, [])
    assert any(f.metadata.get("service_namespace") == "ec2" for f in findings)


def test_action_level_description_notes_only_tracked_actions_assessed() -> None:
    role = _role(actions=["s3:CreateBucket"], resources=["*"])
    findings = _run(role, [_record("s3", {"CreateBucket": None})])
    assert findings[0].category == FindingCategory.UNUSED_PERMISSION
    assert "Only actions tracked by AWS Access Advisor are assessed." in findings[0].description


def test_service_without_access_record_yields_service_level_finding() -> None:
    role = _role(actions=["s3:GetObject"], resources=["*"])
    findings = _run(role, [])
    assert len(findings) == 1
    assert "Unused service access" in findings[0].title


def test_data_gap_principal_is_skipped() -> None:
    role = _role(actions=["s3:GetObject"], resources=["*"])
    findings = analyze_unused_permissions([role], {}, threshold_days=90, data_gap_arns={role.arn})
    assert findings == []


def test_square_bracket_in_granted_pattern_is_matched_literally_not_as_char_class() -> None:
    role = _role(actions=["s3:[CD]*Bucket"], resources=["*"])
    findings = _run(role, [_record("s3", {"CreateBucket": None, "DeleteBucket": None})])
    assert findings == []
