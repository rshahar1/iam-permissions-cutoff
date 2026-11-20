from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

from iam_audit.analyzers.dormancy import analyze_dormancy
from iam_audit.models import FindingCategory, IAMRole, Severity
from tests.conftest import make_role, make_user


def test_dormant_role_at_threshold_boundary() -> None:
    role = make_role(name="boundary-role", days_since_used=90)
    findings = analyze_dormancy([role], threshold_days=90)
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.DORMANCY
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].metadata["days_inactive"] == 90


def test_active_role_below_threshold() -> None:
    role = make_role(name="active-role", days_since_used=89)
    findings = analyze_dormancy([role], threshold_days=90)
    assert len(findings) == 0


def test_never_used_user() -> None:
    user = make_user(name="never-user", days_since_password=None, days_since_key=None)
    findings = analyze_dormancy([user], threshold_days=90)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].metadata["last_activity"] is None
    assert findings[0].metadata["days_inactive"] == 365
    assert findings[0].metadata["created_days_ago"] == 365


def test_never_used_role() -> None:
    role = make_role(name="never-role", days_since_used=None)
    findings = analyze_dormancy([role], threshold_days=90)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_active_role_excluded() -> None:
    role = make_role(name="active-role", days_since_used=10)
    findings = analyze_dormancy([role], threshold_days=90)
    assert len(findings) == 0


def test_service_linked_role_analyzed() -> None:
    role = make_role(
        name="AWSServiceRoleForECS",
        path="/aws-service-role/ecs.amazonaws.com/",
        days_since_used=120,
        is_service_linked=True,
    )
    findings = analyze_dormancy([role], threshold_days=90)
    assert len(findings) == 1
    assert findings[0].principal_name == "AWSServiceRoleForECS"


def test_zero_findings_empty_list() -> None:
    findings = analyze_dormancy([], threshold_days=90)
    assert findings == []


def test_severity_high_for_double_threshold() -> None:
    role = make_role(name="very-dormant-role", days_since_used=180)
    findings = analyze_dormancy([role], threshold_days=90)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].metadata["days_inactive"] == 180


def test_severity_medium_for_at_threshold() -> None:
    role = make_role(name="threshold-role", days_since_used=90)
    findings = analyze_dormancy([role], threshold_days=90)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_user_password_only_dormant() -> None:
    user = make_user(
        name="password-only-user",
        days_since_password=120,
        days_since_key=None,
    )
    findings = analyze_dormancy([user], threshold_days=90)
    assert len(findings) == 1
    assert findings[0].principal_type == "user"
    assert findings[0].metadata["days_inactive"] == 120


NOW = datetime(2026, 11, 20, tzinfo=UTC)


def _never_used_role(age_days: int, naive: bool = False) -> IAMRole:
    created = NOW - timedelta(days=age_days)
    if naive:
        created = created.replace(tzinfo=None)
    return replace(make_role(name="fresh", days_since_used=None), created_date=created)


def test_new_never_used_principal_has_no_finding() -> None:
    assert analyze_dormancy([_never_used_role(0)], threshold_days=90, now=NOW) == []
    assert analyze_dormancy([_never_used_role(89)], threshold_days=90, now=NOW) == []


def test_never_used_at_threshold_is_medium() -> None:
    findings = analyze_dormancy([_never_used_role(90)], threshold_days=90, now=NOW)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].title == "role 'fresh' has never been used (created 90 days ago)"
    assert findings[0].metadata["created_days_ago"] == 90


def test_never_used_just_below_double_threshold_is_medium() -> None:
    findings = analyze_dormancy([_never_used_role(179)], threshold_days=90, now=NOW)
    assert findings[0].severity == Severity.MEDIUM


def test_never_used_at_double_threshold_is_high() -> None:
    findings = analyze_dormancy([_never_used_role(180)], threshold_days=90, now=NOW)
    assert findings[0].severity == Severity.HIGH


def test_never_used_naive_created_date_treated_as_utc() -> None:
    findings = analyze_dormancy([_never_used_role(100, naive=True)], threshold_days=90, now=NOW)
    assert len(findings) == 1
    assert findings[0].metadata["days_inactive"] == 100


def test_never_used_new_user_has_no_finding() -> None:
    user = replace(
        make_user(days_since_password=None, days_since_key=None),
        created_date=NOW - timedelta(days=5),
    )
    assert analyze_dormancy([user], threshold_days=90, now=NOW) == []


def test_old_never_used_role_mentions_tracking_window() -> None:
    findings = analyze_dormancy([_never_used_role(401)], threshold_days=90, now=NOW)
    assert "about 400 days" in findings[0].description


def test_role_within_tracking_window_has_no_window_note() -> None:
    findings = analyze_dormancy([_never_used_role(400)], threshold_days=90, now=NOW)
    assert findings[0].description == ""


def test_old_never_used_user_has_no_window_note() -> None:
    user = replace(
        make_user(days_since_password=None, days_since_key=None),
        created_date=NOW - timedelta(days=500),
    )
    findings = analyze_dormancy([user], threshold_days=90, now=NOW)
    assert findings[0].description == ""
