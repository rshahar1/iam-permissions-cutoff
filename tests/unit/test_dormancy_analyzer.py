from __future__ import annotations

from iam_audit.analyzers.dormancy import analyze_dormancy
from iam_audit.models import FindingCategory, Severity
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
    assert findings[0].metadata["days_inactive"] is None


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
