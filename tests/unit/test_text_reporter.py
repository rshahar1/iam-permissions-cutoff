from __future__ import annotations

from iam_audit.models import FindingCategory, Severity
from iam_audit.reporters.text import format_error, format_text_report
from tests.conftest import make_finding


def test_zero_findings_message() -> None:
    result = format_text_report([])
    assert result == "No issues found.\n"


def test_summary_header_present() -> None:
    findings = [
        make_finding(principal_name="r1"),
        make_finding(principal_name="r2"),
    ]
    result = format_text_report(findings)
    assert "=== IAM Audit Results ===" in result
    assert "Findings: 2" in result


def test_findings_grouped_by_category() -> None:
    findings = [
        make_finding(principal_name="d1", category=FindingCategory.DORMANCY),
        make_finding(principal_name="d2", category=FindingCategory.DORMANCY),
        make_finding(principal_name="p1", category=FindingCategory.PERMISSION),
    ]
    result = format_text_report(findings)
    dormancy_pos = result.find("Dormancy Findings")
    permission_pos = result.find("Permission Findings")
    assert dormancy_pos != -1
    assert permission_pos != -1
    assert dormancy_pos < permission_pos


def test_severity_displayed_uppercase() -> None:
    findings = [
        make_finding(principal_name="r1", severity=Severity.CRITICAL),
    ]
    result = format_text_report(findings)
    assert "CRITICAL" in result


def test_recommendation_shown() -> None:
    findings = [
        make_finding(
            principal_name="r1",
            recommendation="Remove unused permissions or rotate keys.",
        ),
    ]
    result = format_text_report(findings)
    assert "Remove unused permissions or rotate keys." in result


def test_principals_scanned_count() -> None:
    findings = [
        make_finding(principal_name="r1"),
    ]
    result = format_text_report(findings, principals_scanned=10)
    assert "Principals scanned: 10" in result


def test_format_error() -> None:
    result = format_error("bad input")
    assert result == "ERROR: bad input\n"
