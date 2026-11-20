"""Unit tests for the HTML report formatter."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from iam_audit.models import (
    AuditReport,
    DataGap,
    FiltersApplied,
    FindingCategory,
    Severity,
)
from iam_audit.reporters.html import format_html_report
from iam_audit.reporters.json_reporter import format_json_report
from tests.conftest import make_finding


def _make_report(
    findings=None,
    data_gaps=None,
    principals_scanned: int = 10,
) -> AuditReport:
    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime(2026, 3, 10, 12, 0, 0, tzinfo=UTC),
        threshold_days=90,
        filters_applied=FiltersApplied(),
        include_aws_managed=False,
        findings=findings or [],
        data_gaps=data_gaps or [],
    )
    report.compute_summary(principals_scanned=principals_scanned)
    return report


def test_html_structure_has_doctype_head_body() -> None:
    report = _make_report()
    html = format_html_report(report)
    assert html.startswith("<!DOCTYPE html>")
    assert "<head>" in html
    assert "</head>" in html
    assert "<body>" in html
    assert "</body>" in html
    assert "</html>" in html
    assert '<html lang="en">' in html
    assert '<meta charset="utf-8">' in html


def test_summary_badges_show_correct_counts() -> None:
    findings = [
        make_finding(severity=Severity.CRITICAL, category=FindingCategory.PERMISSION),
        make_finding(severity=Severity.CRITICAL, category=FindingCategory.PERMISSION, principal_name="r2"),
        make_finding(severity=Severity.HIGH, category=FindingCategory.DORMANCY),
        make_finding(severity=Severity.LOW, category=FindingCategory.UNUSED_PERMISSION),
    ]
    report = _make_report(findings=findings)
    html = format_html_report(report)
    assert "Total: 4" in html
    assert "Critical" in html
    assert "#dc3545" in html  # critical color


def test_findings_grouped_by_category() -> None:
    findings = [
        make_finding(category=FindingCategory.DORMANCY, principal_name="d1"),
        make_finding(category=FindingCategory.PERMISSION, principal_name="p1"),
        make_finding(category=FindingCategory.UNUSED_PERMISSION, principal_name="u1"),
    ]
    report = _make_report(findings=findings)
    html = format_html_report(report)
    dormancy_pos = html.find("Dormancy Findings")
    permission_pos = html.find("Permission Findings")
    unused_pos = html.find("Unused Permission Findings")
    assert dormancy_pos != -1
    assert permission_pos != -1
    assert unused_pos != -1
    assert dormancy_pos < permission_pos < unused_pos


def test_finding_table_contains_required_columns() -> None:
    finding = make_finding(
        principal_name="my-role",
        principal_type="role",
        severity=Severity.HIGH,
        title="Wildcard actions detected",
        recommendation="Scope actions to specific services",
    )
    report = _make_report(findings=[finding])
    html = format_html_report(report)
    assert "my-role" in html
    assert "arn:aws:iam::123456789012:role/my-role" in html
    assert "High" in html
    assert "Wildcard actions detected" in html
    assert "Scope actions to specific services" in html


def test_zero_findings_shows_no_issues_message() -> None:
    report = _make_report(findings=[])
    html = format_html_report(report)
    assert "No issues found" in html
    assert "Total: 0" in html


def test_special_characters_are_html_escaped() -> None:
    # Application Security Requirement: XSS prevention via html.escape()
    finding = make_finding(
        principal_name='<script>alert("xss")</script>',
        title="Role with <b>bold</b> name",
        recommendation='Use "least privilege" & restrict access',
    )
    report = _make_report(findings=[finding])
    html = format_html_report(report)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "<b>bold</b>" not in html
    assert "&lt;b&gt;bold&lt;/b&gt;" in html
    assert "&amp; restrict" in html


def test_data_gaps_section_rendered() -> None:
    data_gaps = [
        DataGap(principal_arn="arn:aws:iam::123456789012:role/new-role", reason="Newly created"),
        DataGap(principal_arn="arn:aws:iam::123456789012:role/timeout-role", reason="API timeout"),
    ]
    report = _make_report(data_gaps=data_gaps)
    html = format_html_report(report)
    assert "Data Gaps" in html
    assert "new-role" in html
    assert "Newly created" in html
    assert "timeout-role" in html
    assert "API timeout" in html


def test_html_finding_data_matches_json_report() -> None:
    """SC-013: HTML and JSON reports must contain identical finding data."""
    findings = [
        make_finding(
            principal_name="admin-role",
            principal_type="role",
            category=FindingCategory.PERMISSION,
            severity=Severity.CRITICAL,
            title="Full admin access",
            recommendation="Scope to specific services",
        ),
        make_finding(
            principal_name="old-user",
            principal_type="user",
            category=FindingCategory.DORMANCY,
            severity=Severity.LOW,
            title="User inactive 200 days",
            recommendation="Delete this user",
        ),
    ]
    data_gaps = [
        DataGap(principal_arn="arn:aws:iam::123456789012:role/gap-role", reason="API timeout"),
    ]
    report = _make_report(findings=findings, data_gaps=data_gaps)

    html = format_html_report(report)
    json_output = format_json_report(report)
    json_data = json.loads(json_output)

    for jf in json_data["findings"]:
        assert jf["principal_name"] in html
        assert jf["principal_arn"] in html
        assert jf["title"] in html
        assert jf["recommendation"] in html
        assert jf["severity"].title() in html

    for dg in json_data["data_gaps"]:
        assert dg["principal_arn"] in html
        assert dg["reason"] in html


def test_categories_use_details_summary_elements() -> None:
    """FR-035: Each category should be wrapped in <details>/<summary>."""
    findings = [
        make_finding(category=FindingCategory.DORMANCY, principal_name="d1"),
        make_finding(category=FindingCategory.PERMISSION, principal_name="p1"),
    ]
    report = _make_report(findings=findings)
    html = format_html_report(report)
    assert "<details>" in html
    assert "<summary>" in html
    assert "</details>" in html
    assert html.count("<details>") == 2


def test_categories_collapsed_by_default() -> None:
    """FR-035: Categories should be collapsed by default (no 'open' attribute)."""
    findings = [
        make_finding(category=FindingCategory.DORMANCY, principal_name="d1"),
    ]
    report = _make_report(findings=findings)
    html = format_html_report(report)
    assert "<details open" not in html
    assert "<details>" in html


def test_print_css_forces_details_visible() -> None:
    """FR-035: @media print must force collapsed content visible."""
    findings = [make_finding()]
    report = _make_report(findings=findings)
    html = format_html_report(report)
    assert "@media print" in html
    assert "details:not([open])" in html


def test_data_gaps_use_details_summary() -> None:
    data_gaps = [
        DataGap(principal_arn="arn:aws:iam::123456789012:role/gap", reason="API timeout"),
    ]
    report = _make_report(data_gaps=data_gaps)
    html = format_html_report(report)
    assert "<details>" in html
    assert "<summary>Data Gaps (1)</summary>" in html


def test_summary_shows_count_in_summary_element() -> None:
    findings = [
        make_finding(category=FindingCategory.DORMANCY, principal_name="d1"),
        make_finding(category=FindingCategory.DORMANCY, principal_name="d2"),
    ]
    report = _make_report(findings=findings)
    html = format_html_report(report)
    assert "Dormancy Findings (2)</summary>" in html
