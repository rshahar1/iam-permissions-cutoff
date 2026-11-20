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
from iam_audit.reporters.json_reporter import format_json_report
from tests.conftest import make_finding


def test_json_output_is_valid_json() -> None:
    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime(2026, 3, 8, 14, 0, 0, tzinfo=UTC),
        threshold_days=90,
        filters_applied=FiltersApplied(),
        include_aws_managed=False,
        findings=[],
        data_gaps=[],
    )
    report.compute_summary(principals_scanned=10)
    output = format_json_report(report)
    parsed = json.loads(output)
    assert isinstance(parsed, dict)


def test_schema_version_present() -> None:
    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime(2026, 3, 8, 14, 0, 0, tzinfo=UTC),
        threshold_days=90,
        filters_applied=FiltersApplied(),
        include_aws_managed=False,
        findings=[],
        data_gaps=[],
    )
    report.compute_summary(principals_scanned=10)
    output = format_json_report(report)
    parsed = json.loads(output)
    assert parsed["schema_version"] == "1.0.0"


def test_all_findings_included() -> None:
    findings = [
        make_finding(principal_name="r1"),
        make_finding(principal_name="r2"),
        make_finding(principal_name="r3"),
    ]
    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime(2026, 3, 8, 14, 0, 0, tzinfo=UTC),
        threshold_days=90,
        filters_applied=FiltersApplied(),
        include_aws_managed=False,
        findings=findings,
        data_gaps=[],
    )
    report.compute_summary(principals_scanned=10)
    output = format_json_report(report)
    parsed = json.loads(output)
    assert len(parsed["findings"]) == 3


def test_finding_metadata_correct() -> None:
    finding = make_finding(
        principal_name="my-role",
        principal_type="role",
        category=FindingCategory.DORMANCY,
        severity=Severity.HIGH,
        title="Role unused for 180 days",
        recommendation="Delete this role.",
        metadata={"days_inactive": 180},
    )
    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime(2026, 3, 8, 14, 0, 0, tzinfo=UTC),
        threshold_days=90,
        filters_applied=FiltersApplied(),
        include_aws_managed=False,
        findings=[finding],
        data_gaps=[],
    )
    report.compute_summary(principals_scanned=10)
    output = format_json_report(report)
    parsed = json.loads(output)
    f = parsed["findings"][0]
    assert f["principal_name"] == "my-role"
    assert f["principal_type"] == "role"
    assert f["category"] == "dormancy"
    assert f["severity"] == "high"
    assert f["title"] == "Role unused for 180 days"
    assert f["recommendation"] == "Delete this role."
    assert f["metadata"] == {"days_inactive": 180}


def test_zero_findings_empty_array() -> None:
    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime(2026, 3, 8, 14, 0, 0, tzinfo=UTC),
        threshold_days=90,
        filters_applied=FiltersApplied(),
        include_aws_managed=False,
        findings=[],
        data_gaps=[],
    )
    report.compute_summary(principals_scanned=10)
    output = format_json_report(report)
    parsed = json.loads(output)
    assert parsed["findings"] == []


def test_summary_counts_match() -> None:
    findings = [
        make_finding(principal_name="r1"),
        make_finding(principal_name="r2"),
    ]
    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime(2026, 3, 8, 14, 0, 0, tzinfo=UTC),
        threshold_days=90,
        filters_applied=FiltersApplied(),
        include_aws_managed=False,
        findings=findings,
        data_gaps=[],
    )
    report.compute_summary(principals_scanned=10)
    output = format_json_report(report)
    parsed = json.loads(output)
    assert parsed["summary"]["total_findings"] == 2
    assert parsed["summary"]["total_findings"] == len(parsed["findings"])


def test_data_gaps_included() -> None:
    data_gap = DataGap(
        principal_arn="arn:aws:iam::123456789012:role/new-role",
        reason="Newly created",
    )
    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime(2026, 3, 8, 14, 0, 0, tzinfo=UTC),
        threshold_days=90,
        filters_applied=FiltersApplied(),
        include_aws_managed=False,
        findings=[],
        data_gaps=[data_gap],
    )
    report.compute_summary(principals_scanned=10)
    output = format_json_report(report)
    parsed = json.loads(output)
    assert len(parsed["data_gaps"]) == 1
    assert parsed["data_gaps"][0]["principal_arn"] == "arn:aws:iam::123456789012:role/new-role"
    assert parsed["data_gaps"][0]["reason"] == "Newly created"


def test_findings_sorted_by_severity_then_name() -> None:
    """FR-037: findings sorted severity desc then principal name asc."""
    findings = [
        make_finding(principal_name="z-role", severity=Severity.LOW),
        make_finding(principal_name="b-role", severity=Severity.CRITICAL),
        make_finding(principal_name="a-role", severity=Severity.CRITICAL),
        make_finding(principal_name="m-role", severity=Severity.HIGH),
    ]
    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime(2026, 3, 8, 14, 0, 0, tzinfo=UTC),
        threshold_days=90,
        filters_applied=FiltersApplied(),
        include_aws_managed=False,
        findings=findings,
        data_gaps=[],
    )
    report.compute_summary(principals_scanned=10)
    output = format_json_report(report)
    parsed = json.loads(output)
    names = [f["principal_name"] for f in parsed["findings"]]
    assert names == ["a-role", "b-role", "m-role", "z-role"]


def test_has_deny_statements_in_metadata() -> None:
    """FR-036: has_deny_statements appears in JSON output metadata."""
    finding = make_finding(
        category=FindingCategory.PERMISSION,
        severity=Severity.CRITICAL,
        metadata={"has_deny_statements": True, "policy_name": "Admin"},
    )
    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime(2026, 3, 8, 14, 0, 0, tzinfo=UTC),
        threshold_days=90,
        filters_applied=FiltersApplied(),
        include_aws_managed=False,
        findings=[finding],
        data_gaps=[],
    )
    report.compute_summary(principals_scanned=10)
    output = format_json_report(report)
    parsed = json.loads(output)
    assert parsed["findings"][0]["metadata"]["has_deny_statements"] is True
