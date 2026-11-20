"""Performance benchmark tests for IAM Audit CLI (T045, SC-003, Constitution V)."""

from __future__ import annotations

import time
import tracemalloc
from datetime import UTC, datetime

import pytest

from iam_audit.analyzers.dormancy import analyze_dormancy
from iam_audit.analyzers.permissions import analyze_permissions
from iam_audit.filters import apply_filters
from iam_audit.models import AuditReport, FiltersApplied
from iam_audit.reporters.html import format_html_report
from iam_audit.reporters.json_reporter import format_json_report
from iam_audit.reporters.text import format_text_report
from tests.conftest import make_attached_policy, make_role, make_user

WILDCARD_DOC = make_attached_policy(name="AdminPolicy").document


def _generate_principals(role_count: int = 500, user_count: int = 100):
    """Generate a large set of principals for benchmark testing."""
    principals = []
    for i in range(role_count):
        days = (i % 200) + 1
        role = make_role(
            name=f"role-{i:04d}",
            days_since_used=days if i % 3 != 0 else None,
            attached_policies=[make_attached_policy(name=f"Policy-{i}")] if i % 5 == 0 else [],
        )
        principals.append(role)
    for i in range(user_count):
        user = make_user(
            name=f"user-{i:04d}",
            days_since_password=(i % 180) + 1,
            days_since_key=(i % 150) + 10,
        )
        principals.append(user)
    return principals


@pytest.mark.benchmark
def test_cold_start_under_2_seconds() -> None:
    """Constitution V: Cold start (import to first useful output) under 2 seconds."""
    start = time.monotonic()
    from iam_audit.cli import _build_parser  # noqa: PLC0415

    parser = _build_parser()
    args = parser.parse_args(["dormancy", "--days", "90"])
    elapsed = time.monotonic() - start
    assert elapsed < 2.0, f"Cold start took {elapsed:.2f}s (limit: 2.0s)"
    assert args.subcommand == "dormancy"


@pytest.mark.benchmark
def test_500_role_dormancy_under_60_seconds() -> None:
    """SC-003: Dormancy analysis of 500 roles + 100 users completes quickly.

    The 5-minute budget (SC-003) includes AWS API calls; this test measures
    pure analysis + reporting time which should be well under that.
    """
    principals = _generate_principals(500, 100)

    start = time.monotonic()
    filters = FiltersApplied()
    filtered = apply_filters(principals, filters)
    findings = analyze_dormancy(filtered, threshold_days=90)
    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime.now(UTC),
        threshold_days=90,
        filters_applied=filters,
        include_aws_managed=False,
        findings=findings,
        data_gaps=[],
    )
    report.compute_summary(principals_scanned=len(filtered))
    _text = format_text_report(
        report.findings,
        principals_scanned=report.summary.principals_scanned,
        data_gaps=report.data_gaps,
    )
    _json = format_json_report(report)
    _html = format_html_report(report)
    elapsed = time.monotonic() - start

    assert elapsed < 60.0, f"Analysis took {elapsed:.2f}s (limit: 60s)"
    assert len(findings) > 0, "Expected at least some dormancy findings"


@pytest.mark.benchmark
def test_500_role_permissions_under_60_seconds() -> None:
    """SC-003: Permissions analysis of 500 roles completes quickly."""
    principals = _generate_principals(500, 100)

    start = time.monotonic()
    findings = analyze_permissions(principals)
    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime.now(UTC),
        threshold_days=90,
        filters_applied=FiltersApplied(),
        include_aws_managed=False,
        findings=findings,
        data_gaps=[],
    )
    report.compute_summary(principals_scanned=len(principals))
    _text = format_text_report(
        report.findings,
        principals_scanned=report.summary.principals_scanned,
        data_gaps=report.data_gaps,
    )
    _json = format_json_report(report)
    _html = format_html_report(report)
    elapsed = time.monotonic() - start

    assert elapsed < 60.0, f"Analysis took {elapsed:.2f}s (limit: 60s)"


@pytest.mark.benchmark
def test_memory_under_256mb_for_500_roles() -> None:
    """Constitution V: Memory usage under 256 MB for typical workloads."""
    tracemalloc.start()

    principals = _generate_principals(500, 100)
    findings = analyze_dormancy(principals, threshold_days=90)
    perm_findings = analyze_permissions(principals)
    all_findings = findings + perm_findings

    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime.now(UTC),
        threshold_days=90,
        filters_applied=FiltersApplied(),
        include_aws_managed=False,
        findings=all_findings,
        data_gaps=[],
    )
    report.compute_summary(principals_scanned=len(principals))
    _html = format_html_report(report)

    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak / (1024 * 1024)
    assert peak_mb < 256.0, f"Peak memory {peak_mb:.1f} MB exceeds 256 MB limit"
