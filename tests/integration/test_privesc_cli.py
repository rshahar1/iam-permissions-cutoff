"""Pipeline registration and end-to-end (moto) tests for the privesc check."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from iam_audit.cli import main
from iam_audit.models import FindingCategory
from iam_audit.pipeline import CHECKS, get_subcommand

if TYPE_CHECKING:
    from pathlib import Path

_TRUST = '{"Version":"2012-10-17","Statement":[]}'


def test_privesc_check_is_registered_and_reads_policies() -> None:
    assert "privesc" in CHECKS
    assert CHECKS["privesc"].needs_policies is True


@pytest.mark.parametrize(("name", "expected"), [("permissions", True), ("report", True), ("dormancy", False)])
def test_privesc_runs_only_in_permissions_and_report_subcommands(name: str, expected: bool) -> None:
    assert ("privesc" in get_subcommand(name).checks) is expected


def test_privilege_escalation_category_display_name() -> None:
    assert FindingCategory.PRIVILEGE_ESCALATION.value == "privilege_escalation"
    assert FindingCategory.PRIVILEGE_ESCALATION.display_name == "Privilege Escalation Findings"


@pytest.mark.integration
@mock_aws
def test_report_json_contains_privilege_escalation_findings_for_risky_role(tmp_path: Path) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="risky", AssumeRolePolicyDocument=_TRUST)
    iam.put_role_policy(
        RoleName="risky",
        PolicyName="RiskyPolicy",
        PolicyDocument=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutRolePolicy","Resource":"*"}]}'
        ),
    )
    out = tmp_path / "report.json"
    with (
        patch("iam_audit.cli.get_account_id", return_value="123456789012"),
        patch("iam_audit.pipeline.collect_access_advisor", return_value=({}, [])),
        pytest.raises(SystemExit) as exc_info,
        patch("sys.argv", ["iam-audit", "report", "--format", "json", "--output", str(out)]),
    ):
        main()
    assert exc_info.value.code == 1
    data = json.loads(out.read_text())
    assert data["schema_version"] == "1.0.0"
    privesc = [f for f in data["findings"] if f["category"] == "privilege_escalation"]
    assert [f["metadata"]["rule_id"] for f in privesc] == ["PE-008"]
    assert privesc[0]["severity"] == "critical"
    assert privesc[0]["metadata"]["granting_policies"] == ["RiskyPolicy"]
