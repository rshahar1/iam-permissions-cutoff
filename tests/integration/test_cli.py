from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import patch

if TYPE_CHECKING:
    from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from iam_audit.cli import main


def _setup_iam_resources() -> None:
    iam = boto3.client("iam", region_name="us-east-1")

    iam.create_role(
        RoleName="dormant-role",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
        Path="/team-alpha/",
    )

    iam.create_role(
        RoleName="admin-role",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
        Path="/",
    )
    iam.put_role_policy(
        RoleName="admin-role",
        PolicyName="AdminPolicy",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
    )

    iam.create_role(
        RoleName="active-role",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
        Path="/",
    )


@pytest.mark.integration
@mock_aws
def test_dormancy_subcommand_exit_code_1() -> None:
    _setup_iam_resources()
    with (
        patch("iam_audit.cli.get_account_id", return_value="123456789012"),
        pytest.raises(SystemExit) as exc_info,
        patch("sys.argv", ["iam-audit", "dormancy", "--days", "1"]),
    ):
        main()
    assert exc_info.value.code == 1


@pytest.mark.integration
@mock_aws
def test_dormancy_text_output_format(capsys: pytest.CaptureFixture[str]) -> None:
    _setup_iam_resources()
    with (
        patch("iam_audit.cli.get_account_id", return_value="123456789012"),
        pytest.raises(SystemExit),
        patch("sys.argv", ["iam-audit", "dormancy", "--days", "1"]),
    ):
        main()
    captured = capsys.readouterr()
    assert "Dormancy Findings" in captured.out


@pytest.mark.integration
@mock_aws
def test_dormancy_json_output_valid(capsys: pytest.CaptureFixture[str]) -> None:
    _setup_iam_resources()
    with (
        patch("iam_audit.cli.get_account_id", return_value="123456789012"),
        pytest.raises(SystemExit),
        patch("sys.argv", ["iam-audit", "dormancy", "--days", "1", "--format", "json"]),
    ):
        main()
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data.get("schema_version") == "1.0.0"


@pytest.mark.integration
@mock_aws
def test_permissions_subcommand_finds_wildcard(capsys: pytest.CaptureFixture[str]) -> None:
    _setup_iam_resources()
    with (
        patch("iam_audit.cli.get_account_id", return_value="123456789012"),
        patch("iam_audit.pipeline.collect_access_advisor", return_value=({}, [])),
        pytest.raises(SystemExit) as exc_info,
        patch("sys.argv", ["iam-audit", "permissions"]),
    ):
        main()
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Permission Findings" in captured.out
    assert "admin-role" in captured.out


@pytest.mark.integration
@mock_aws
def test_filter_by_path_prefix(capsys: pytest.CaptureFixture[str]) -> None:
    _setup_iam_resources()
    with (
        patch("iam_audit.cli.get_account_id", return_value="123456789012"),
        pytest.raises(SystemExit),
        patch("sys.argv", ["iam-audit", "dormancy", "--days", "1", "--path-prefix", "/team-alpha/"]),
    ):
        main()
    captured = capsys.readouterr()
    assert "dormant-role" in captured.out
    assert "admin-role" not in captured.out
    assert "active-role" not in captured.out


@pytest.mark.integration
@mock_aws
def test_report_html_output_writes_file(tmp_path: Path) -> None:
    _setup_iam_resources()
    out_file = tmp_path / "report.html"
    with (
        patch("iam_audit.cli.get_account_id", return_value="123456789012"),
        patch("iam_audit.pipeline.collect_access_advisor", return_value=({}, [])),
        pytest.raises(SystemExit) as exc_info,
        patch("sys.argv", [
            "iam-audit", "report", "--format", "html",
            "--output", str(out_file),
        ]),
    ):
        main()
    assert exc_info.value.code == 1
    assert out_file.exists()
    content = out_file.read_text()
    assert "<!DOCTYPE html>" in content
    assert "IAM Audit Report" in content
    assert "admin-role" in content


@pytest.mark.integration
@mock_aws
def test_dormancy_html_output_writes_file(tmp_path: Path) -> None:
    _setup_iam_resources()
    out_file = tmp_path / "dormancy.html"
    with (
        patch("iam_audit.cli.get_account_id", return_value="123456789012"),
        pytest.raises(SystemExit) as exc_info,
        patch("sys.argv", [
            "iam-audit", "dormancy", "--days", "1",
            "--format", "html", "--output", str(out_file),
        ]),
    ):
        main()
    assert exc_info.value.code == 1
    assert out_file.exists()
    content = out_file.read_text()
    assert "<!DOCTYPE html>" in content


@pytest.mark.integration
def test_html_without_output_exits_code_2(capsys: pytest.CaptureFixture[str]) -> None:
    with (
        pytest.raises(SystemExit) as exc_info,
        patch("sys.argv", ["iam-audit", "report", "--format", "html"]),
    ):
        main()
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert "--output is required" in captured.err


@pytest.mark.integration
def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with (
        pytest.raises(SystemExit) as exc_info,
        patch("sys.argv", ["iam-audit", "--version"]),
    ):
        main()
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "iam-audit" in captured.out


@pytest.mark.integration
@mock_aws
def test_output_silently_overwrites_file(tmp_path: Path) -> None:
    """R11: --output silently overwrites existing files."""
    _setup_iam_resources()
    out_file = tmp_path / "report.json"
    out_file.write_text("old content")
    with (
        patch("iam_audit.cli.get_account_id", return_value="123456789012"),
        pytest.raises(SystemExit),
        patch("sys.argv", [
            "iam-audit", "dormancy", "--days", "1",
            "--format", "json", "--output", str(out_file),
        ]),
    ):
        main()
    content = out_file.read_text()
    assert "old content" not in content
    assert "schema_version" in content


@pytest.mark.integration
@mock_aws
def test_no_findings_exit_code_0() -> None:
    _setup_iam_resources()
    with (
        patch("iam_audit.cli.get_account_id", return_value="123456789012"),
        pytest.raises(SystemExit) as exc_info,
        patch("sys.argv", ["iam-audit", "dormancy", "--days", "99999", "--path-prefix", "/nonexistent/"]),
    ):
        main()
    assert exc_info.value.code == 0
