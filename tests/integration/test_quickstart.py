"""T046: Validate quickstart.md documented commands parse correctly."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from iam_audit.cli import _build_parser, main


class TestQuickstartCLIParsing:
    """Verify every command in quickstart.md is accepted by the argument parser."""

    def setup_method(self) -> None:
        self.parser = _build_parser()

    def test_help_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc_info, patch("sys.argv", ["iam-audit", "--help"]):
            main()
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "dormancy" in captured.out
        assert "permissions" in captured.out
        assert "report" in captured.out

    def test_dormancy_default(self) -> None:
        args = self.parser.parse_args(["dormancy"])
        assert args.subcommand == "dormancy"
        assert args.days == 90
        assert args.format == "text"

    def test_dormancy_custom_days(self) -> None:
        args = self.parser.parse_args(["dormancy", "--days", "30"])
        assert args.subcommand == "dormancy"
        assert args.days == 30

    def test_permissions_default(self) -> None:
        args = self.parser.parse_args(["permissions"])
        assert args.subcommand == "permissions"

    def test_report_default(self) -> None:
        args = self.parser.parse_args(["report"])
        assert args.subcommand == "report"
        assert args.format == "text"

    def test_report_json_format(self) -> None:
        args = self.parser.parse_args(["report", "--format", "json"])
        assert args.format == "json"
        assert args.output is None

    def test_report_html_with_output(self) -> None:
        args = self.parser.parse_args(["report", "--format", "html", "--output", "audit-report.html"])
        assert args.format == "html"
        assert args.output == "audit-report.html"

    def test_dormancy_html_with_output(self) -> None:
        args = self.parser.parse_args(["dormancy", "--format", "html", "--output", "dormancy.html"])
        assert args.format == "html"
        assert args.output == "dormancy.html"

    def test_permissions_html_with_output(self) -> None:
        args = self.parser.parse_args(["permissions", "--format", "html", "--output", "permissions.html"])
        assert args.format == "html"
        assert args.output == "permissions.html"

    def test_report_path_prefix(self) -> None:
        args = self.parser.parse_args(["report", "--path-prefix", "/team-alpha/"])
        assert args.path_prefix == "/team-alpha/"

    def test_report_tag_filter(self) -> None:
        args = self.parser.parse_args(["report", "--tag", "team=platform"])
        assert args.tag == ["team=platform"]

    def test_report_name_glob(self) -> None:
        args = self.parser.parse_args(["report", "--name", "ci-*"])
        assert args.name == "ci-*"

    def test_report_include_aws_managed(self) -> None:
        args = self.parser.parse_args(["report", "--include-aws-managed"])
        assert args.include_aws_managed is True

    def test_report_json_to_file(self) -> None:
        args = self.parser.parse_args(["report", "--format", "json", "--output", "audit.json"])
        assert args.format == "json"
        assert args.output == "audit.json"

    def test_report_text_to_file(self) -> None:
        args = self.parser.parse_args(["report", "--format", "text", "--output", "audit.txt"])
        assert args.format == "text"
        assert args.output == "audit.txt"

    def test_version_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc_info, patch("sys.argv", ["iam-audit", "--version"]):
            main()
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "iam-audit" in captured.out

    def test_concurrency_flag(self) -> None:
        args = self.parser.parse_args(["permissions", "--concurrency", "5"])
        assert args.concurrency == 5

    def test_combined_filters(self) -> None:
        args = self.parser.parse_args([
            "report",
            "--path-prefix", "/team-alpha/",
            "--tag", "team=platform",
            "--name", "ci-*",
            "--include-aws-managed",
            "--days", "30",
            "--format", "json",
            "--output", "audit.json",
        ])
        assert args.path_prefix == "/team-alpha/"
        assert args.tag == ["team=platform"]
        assert args.name == "ci-*"
        assert args.include_aws_managed is True
        assert args.days == 30
        assert args.format == "json"
        assert args.output == "audit.json"
