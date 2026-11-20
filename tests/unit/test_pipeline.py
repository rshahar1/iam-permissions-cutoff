from __future__ import annotations

import argparse
from unittest.mock import patch

import pytest

from iam_audit import cli
from iam_audit.models import Finding, FindingCategory, Severity
from iam_audit.pipeline import (
    CHECKS,
    SUBCOMMANDS,
    AuditContext,
    Check,
    get_subcommand,
    needs_policies,
    run_checks,
)


def _finding(name: str) -> Finding:
    return Finding(
        principal_arn=f"arn:aws:iam::123456789012:role/{name}",
        principal_name=name,
        principal_type="role",
        category=FindingCategory.PERMISSION,
        severity=Severity.LOW,
        title=name,
        description="",
        recommendation="",
    )


def _ctx() -> AuditContext:
    return AuditContext(
        iam_client=None,  # type: ignore[arg-type]  # checks under test never call AWS
        account_id="123456789012",
        options=argparse.Namespace(days=90),
        principals=[],
    )


def test_every_subcommand_references_registered_checks() -> None:
    for subcommand in SUBCOMMANDS:
        assert subcommand.checks, subcommand.name
        for name in subcommand.checks:
            assert name in CHECKS, f"{subcommand.name} -> {name}"


def test_report_subcommand_runs_every_registered_check() -> None:
    assert set(get_subcommand("report").checks) == set(CHECKS)


def test_get_subcommand_unknown_name_raises_key_error() -> None:
    with pytest.raises(KeyError):
        get_subcommand("does-not-exist")


def test_needs_policies_true_only_when_a_check_reads_policies() -> None:
    assert needs_policies(("dormancy",)) is False
    assert needs_policies(("dormancy", "permissions")) is True


def test_run_checks_runs_in_order_and_concatenates_findings() -> None:
    calls: list[str] = []

    def make(name: str) -> Check:
        def run(ctx: AuditContext) -> list[Finding]:
            calls.append(name)
            return [_finding(name)]

        return Check(name, run)

    fake = {"a": make("a"), "b": make("b")}
    with patch.dict("iam_audit.pipeline.CHECKS", fake, clear=True):
        findings = run_checks(_ctx(), ("b", "a"))
    assert calls == ["b", "a"]
    assert [f.title for f in findings] == ["b", "a"]


def test_check_add_arguments_is_wired_into_every_subcommand_parser() -> None:
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--example-flag", default="x")

    extra = Check("example", lambda ctx: [], add_arguments=add_arguments)
    with patch.dict("iam_audit.pipeline.CHECKS", {**CHECKS, "example": extra}):
        parser = cli._build_parser()
    for subcommand in SUBCOMMANDS:
        args = parser.parse_args([subcommand.name, "--example-flag", "y"])
        assert args.example_flag == "y"


def test_every_finding_category_has_a_display_name() -> None:
    for category in FindingCategory:
        assert category.display_name.endswith("Findings")
