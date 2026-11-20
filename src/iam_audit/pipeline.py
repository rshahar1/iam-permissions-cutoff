"""Audit pipeline: shared context, check registry and subcommand composition.

A *check* is a function that receives an :class:`AuditContext` and returns findings.
To add a new check:

1. write ``run(ctx) -> list[Finding]`` in its own analyzer module,
2. add a :class:`Check` to ``CHECKS`` (set ``needs_policies`` if it reads policy
   documents, and ``add_arguments`` if it needs CLI options),
3. list its name in the ``checks`` of each :class:`Subcommand` that should run it,
   or add a new :class:`Subcommand`.

The CLI builds its parser and runs subcommands from this registry, and reporters
read category names from :class:`~iam_audit.models.FindingCategory`, so neither
needs editing for a new check.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from iam_audit.analyzers import credentials
from iam_audit.analyzers.dormancy import analyze_dormancy
from iam_audit.analyzers.permissions import analyze_permissions
from iam_audit.analyzers.unused import analyze_unused_permissions
from iam_audit.collectors.access_advisor import collect_access_advisor

if TYPE_CHECKING:
    import argparse
    from collections.abc import Callable

    from mypy_boto3_iam import IAMClient

    from iam_audit.models import DataGap, Finding, Principal


@dataclass
class AuditContext:
    """Everything a check may read; checks append report-level gaps to ``data_gaps``."""

    iam_client: IAMClient
    account_id: str
    options: argparse.Namespace
    principals: list[Principal]
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    data_gaps: list[DataGap] = field(default_factory=list)


@dataclass(frozen=True)
class Check:
    """A named analysis step that turns an :class:`AuditContext` into findings."""

    name: str
    run: Callable[[AuditContext], list[Finding]]
    needs_policies: bool = False
    add_arguments: Callable[[argparse.ArgumentParser], None] | None = None


@dataclass(frozen=True)
class Subcommand:
    """A CLI subcommand and the ordered checks it runs."""

    name: str
    help: str
    description: str
    epilog: str
    checks: tuple[str, ...]


def _run_dormancy(ctx: AuditContext) -> list[Finding]:
    return analyze_dormancy(ctx.principals, threshold_days=ctx.options.days)


def _run_permissions(ctx: AuditContext) -> list[Finding]:
    return analyze_permissions(ctx.principals)


def _run_unused(ctx: AuditContext) -> list[Finding]:
    print(f"Running Access Advisor analysis for {len(ctx.principals)} principals...", file=sys.stderr)
    access_data, gaps = collect_access_advisor(
        ctx.iam_client, ctx.principals, concurrency=ctx.options.concurrency
    )
    ctx.data_gaps.extend(gaps)
    return analyze_unused_permissions(
        ctx.principals,
        access_data,
        threshold_days=ctx.options.days,
        data_gap_arns={gap.principal_arn for gap in gaps},
    )


CHECKS: dict[str, Check] = {
    check.name: check
    for check in (
        Check("dormancy", _run_dormancy),
        Check("permissions", _run_permissions, needs_policies=True),
        Check("unused", _run_unused, needs_policies=True),
        Check("credentials", credentials.run, add_arguments=credentials.add_arguments),
    )
}


_DORMANCY_EPILOG = """\
examples:
  iam-audit dormancy                         Default 90-day threshold
  iam-audit dormancy --days 30               Flag principals inactive > 30 days
  iam-audit dormancy --path-prefix /ops/     Only roles/users under /ops/
  iam-audit dormancy --tag env=prod          Only principals tagged env=prod
  iam-audit dormancy --format json           JSON output to stdout
  iam-audit dormancy --format html --output dormancy.html
"""

_PERMISSIONS_EPILOG = """\
examples:
  iam-audit permissions                      Detect wildcards + unused permissions
  iam-audit permissions --days 60            60-day Access Advisor lookback
  iam-audit permissions --include-aws-managed  Also scan service-linked and SSO roles
  iam-audit permissions --concurrency 20     Increase API parallelism
  iam-audit permissions --format json > out.json
"""

_CREDENTIALS_EPILOG = """\
examples:
  iam-audit credentials                      Root, MFA, access key and password hygiene
  iam-audit credentials --key-max-age 60     Flag access keys not rotated in 60 days
  iam-audit credentials --days 30            Recent-use / never-used window of 30 days
  iam-audit credentials --name "ci-*"        Only matching users (root row is skipped)
  iam-audit credentials --format json        JSON output to stdout
"""

_REPORT_EPILOG = """\
examples:
  iam-audit report                           Full text report to stdout
  iam-audit report --format json             Full JSON report to stdout
  iam-audit report --format html --output audit.html  Shareable HTML file
  iam-audit report --format json --output audit.json  Write JSON to file
  iam-audit report --path-prefix /team-a/ --tag team=alpha --days 60
"""

SUBCOMMANDS: tuple[Subcommand, ...] = (
    Subcommand(
        name="dormancy",
        help="Identify IAM roles and users with no recent activity",
        description="Identify IAM roles and users inactive beyond the --days threshold.\n"
        "Flags entities that have never been used or exceeded the dormancy window.",
        epilog=_DORMANCY_EPILOG,
        checks=("dormancy",),
    ),
    Subcommand(
        name="permissions",
        help="Detect overly permissive policies and unused permission grants",
        description="Analyze IAM policies for wildcard actions, broad resources, and\n"
        "unused permissions via AWS Access Advisor. Includes Deny-statement awareness.",
        epilog=_PERMISSIONS_EPILOG,
        checks=("permissions", "unused"),
    ),
    Subcommand(
        name="report",
        help="Generate a consolidated audit report (all checks)",
        description="Run every check and produce a combined report.\n"
        "Supports text, JSON, and HTML output formats.",
        epilog=_REPORT_EPILOG,
        checks=("dormancy", "permissions", "unused", "credentials"),
    ),
    Subcommand(
        name="credentials",
        help="Audit credential hygiene: root account, MFA, access keys and passwords",
        description="Analyze the IAM credential report for an active or MFA-less root account,\n"
        "console users without MFA, stale or unused access keys and unused passwords.",
        epilog=_CREDENTIALS_EPILOG,
        checks=("credentials",),
    ),
)


def get_subcommand(name: str) -> Subcommand:
    """Return the registered subcommand called ``name``."""
    for subcommand in SUBCOMMANDS:
        if subcommand.name == name:
            return subcommand
    raise KeyError(f"unknown subcommand: {name}")


def needs_policies(check_names: tuple[str, ...]) -> bool:
    """True if any of the named checks reads policy documents."""
    return any(CHECKS[name].needs_policies for name in check_names)


def run_checks(ctx: AuditContext, check_names: tuple[str, ...]) -> list[Finding]:
    """Run the named checks in order and return all findings."""
    findings: list[Finding] = []
    for name in check_names:
        findings.extend(CHECKS[name].run(ctx))
    return findings
