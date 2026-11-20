from __future__ import annotations

import argparse
import logging
import pathlib
import sys
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from iam_audit import __version__
from iam_audit.analyzers.dormancy import analyze_dormancy
from iam_audit.analyzers.permissions import analyze_permissions
from iam_audit.analyzers.unused import analyze_unused_permissions
from iam_audit.aws_client import check_iam_permissions, create_iam_client, create_session, get_account_id
from iam_audit.collectors.access_advisor import collect_access_advisor
from iam_audit.collectors.policies import collect_policies_for_principal
from iam_audit.collectors.roles import collect_roles
from iam_audit.collectors.users import collect_users
from iam_audit.filters import apply_filters
from iam_audit.logging_config import setup_logging
from iam_audit.models import AuditReport, FiltersApplied
from iam_audit.reporters.html import format_html_report
from iam_audit.reporters.json_reporter import format_json_report
from iam_audit.reporters.text import format_error, format_text_report

if TYPE_CHECKING:
    from iam_audit.models import DataGap, Finding, Principal

logger = logging.getLogger("iam_audit")


_TOP_EPILOG = """\
examples:
  iam-audit dormancy                         Find dormant roles/users (90-day default)
  iam-audit dormancy --days 30               Custom dormancy threshold
  iam-audit permissions                      Detect overly permissive & unused permissions
  iam-audit report --format json             Full report in JSON
  iam-audit report --format html --output r.html  HTML report (file required)
  iam-audit report --path-prefix /team-a/    Scope to a path prefix
  iam-audit report --tag team=platform       Scope to tagged principals
  iam-audit report --name "ci-*"             Scope to name glob pattern

exit codes:
  0  No findings
  1  Findings present — review the report
  2  Tool error (credentials, permissions, invalid arguments)
"""

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

_REPORT_EPILOG = """\
examples:
  iam-audit report                           Full text report to stdout
  iam-audit report --format json             Full JSON report to stdout
  iam-audit report --format html --output audit.html  Shareable HTML file
  iam-audit report --format json --output audit.json  Write JSON to file
  iam-audit report --path-prefix /team-a/ --tag team=alpha --days 60
"""


def _build_parser() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "--days", type=int, default=90,
        help="Dormancy threshold and Access Advisor lookback window in days (default: 90)",
    )
    parent.add_argument(
        "--path-prefix", type=str, default=None,
        help="Filter principals by IAM path prefix (e.g. /team-alpha/)",
    )
    parent.add_argument(
        "--name", type=str, default=None,
        help="Filter principals by name glob pattern (e.g. 'ci-*')",
    )
    parent.add_argument(
        "--tag", type=str, action="append", default=None, metavar="KEY=VALUE",
        help="Filter by tag KEY=VALUE; repeatable, AND-combined",
    )
    parent.add_argument(
        "--include-aws-managed", action="store_true", default=False,
        help=(
            "Also scan AWS-managed principals: service-linked roles, service roles, and "
            "IAM Identity Center (SSO) roles under /aws-reserved/. AWS-managed policies "
            "attached to your own roles and users are always analyzed."
        ),
    )
    parent.add_argument(
        "--format", choices=["text", "json", "html"], default="text",
        help="Output format: text (table), json (machine-readable), html (standalone file) (default: text)",
    )
    parent.add_argument(
        "--output", type=str, default=None, metavar="PATH",
        help="Write output to PATH instead of stdout (required when --format html)",
    )
    parent.add_argument(
        "--concurrency", type=int, default=10, metavar="N",
        help="Max concurrent Access Advisor API requests (default: 10)",
    )

    parser = argparse.ArgumentParser(
        prog="iam-audit",
        description="IAM Audit — detect over-provisioned IAM roles and users.\n\n"
                    "Scans IAM roles and users for dormant entities, overly permissive policies,\n"
                    "and unused permissions. Produces actionable findings with severity ratings\n"
                    "and least-privilege recommendations.",
        epilog=_TOP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[parent],
        add_help=True,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="subcommand", required=False)
    subparsers.add_parser(
        "dormancy", parents=[parent],
        help="Identify IAM roles and users with no recent activity",
        description="Identify IAM roles and users inactive beyond the --days threshold.\n"
                    "Flags entities that have never been used or exceeded the dormancy window.",
        epilog=_DORMANCY_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers.add_parser(
        "permissions", parents=[parent],
        help="Detect overly permissive policies and unused permission grants",
        description="Analyze IAM policies for wildcard actions, broad resources, and\n"
                    "unused permissions via AWS Access Advisor. Includes Deny-statement awareness.",
        epilog=_PERMISSIONS_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers.add_parser(
        "report", parents=[parent],
        help="Generate a consolidated audit report (dormancy + permissions)",
        description="Run both dormancy and permissions analysis and produce a combined report.\n"
                    "Supports text, JSON, and HTML output formats.",
        epilog=_REPORT_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    return parser


def _parse_tag_args(tag_args: list[str] | None) -> dict[str, str] | None:
    if not tag_args:
        return None
    tags: dict[str, str] = {}
    for item in tag_args:
        if "=" not in item:
            continue
        key, _, value = item.partition("=")
        tags[key.strip()] = value.strip()
    return tags or None


def _validate_output_args(args: argparse.Namespace) -> None:
    """Validate --output / --format interaction. Exits with code 2 on error."""
    if args.format == "html" and not args.output:
        print("ERROR: --output is required when --format html", file=sys.stderr)
        sys.exit(2)
    if args.output:
        parent = pathlib.Path(args.output).parent
        if not parent.exists():
            print(
                f"ERROR: Output directory does not exist: {parent}",
                file=sys.stderr,
            )
            sys.exit(2)


def _build_filters(args: argparse.Namespace) -> FiltersApplied:
    return FiltersApplied(
        path_prefix=args.path_prefix,
        name_pattern=args.name,
        tags=_parse_tag_args(args.tag),
    )


def _collect_principals(iam_client: object, include_aws_managed: bool) -> list[Principal]:
    principals: list[Principal] = []
    print("Scanning IAM roles...", file=sys.stderr)
    principals.extend(collect_roles(iam_client, include_aws_managed=include_aws_managed))
    print("Scanning IAM users...", file=sys.stderr)
    principals.extend(collect_users(iam_client, include_aws_managed=include_aws_managed))
    logger.info("Collected %d principals", len(principals))
    return principals


def _enrich_with_policies(iam_client: object, principals: list[Principal]) -> list[Principal]:
    print(f"Analyzing policies for {len(principals)} principals...", file=sys.stderr)
    enriched: list[Principal] = []
    for p in principals:
        enriched.append(collect_policies_for_principal(iam_client, p))
    return enriched


def _write_output_file(content: str, path: str) -> None:
    """Write report content to the specified file path."""
    pathlib.Path(path).write_text(content, encoding="utf-8")
    print(f"Report written to {path}", file=sys.stderr)


def _output_report(report: AuditReport, args: argparse.Namespace) -> None:
    """Route report output to stdout or file based on --format and --output."""
    fmt = args.format
    output_path = args.output

    if fmt == "html":
        content = format_html_report(report)
        _write_output_file(content, output_path)
    elif fmt == "json":
        content = format_json_report(report)
        if output_path:
            _write_output_file(content, output_path)
        else:
            print(content)
    else:
        content = format_text_report(
            report.findings,
            principals_scanned=report.summary.principals_scanned,
            data_gaps=report.data_gaps,
        )
        if output_path:
            _write_output_file(content, output_path)
        else:
            print(content)


def _build_report(
    account_id: str,
    args: argparse.Namespace,
    filters: FiltersApplied,
    findings: list[Finding],
    data_gaps: list[DataGap],
    principals_scanned: int,
) -> AuditReport:
    report = AuditReport(
        account_id=account_id,
        audit_timestamp=datetime.now(UTC),
        threshold_days=args.days,
        filters_applied=filters,
        include_aws_managed=args.include_aws_managed,
        findings=findings,
        data_gaps=data_gaps,
    )
    report.compute_summary(principals_scanned=principals_scanned)
    return report


def _init_aws() -> tuple[object, str]:
    session = create_session()
    iam_client = create_iam_client(session=session)
    account_id = get_account_id(session)
    check_iam_permissions(iam_client)
    return iam_client, account_id


def _run_dormancy(args: argparse.Namespace) -> int:
    _validate_output_args(args)
    try:
        iam_client, account_id = _init_aws()
        logger.info("Starting dormancy audit for account %s", account_id)
    except Exception as exc:
        print(format_error(f"AWS credential or permission error: {exc}"), file=sys.stderr, end="")
        return 2

    try:
        filters = _build_filters(args)
        principals = _collect_principals(iam_client, args.include_aws_managed)
        principals = apply_filters(principals, filters)

        findings = analyze_dormancy(principals, threshold_days=args.days)
        report = _build_report(account_id, args, filters, findings, [], len(principals))
        _output_report(report, args)

        return 1 if findings else 0
    except Exception as exc:
        print(format_error(str(exc)), file=sys.stderr, end="")
        return 2


def _run_permissions(args: argparse.Namespace) -> int:
    _validate_output_args(args)
    try:
        iam_client, account_id = _init_aws()
        logger.info("Starting permissions audit for account %s", account_id)
    except Exception as exc:
        print(format_error(f"AWS credential or permission error: {exc}"), file=sys.stderr, end="")
        return 2

    try:
        filters = _build_filters(args)
        principals = _collect_principals(iam_client, args.include_aws_managed)
        principals = apply_filters(principals, filters)
        principals = _enrich_with_policies(iam_client, principals)

        findings: list[Finding] = analyze_permissions(principals)

        print(f"Running Access Advisor analysis for {len(principals)} principals...", file=sys.stderr)
        access_data, data_gaps = collect_access_advisor(iam_client, principals, concurrency=args.concurrency)
        data_gap_arns = {dg.principal_arn for dg in data_gaps}
        unused_findings = analyze_unused_permissions(
            principals, access_data, threshold_days=args.days, data_gap_arns=data_gap_arns
        )
        findings.extend(unused_findings)

        report = _build_report(account_id, args, filters, findings, list(data_gaps), len(principals))
        _output_report(report, args)

        return 1 if findings else 0
    except Exception as exc:
        print(format_error(str(exc)), file=sys.stderr, end="")
        return 2


def _run_report(args: argparse.Namespace) -> int:
    _validate_output_args(args)
    try:
        iam_client, account_id = _init_aws()
        logger.info("Starting consolidated audit for account %s", account_id)
    except Exception as exc:
        print(format_error(f"AWS credential or permission error: {exc}"), file=sys.stderr, end="")
        return 2

    try:
        filters = _build_filters(args)
        principals = _collect_principals(iam_client, args.include_aws_managed)
        principals = apply_filters(principals, filters)

        dormancy_findings = analyze_dormancy(principals, threshold_days=args.days)

        principals = _enrich_with_policies(iam_client, principals)
        perm_findings: list[Finding] = analyze_permissions(principals)

        print(f"Running Access Advisor analysis for {len(principals)} principals...", file=sys.stderr)
        access_data, data_gaps = collect_access_advisor(iam_client, principals, concurrency=args.concurrency)
        data_gap_arns = {dg.principal_arn for dg in data_gaps}
        unused_findings = analyze_unused_permissions(
            principals, access_data, threshold_days=args.days, data_gap_arns=data_gap_arns
        )

        all_findings = dormancy_findings + perm_findings + unused_findings
        report = _build_report(account_id, args, filters, all_findings, list(data_gaps), len(principals))
        _output_report(report, args)

        return 1 if all_findings else 0
    except Exception as exc:
        print(format_error(str(exc)), file=sys.stderr, end="")
        return 2


def main() -> None:
    setup_logging()
    try:
        parser = _build_parser()
        args = parser.parse_args()

        if args.subcommand is None:
            parser.print_help()
            sys.exit(2)

        handlers = {
            "dormancy": _run_dormancy,
            "permissions": _run_permissions,
            "report": _run_report,
        }
        exit_code = handlers[args.subcommand](args)
        sys.exit(exit_code)
    except SystemExit:
        raise
    except Exception as exc:
        logger.exception("Unexpected error")
        print(format_error(str(exc)), file=sys.stderr, end="")
        sys.exit(2)
