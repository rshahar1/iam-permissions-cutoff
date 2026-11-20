from __future__ import annotations

from iam_audit.models import DataGap, Finding, FindingCategory

CATEGORY_DISPLAY_NAMES: dict[str, str] = {
    "dormancy": "Dormancy Findings",
    "permission": "Permission Findings",
    "unused_permission": "Unused Permission Findings",
}

CATEGORY_ORDER: list[str] = [c.value for c in FindingCategory]


def format_data_gaps(data_gaps: list[DataGap]) -> str:
    if not data_gaps:
        return ""
    lines = ["--- Data Gaps ---"]
    for g in data_gaps:
        lines.append(f"{g.principal_arn}: {g.reason}")
    return "\n".join(lines) + "\n"


def format_text_report(
    findings: list[Finding],
    principals_scanned: int = 0,
    data_gaps: list[DataGap] | None = None,
) -> str:
    if not findings and not (data_gaps or []):
        return "No issues found.\n"

    lines: list[str] = [
        "=== IAM Audit Results ===",
        f"Principals scanned: {principals_scanned}",
        f"Findings: {len(findings)}",
        "",
    ]

    by_category: dict[str, list[Finding]] = {}
    for f in findings:
        cat = f.category.value
        by_category.setdefault(cat, []).append(f)

    for cat_value in CATEGORY_ORDER:
        if cat_value not in by_category:
            continue
        group = by_category[cat_value]
        display_name = CATEGORY_DISPLAY_NAMES.get(cat_value, cat_value)
        lines.append(f"--- {display_name} ---")
        for f in group:
            severity = f.severity.value.upper()
            pname = f.principal_name[:40] if len(f.principal_name) > 40 else f.principal_name
            lines.append(f"{severity:8s}  {f.principal_type:4s}  {pname:40s}  {f.title}")
            lines.append(f"                Recommendation: {f.recommendation}")
        lines.append("")

    gaps_section = format_data_gaps(data_gaps or [])
    if gaps_section:
        lines.append(gaps_section.rstrip())

    return "\n".join(lines).rstrip() + "\n"


def format_error(message: str) -> str:
    return f"ERROR: {message}\n"
