from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from iam_audit.models import AuditReport


def _serialize_value(obj: object) -> object:
    if isinstance(obj, datetime):
        return obj.isoformat().replace("+00:00", "Z")
    if isinstance(obj, dict):
        return {k: _serialize_value(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize_value(v) for v in obj]
    return obj


def format_json_report(report: AuditReport) -> str:
    filters = report.filters_applied
    filters_dict = {
        "path_prefix": filters.path_prefix,
        "name_pattern": filters.name_pattern,
        "tags": filters.tags,
    }
    summary = report.summary
    summary_dict = {
        "total_findings": summary.total_findings,
        "principals_scanned": summary.principals_scanned,
        "data_gaps_count": summary.data_gaps_count,
        "by_category": summary.by_category,
        "by_severity": summary.by_severity,
    }
    findings_list = [
        {
            "principal_arn": f.principal_arn,
            "principal_name": f.principal_name,
            "principal_type": f.principal_type,
            "category": f.category.value,
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "recommendation": f.recommendation,
            "metadata": _serialize_value(f.metadata),
        }
        for f in report.findings
    ]
    data_gaps_list = [
        {"principal_arn": g.principal_arn, "reason": g.reason}
        for g in report.data_gaps
    ]
    audit_ts = report.audit_timestamp
    ts_str = audit_ts.isoformat().replace("+00:00", "Z") if isinstance(audit_ts, datetime) else str(audit_ts)
    data = {
        "schema_version": "1.0.0",
        "account_id": report.account_id,
        "audit_timestamp": ts_str,
        "threshold_days": report.threshold_days,
        "include_aws_managed": report.include_aws_managed,
        "filters": filters_dict,
        "summary": summary_dict,
        "findings": findings_list,
        "data_gaps": data_gaps_list,
    }
    return json.dumps(data, indent=2)
