"""Data model dataclasses for IAM Audit CLI."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime  # noqa: TC003 — used at runtime in property bodies


class FindingCategory(enum.Enum):
    """Finding categories, in report order. Add new categories here with a display name."""

    DORMANCY = "dormancy"
    PERMISSION = "permission"
    UNUSED_PERMISSION = "unused_permission"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CREDENTIAL = "credential"
    TRUST_POLICY = "trust_policy"

    @property
    def display_name(self) -> str:
        """Section heading used by the text and HTML reporters."""
        return _CATEGORY_DISPLAY_NAMES[self]


_CATEGORY_DISPLAY_NAMES: dict[FindingCategory, str] = {
    FindingCategory.DORMANCY: "Dormancy Findings",
    FindingCategory.PERMISSION: "Permission Findings",
    FindingCategory.UNUSED_PERMISSION: "Unused Permission Findings",
    FindingCategory.PRIVILEGE_ESCALATION: "Privilege Escalation Findings",
    FindingCategory.CREDENTIAL: "Credential Findings",
    FindingCategory.TRUST_POLICY: "Trust Policy Findings",
}


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity descending then principal name ascending."""
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.principal_name))


@dataclass(frozen=True)
class PolicyStatement:
    effect: str
    actions: list[str]
    resources: list[str]
    sid: str | None = None
    conditions: dict | None = None  # type: ignore[type-arg]
    not_actions: list[str] = field(default_factory=list)
    not_resources: list[str] = field(default_factory=list)
    principals: dict[str, list[str]] | None = None
    not_principals: dict[str, list[str]] | None = None


@dataclass(frozen=True)
class PolicyDocument:
    version: str
    statements: list[PolicyStatement]


@dataclass(frozen=True)
class AttachedPolicy:
    arn: str
    name: str
    is_aws_managed: bool
    document: PolicyDocument


@dataclass(frozen=True)
class InlinePolicy:
    name: str
    document: PolicyDocument


@dataclass
class Principal:
    arn: str
    name: str
    path: str
    created_date: datetime
    tags: dict[str, str] = field(default_factory=dict)
    attached_policies: list[AttachedPolicy] = field(default_factory=list)
    inline_policies: list[InlinePolicy] = field(default_factory=list)
    is_aws_managed: bool = False

    @property
    def last_activity(self) -> datetime | None:
        raise NotImplementedError

    @property
    def principal_type(self) -> str:
        raise NotImplementedError


@dataclass
class IAMRole(Principal):
    last_used_date: datetime | None = None
    last_used_region: str | None = None
    is_service_linked: bool = False
    is_service_role: bool = False
    is_aws_reserved: bool = False
    trust_policy: PolicyDocument | None = None

    @property
    def last_activity(self) -> datetime | None:
        return self.last_used_date

    @property
    def principal_type(self) -> str:
        return "role"


@dataclass
class IAMUser(Principal):
    password_last_used: datetime | None = None
    access_key_last_used: datetime | None = None
    group_memberships: list[str] = field(default_factory=list)
    group_policies: list[AttachedPolicy] = field(default_factory=list)

    @property
    def last_activity(self) -> datetime | None:
        dates = [d for d in (self.password_last_used, self.access_key_last_used) if d is not None]
        return max(dates) if dates else None

    @property
    def principal_type(self) -> str:
        return "user"


@dataclass(frozen=True)
class ActionLastAccessed:
    action_name: str
    last_accessed_time: datetime | None = None


@dataclass(frozen=True)
class ServiceLastAccessedRecord:
    service_namespace: str
    service_name: str
    last_authenticated: datetime | None = None
    last_authenticated_region: str | None = None
    tracked_actions: list[ActionLastAccessed] | None = None


@dataclass(frozen=True)
class Finding:
    principal_arn: str
    principal_name: str
    principal_type: str
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    recommendation: str
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class DataGap:
    principal_arn: str
    reason: str


@dataclass(frozen=True)
class FiltersApplied:
    path_prefix: str | None = None
    name_pattern: str | None = None
    tags: dict[str, str] | None = None


@dataclass
class ReportSummary:
    total_findings: int = 0
    by_category: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    principals_scanned: int = 0
    data_gaps_count: int = 0


@dataclass
class AuditReport:
    account_id: str
    audit_timestamp: datetime
    threshold_days: int
    filters_applied: FiltersApplied
    include_aws_managed: bool
    findings: list[Finding] = field(default_factory=list)
    data_gaps: list[DataGap] = field(default_factory=list)
    summary: ReportSummary = field(default_factory=ReportSummary)

    def compute_summary(self, principals_scanned: int) -> None:
        self.findings = sort_findings(self.findings)
        by_cat: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        for f in self.findings:
            cat = f.category.value
            sev = f.severity.value
            by_cat[cat] = by_cat.get(cat, 0) + 1
            by_sev[sev] = by_sev.get(sev, 0) + 1
        self.summary = ReportSummary(
            total_findings=len(self.findings),
            by_category=by_cat,
            by_severity=by_sev,
            principals_scanned=principals_scanned,
            data_gaps_count=len(self.data_gaps),
        )
