"""Shared test fixtures for IAM Audit CLI tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from iam_audit.models import (
    AttachedPolicy,
    AuditReport,
    DataGap,
    FiltersApplied,
    Finding,
    FindingCategory,
    IAMRole,
    IAMUser,
    InlinePolicy,
    PolicyDocument,
    PolicyStatement,
    Severity,
)


def make_role(
    name: str = "test-role",
    path: str = "/",
    days_since_used: int | None = 30,
    is_service_linked: bool = False,
    is_service_role: bool = False,
    tags: dict[str, str] | None = None,
    attached_policies: list[AttachedPolicy] | None = None,
    inline_policies: list[InlinePolicy] | None = None,
) -> IAMRole:
    now = datetime.now(UTC)
    last_used = now - timedelta(days=days_since_used) if days_since_used is not None else None
    return IAMRole(
        arn=f"arn:aws:iam::123456789012:role{path}{name}",
        name=name,
        path=path,
        created_date=now - timedelta(days=365),
        last_used_date=last_used,
        last_used_region="us-east-1" if last_used else None,
        is_service_linked=is_service_linked,
        is_service_role=is_service_role,
        is_aws_managed=is_service_linked or is_service_role,
        tags=tags or {},
        attached_policies=attached_policies or [],
        inline_policies=inline_policies or [],
    )


def make_user(
    name: str = "test-user",
    path: str = "/",
    days_since_password: int | None = 30,
    days_since_key: int | None = 20,
    group_memberships: list[str] | None = None,
    tags: dict[str, str] | None = None,
    attached_policies: list[AttachedPolicy] | None = None,
    inline_policies: list[InlinePolicy] | None = None,
) -> IAMUser:
    now = datetime.now(UTC)
    pwd = now - timedelta(days=days_since_password) if days_since_password is not None else None
    key = now - timedelta(days=days_since_key) if days_since_key is not None else None
    return IAMUser(
        arn=f"arn:aws:iam::123456789012:user{path}{name}",
        name=name,
        path=path,
        created_date=now - timedelta(days=365),
        password_last_used=pwd,
        access_key_last_used=key,
        group_memberships=group_memberships or [],
        is_aws_managed=False,
        tags=tags or {},
        attached_policies=attached_policies or [],
        inline_policies=inline_policies or [],
    )


def make_finding(
    principal_name: str = "test-role",
    principal_type: str = "role",
    category: FindingCategory = FindingCategory.DORMANCY,
    severity: Severity = Severity.HIGH,
    title: str = "Test finding",
    recommendation: str = "Fix it",
    metadata: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        principal_arn=f"arn:aws:iam::123456789012:{principal_type}/{principal_name}",
        principal_name=principal_name,
        principal_type=principal_type,
        category=category,
        severity=severity,
        title=title,
        description=f"Finding for {principal_name}",
        recommendation=recommendation,
        metadata=metadata or {},
    )


def make_policy_document(
    actions: list[str] | None = None,
    resources: list[str] | None = None,
    effect: str = "Allow",
    sid: str | None = None,
    not_actions: list[str] | None = None,
    not_resources: list[str] | None = None,
) -> PolicyDocument:
    if actions is None:
        actions = [] if not_actions else ["*"]
    if resources is None:
        resources = [] if not_resources else ["*"]
    return PolicyDocument(
        version="2012-10-17",
        statements=[
            PolicyStatement(
                sid=sid,
                effect=effect,
                actions=actions,
                resources=resources,
                not_actions=not_actions or [],
                not_resources=not_resources or [],
            )
        ],
    )


WILDCARD_POLICY_DOC = make_policy_document(actions=["*"], resources=["*"])
S3_WILDCARD_POLICY_DOC = make_policy_document(actions=["s3:*"], resources=["*"])
TIGHT_S3_POLICY_DOC = make_policy_document(
    actions=["s3:GetObject"],
    resources=["arn:aws:s3:::my-bucket/*"],
)


def make_attached_policy(
    name: str = "TestPolicy",
    is_aws_managed: bool = False,
    document: PolicyDocument | None = None,
) -> AttachedPolicy:
    prefix = "arn:aws:iam::aws:policy/" if is_aws_managed else "arn:aws:iam::123456789012:policy/"
    return AttachedPolicy(
        arn=f"{prefix}{name}",
        name=name,
        is_aws_managed=is_aws_managed,
        document=document or TIGHT_S3_POLICY_DOC,
    )


def make_inline_policy(
    name: str = "InlineTestPolicy",
    document: PolicyDocument | None = None,
) -> InlinePolicy:
    return InlinePolicy(
        name=name,
        document=document or TIGHT_S3_POLICY_DOC,
    )


@pytest.fixture()
def sample_role() -> IAMRole:
    return make_role()


@pytest.fixture()
def dormant_role() -> IAMRole:
    return make_role(name="dormant-role", days_since_used=120)


@pytest.fixture()
def never_used_role() -> IAMRole:
    return make_role(name="never-used-role", days_since_used=None)


@pytest.fixture()
def service_linked_role() -> IAMRole:
    return make_role(
        name="AWSServiceRoleForECS",
        path="/aws-service-role/ecs.amazonaws.com/",
        is_service_linked=True,
    )


@pytest.fixture()
def sample_user() -> IAMUser:
    return make_user()


@pytest.fixture()
def dormant_user() -> IAMUser:
    return make_user(name="dormant-user", days_since_password=120, days_since_key=120)


@pytest.fixture()
def never_used_user() -> IAMUser:
    return make_user(name="never-user", days_since_password=None, days_since_key=None)


@pytest.fixture()
def sample_audit_report() -> AuditReport:
    report = AuditReport(
        account_id="123456789012",
        audit_timestamp=datetime.now(UTC),
        threshold_days=90,
        filters_applied=FiltersApplied(),
        include_aws_managed=False,
        findings=[
            make_finding(category=FindingCategory.DORMANCY, severity=Severity.HIGH),
            make_finding(
                principal_name="admin-role",
                category=FindingCategory.PERMISSION,
                severity=Severity.CRITICAL,
            ),
        ],
        data_gaps=[DataGap(principal_arn="arn:aws:iam::123456789012:role/new-role", reason="Newly created")],
    )
    report.compute_summary(principals_scanned=10)
    return report
