from __future__ import annotations

from typing import TYPE_CHECKING, Any

from iam_audit.collectors.policies import load_policy_document
from iam_audit.models import IAMRole

# IAM Identity Center (SSO) permission-set roles live here; they are managed in
# Identity Center and cannot be edited through IAM.
AWS_RESERVED_PATH_PREFIX = "/aws-reserved/"

if TYPE_CHECKING:
    from collections.abc import Generator
    from datetime import datetime

    from mypy_boto3_iam import IAMClient

    from iam_audit.models import PolicyDocument


def _fetch_role_tags(iam_client: IAMClient, role_name: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    marker = None
    while True:
        kwargs: dict[str, Any] = {"RoleName": role_name}
        if marker:
            kwargs["Marker"] = marker
        resp = iam_client.list_role_tags(**kwargs)
        for tag in resp.get("Tags", []):
            tags[tag["Key"]] = tag["Value"]
        if not resp.get("IsTruncated"):
            break
        marker = resp.get("Marker")
    return tags


def _fetch_role_last_used(
    iam_client: IAMClient, role_name: str
) -> tuple[datetime | None, str | None]:
    resp = iam_client.get_role(RoleName=role_name)
    role_last_used = resp.get("Role", {}).get("RoleLastUsed", {})
    return role_last_used.get("LastUsedDate"), role_last_used.get("Region")


def _parse_trust_policy(role: Any) -> PolicyDocument | None:
    """Parse the ``AssumeRolePolicyDocument`` that ``list_roles`` already returns."""
    raw = role.get("AssumeRolePolicyDocument")
    return load_policy_document(raw) if raw else None


def collect_roles(
    iam_client: IAMClient,
    include_aws_managed: bool = False,
) -> Generator[IAMRole, None, None]:
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            path = role.get("Path", "")
            is_service_linked = path.startswith("/aws-service-role/")
            is_service_role = path.startswith("/service-role/")
            is_aws_reserved = path.startswith(AWS_RESERVED_PATH_PREFIX)
            is_aws_managed = is_service_linked or is_service_role or is_aws_reserved
            if not include_aws_managed and is_aws_managed:
                continue

            last_used_date, last_used_region = _fetch_role_last_used(
                iam_client, role["RoleName"]
            )

            tags = _fetch_role_tags(iam_client, role["RoleName"])

            yield IAMRole(
                arn=role["Arn"],
                name=role["RoleName"],
                path=path,
                created_date=role["CreateDate"],
                last_used_date=last_used_date,
                last_used_region=last_used_region,
                is_service_linked=is_service_linked,
                is_service_role=is_service_role,
                is_aws_reserved=is_aws_reserved,
                is_aws_managed=is_aws_managed,
                tags=tags,
                trust_policy=_parse_trust_policy(role),
            )
