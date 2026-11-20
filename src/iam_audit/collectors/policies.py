from __future__ import annotations

import json
import logging
import urllib.parse
from dataclasses import replace
from typing import TYPE_CHECKING, Any, cast

from iam_audit.models import (
    AttachedPolicy,
    IAMRole,
    IAMUser,
    InlinePolicy,
    PolicyDocument,
    PolicyStatement,
)

if TYPE_CHECKING:
    from mypy_boto3_iam import IAMClient

    from iam_audit.models import Principal

logger = logging.getLogger(__name__)

AWS_MANAGED_POLICY_PREFIX = "arn:aws:iam::aws:policy/"


def _as_list(value: object) -> list[str]:
    """Normalize an IAM policy element that may be a string or a list of strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _parse_policy_document(doc: dict[str, Any]) -> PolicyDocument:
    """Parse a raw IAM policy document, including NotAction/NotResource elements."""
    version = doc.get("Version", "2012-10-17")
    raw_statements = doc.get("Statement", [])
    statements_raw = raw_statements if isinstance(raw_statements, list) else [raw_statements]
    statements: list[PolicyStatement] = []
    for stmt in statements_raw:
        statements.append(
            PolicyStatement(
                effect=stmt.get("Effect", "Allow"),
                actions=_as_list(stmt.get("Action")),
                resources=_as_list(stmt.get("Resource")),
                sid=stmt.get("Sid"),
                conditions=stmt.get("Condition"),
                not_actions=_as_list(stmt.get("NotAction")),
                not_resources=_as_list(stmt.get("NotResource")),
            )
        )
    return PolicyDocument(version=version, statements=statements)


def _load_document(raw: object) -> dict[str, Any]:
    """Return a policy document as a dict, decoding URL-encoded JSON strings."""
    if isinstance(raw, str):
        raw = json.loads(urllib.parse.unquote(raw))
    return cast("dict[str, Any]", raw)


def _fetch_inline_policies(iam_client: IAMClient, principal: Principal) -> list[InlinePolicy]:
    result: list[InlinePolicy] = []
    if isinstance(principal, IAMRole):
        paginator = iam_client.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=principal.name):
            for policy_name in page.get("PolicyNames", []):
                try:
                    resp = iam_client.get_role_policy(
                        RoleName=principal.name, PolicyName=policy_name
                    )
                    doc: object = resp.get("PolicyDocument", {})
                    parsed = _parse_policy_document(_load_document(doc))
                    result.append(InlinePolicy(name=policy_name, document=parsed))
                except Exception as e:
                    logger.warning(
                        "Failed to fetch inline policy %s for role %s: %s",
                        policy_name, principal.name, e,
                    )
    elif isinstance(principal, IAMUser):
        user_paginator = iam_client.get_paginator("list_user_policies")
        for page in user_paginator.paginate(UserName=principal.name):
            for policy_name in page.get("PolicyNames", []):
                try:
                    user_resp = iam_client.get_user_policy(
                        UserName=principal.name, PolicyName=policy_name
                    )
                    user_doc: object = user_resp.get("PolicyDocument", {})
                    parsed = _parse_policy_document(_load_document(user_doc))
                    result.append(InlinePolicy(name=policy_name, document=parsed))
                except Exception as e:
                    logger.warning(
                        "Failed to fetch inline policy %s for user %s: %s",
                        policy_name, principal.name, e,
                    )
    return result


def _fetch_attached_policies(iam_client: IAMClient, principal: Principal) -> list[AttachedPolicy]:
    result: list[AttachedPolicy] = []
    if isinstance(principal, IAMRole):
        paginator = iam_client.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=principal.name):
            for att in page.get("AttachedPolicies", []):
                try:
                    policy_arn = att["PolicyArn"]
                    policy_name = att["PolicyName"]
                    is_aws_managed = policy_arn.startswith(AWS_MANAGED_POLICY_PREFIX)
                    policy_resp = iam_client.get_policy(PolicyArn=policy_arn)
                    default_version = policy_resp["Policy"]["DefaultVersionId"]
                    version_resp = iam_client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=default_version
                    )
                    doc: object = version_resp["PolicyVersion"].get("Document", {})
                    parsed = _parse_policy_document(_load_document(doc))
                    result.append(
                        AttachedPolicy(
                            arn=policy_arn,
                            name=policy_name,
                            is_aws_managed=is_aws_managed,
                            document=parsed,
                        )
                    )
                except Exception as e:
                    logger.warning(
                        "Failed to fetch attached policy %s for role %s: %s",
                        att.get("PolicyArn"), principal.name, e,
                    )
    elif isinstance(principal, IAMUser):
        user_paginator = iam_client.get_paginator("list_attached_user_policies")
        for page in user_paginator.paginate(UserName=principal.name):
            for att in page.get("AttachedPolicies", []):
                try:
                    policy_arn = att["PolicyArn"]
                    policy_name = att["PolicyName"]
                    is_aws_managed = policy_arn.startswith(AWS_MANAGED_POLICY_PREFIX)
                    policy_resp = iam_client.get_policy(PolicyArn=policy_arn)
                    default_version = policy_resp["Policy"]["DefaultVersionId"]
                    version_resp = iam_client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=default_version
                    )
                    user_doc: object = version_resp["PolicyVersion"].get("Document", {})
                    parsed = _parse_policy_document(_load_document(user_doc))
                    result.append(
                        AttachedPolicy(
                            arn=policy_arn,
                            name=policy_name,
                            is_aws_managed=is_aws_managed,
                            document=parsed,
                        )
                    )
                except Exception as e:
                    logger.warning(
                        "Failed to fetch attached policy %s for user %s: %s",
                        att.get("PolicyArn"), principal.name, e,
                    )
    return result


def _fetch_group_policies(iam_client: IAMClient, user: IAMUser) -> list[AttachedPolicy]:
    result: list[AttachedPolicy] = []
    for group_name in user.group_memberships:
        paginator = iam_client.get_paginator("list_attached_group_policies")
        for page in paginator.paginate(GroupName=group_name):
            for att in page.get("AttachedPolicies", []):
                try:
                    policy_arn = att["PolicyArn"]
                    policy_name = att["PolicyName"]
                    is_aws_managed = policy_arn.startswith(AWS_MANAGED_POLICY_PREFIX)
                    policy_resp = iam_client.get_policy(PolicyArn=policy_arn)
                    default_version = policy_resp["Policy"]["DefaultVersionId"]
                    version_resp = iam_client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=default_version
                    )
                    doc: object = version_resp["PolicyVersion"].get("Document", {})
                    parsed = _parse_policy_document(_load_document(doc))
                    result.append(
                        AttachedPolicy(
                            arn=policy_arn,
                            name=policy_name,
                            is_aws_managed=is_aws_managed,
                            document=parsed,
                        )
                    )
                except Exception as e:
                    logger.warning(
                        "Failed to fetch group policy %s for group %s: %s",
                        att.get("PolicyArn"), group_name, e,
                    )
    return result


def collect_policies_for_principal(iam_client: IAMClient, principal: Principal) -> Principal:
    attached_policies = _fetch_attached_policies(iam_client, principal)
    inline_policies = _fetch_inline_policies(iam_client, principal)
    if isinstance(principal, IAMUser):
        group_policies = _fetch_group_policies(iam_client, principal)
        return replace(
            principal,
            attached_policies=attached_policies,
            inline_policies=inline_policies,
            group_policies=group_policies,
        )
    return replace(
        principal,
        attached_policies=attached_policies,
        inline_policies=inline_policies,
    )
