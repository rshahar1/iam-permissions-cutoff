from __future__ import annotations

import json
import urllib.parse
from datetime import UTC, datetime

import boto3
from botocore.config import Config
from botocore.stub import Stubber

from iam_audit.collectors.policies import _parse_policy_document, collect_policies_for_principal
from iam_audit.collectors.roles import collect_roles
from iam_audit.collectors.users import collect_users
from iam_audit.models import IAMRole, IAMUser


def _make_iam_client():
    config = Config(retries={"total_max_attempts": 1, "mode": "standard"})
    return boto3.client("iam", region_name="us-east-1", config=config)


def test_collect_roles_basic() -> None:
    client = _make_iam_client()
    with Stubber(client) as stubber:
        stubber.add_response(
            "list_roles",
            {
                "Roles": [
                    {
                        "Arn": "arn:aws:iam::123456789012:role/test-role",
                        "RoleName": "test-role",
                        "Path": "/",
                        "CreateDate": datetime(2025, 1, 1, tzinfo=UTC),
                        "RoleId": "AROAXXXXXXXXXXXX",
                    }
                ],
                "IsTruncated": False,
            },
        )
        stubber.add_response(
            "get_role",
            {
                "Role": {
                    "Arn": "arn:aws:iam::123456789012:role/test-role",
                    "RoleName": "test-role",
                    "Path": "/",
                    "CreateDate": datetime(2025, 1, 1, tzinfo=UTC),
                    "RoleId": "AROAXXXXXXXXXXXX",
                    "RoleLastUsed": {
                        "LastUsedDate": datetime(2026, 1, 1, tzinfo=UTC),
                        "Region": "us-east-1",
                    },
                }
            },
        )
        stubber.add_response(
            "list_role_tags",
            {"Tags": [{"Key": "env", "Value": "prod"}], "IsTruncated": False},
        )
        roles = list(collect_roles(client, include_aws_managed=False))
    assert len(roles) == 1
    role = roles[0]
    assert role.name == "test-role"
    assert role.arn == "arn:aws:iam::123456789012:role/test-role"
    assert role.path == "/"
    assert role.tags == {"env": "prod"}
    assert role.last_used_date == datetime(2026, 1, 1, tzinfo=UTC)
    assert role.last_used_region == "us-east-1"
    assert role.is_service_linked is False
    assert role.is_service_role is False


def test_collect_roles_excludes_service_linked() -> None:
    client = _make_iam_client()
    with Stubber(client) as stubber:
        stubber.add_response(
            "list_roles",
            {
                "Roles": [
                    {
                        "Arn": "arn:aws:iam::123456789012:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS",
                        "RoleName": "AWSServiceRoleForECS",
                        "Path": "/aws-service-role/ecs.amazonaws.com/",
                        "CreateDate": datetime(2025, 1, 1, tzinfo=UTC),
                        "RoleId": "AROAXXXXXXXXXXXX",
                    }
                ],
                "IsTruncated": False,
            },
        )
        roles = list(collect_roles(client, include_aws_managed=False))
    assert len(roles) == 0


def test_collect_roles_includes_service_linked() -> None:
    client = _make_iam_client()
    with Stubber(client) as stubber:
        stubber.add_response(
            "list_roles",
            {
                "Roles": [
                    {
                        "Arn": "arn:aws:iam::123456789012:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS",
                        "RoleName": "AWSServiceRoleForECS",
                        "Path": "/aws-service-role/ecs.amazonaws.com/",
                        "CreateDate": datetime(2025, 1, 1, tzinfo=UTC),
                        "RoleId": "AROAXXXXXXXXXXXX",
                    }
                ],
                "IsTruncated": False,
            },
        )
        stubber.add_response(
            "get_role",
            {
                "Role": {
                    "Arn": "arn:aws:iam::123456789012:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS",
                    "RoleName": "AWSServiceRoleForECS",
                    "Path": "/aws-service-role/ecs.amazonaws.com/",
                    "CreateDate": datetime(2025, 1, 1, tzinfo=UTC),
                    "RoleId": "AROAXXXXXXXXXXXX",
                    "RoleLastUsed": {},
                }
            },
        )
        stubber.add_response(
            "list_role_tags",
            {"Tags": [], "IsTruncated": False},
        )
        roles = list(collect_roles(client, include_aws_managed=True))
    assert len(roles) == 1
    assert roles[0].name == "AWSServiceRoleForECS"
    assert roles[0].is_service_linked is True


def test_collect_users_basic() -> None:
    client = _make_iam_client()
    with Stubber(client) as stubber:
        stubber.add_response(
            "list_users",
            {
                "Users": [
                    {
                        "Arn": "arn:aws:iam::123456789012:user/test-user",
                        "UserName": "test-user",
                        "Path": "/",
                        "CreateDate": datetime(2025, 1, 1, tzinfo=UTC),
                        "UserId": "AIDAXXXXXXXXXXXX",
                        "PasswordLastUsed": datetime(2025, 6, 1, tzinfo=UTC),
                    }
                ],
                "IsTruncated": False,
            },
        )
        stubber.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "AccessKeyId": "AKIAXXXXXXXXXXXX",
                        "UserName": "test-user",
                        "Status": "Active",
                        "CreateDate": datetime(2025, 1, 1, tzinfo=UTC),
                    }
                ],
                "IsTruncated": False,
            },
        )
        stubber.add_response(
            "get_access_key_last_used",
            {
                "AccessKeyLastUsed": {
                    "LastUsedDate": datetime(2025, 12, 1, tzinfo=UTC),
                    "ServiceName": "ec2",
                    "Region": "us-east-1",
                }
            },
        )
        stubber.add_response(
            "list_groups_for_user",
            {
                "Groups": [
                    {
                        "GroupName": "Developers",
                        "GroupId": "AGPAXXXXXXXXXXXX",
                        "Arn": "arn:aws:iam::123456789012:group/Developers",
                        "Path": "/",
                        "CreateDate": datetime(2025, 1, 1, tzinfo=UTC),
                    }
                ],
                "IsTruncated": False,
            },
        )
        stubber.add_response(
            "list_user_tags",
            {"Tags": [{"Key": "team", "Value": "platform"}], "IsTruncated": False},
        )
        users = list(collect_users(client, include_aws_managed=False))
    assert len(users) == 1
    user = users[0]
    assert user.name == "test-user"
    assert user.arn == "arn:aws:iam::123456789012:user/test-user"
    assert user.path == "/"
    assert user.group_memberships == ["Developers"]
    assert user.tags == {"team": "platform"}
    assert user.access_key_last_used == datetime(2025, 12, 1, tzinfo=UTC)


def test_parse_policy_document_normalizes_string_action() -> None:
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
            }
        ],
    }
    result = _parse_policy_document(doc)
    assert result.version == "2012-10-17"
    assert len(result.statements) == 1
    assert result.statements[0].actions == ["s3:GetObject"]
    assert result.statements[0].resources == ["*"]


def test_parse_policy_document_single_statement_as_dict() -> None:
    doc = {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"},
    }
    result = _parse_policy_document(doc)
    assert len(result.statements) == 1
    assert result.statements[0].actions == ["ec2:DescribeInstances"]


def test_parse_policy_document_multiple_statements() -> None:
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket/*"]},
            {"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": ["*"], "Sid": "DenyDelete"},
        ],
    }
    result = _parse_policy_document(doc)
    assert len(result.statements) == 2
    assert result.statements[0].effect == "Allow"
    assert result.statements[0].actions == ["s3:GetObject"]
    assert result.statements[1].effect == "Deny"
    assert result.statements[1].sid == "DenyDelete"


def test_collect_policies_for_user_with_inline_policy() -> None:
    user = IAMUser(
        arn="arn:aws:iam::123456789012:user/test-user",
        name="test-user",
        path="/",
        created_date=datetime(2025, 1, 1, tzinfo=UTC),
        group_memberships=[],
        tags={},
    )
    client = _make_iam_client()
    with Stubber(client) as stubber:
        stubber.add_response(
            "list_attached_user_policies",
            {"AttachedPolicies": [], "IsTruncated": False},
        )
        stubber.add_response(
            "list_user_policies",
            {"PolicyNames": ["user-inline-1"], "IsTruncated": False},
        )
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": ["*"]}
            ],
        }
        stubber.add_response(
            "get_user_policy",
            {
                "UserName": "test-user",
                "PolicyName": "user-inline-1",
                "PolicyDocument": urllib.parse.quote(json.dumps(policy_doc)),
            },
        )
        result = collect_policies_for_principal(client, user)
    assert len(result.attached_policies) == 0
    assert len(result.inline_policies) == 1
    assert result.inline_policies[0].name == "user-inline-1"
    assert result.inline_policies[0].document.statements[0].actions == ["dynamodb:GetItem"]


def test_collect_policies_for_role() -> None:
    role = IAMRole(
        arn="arn:aws:iam::123456789012:role/test-role",
        name="test-role",
        path="/",
        created_date=datetime(2025, 1, 1, tzinfo=UTC),
        tags={},
    )
    client = _make_iam_client()
    with Stubber(client) as stubber:
        stubber.add_response(
            "list_attached_role_policies",
            {"AttachedPolicies": [], "IsTruncated": False},
        )
        stubber.add_response(
            "list_role_policies",
            {"PolicyNames": ["inline-policy-1"], "IsTruncated": False},
        )
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["*"]}
            ],
        }
        stubber.add_response(
            "get_role_policy",
            {
                "RoleName": "test-role",
                "PolicyName": "inline-policy-1",
                "PolicyDocument": urllib.parse.quote(json.dumps(policy_doc)),
            },
        )
        result = collect_policies_for_principal(client, role)
    assert len(result.attached_policies) == 0
    assert len(result.inline_policies) == 1
    assert result.inline_policies[0].name == "inline-policy-1"
    assert result.inline_policies[0].document.statements[0].actions == ["s3:GetObject"]


def test_collect_policies_for_role_with_attached_policy() -> None:
    role = IAMRole(
        arn="arn:aws:iam::123456789012:role/test-role",
        name="test-role",
        path="/",
        created_date=datetime(2025, 1, 1, tzinfo=UTC),
        tags={},
    )
    client = _make_iam_client()
    policy_arn = "arn:aws:iam::123456789012:policy/MyCustomPolicy"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": ["arn:aws:sqs:*:*:my-queue"]}
        ],
    }
    with Stubber(client) as stubber:
        stubber.add_response(
            "list_attached_role_policies",
            {
                "AttachedPolicies": [
                    {"PolicyName": "MyCustomPolicy", "PolicyArn": policy_arn}
                ],
                "IsTruncated": False,
            },
        )
        stubber.add_response(
            "get_policy",
            {
                "Policy": {
                    "PolicyName": "MyCustomPolicy",
                    "PolicyId": "ANPAXXXXXXXXXXXX",
                    "Arn": policy_arn,
                    "Path": "/",
                    "DefaultVersionId": "v1",
                    "AttachmentCount": 1,
                    "CreateDate": datetime(2025, 1, 1, tzinfo=UTC),
                    "UpdateDate": datetime(2025, 1, 1, tzinfo=UTC),
                }
            },
        )
        stubber.add_response(
            "get_policy_version",
            {
                "PolicyVersion": {
                    "Document": urllib.parse.quote(json.dumps(policy_doc)),
                    "VersionId": "v1",
                    "IsDefaultVersion": True,
                    "CreateDate": datetime(2025, 1, 1, tzinfo=UTC),
                }
            },
        )
        stubber.add_response(
            "list_role_policies",
            {"PolicyNames": [], "IsTruncated": False},
        )
        result = collect_policies_for_principal(client, role)
    assert len(result.attached_policies) == 1
    assert result.attached_policies[0].name == "MyCustomPolicy"
    assert result.attached_policies[0].arn == policy_arn
    assert result.attached_policies[0].is_aws_managed is False
    assert result.attached_policies[0].document.statements[0].actions == ["sqs:SendMessage"]
    assert len(result.inline_policies) == 0
