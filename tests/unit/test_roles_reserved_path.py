from __future__ import annotations

from datetime import UTC, datetime

import boto3
from botocore.config import Config
from botocore.stub import Stubber

from iam_audit.collectors.roles import collect_roles

NORMAL = ("normal-role", "/")
RESERVED = ("AWSReservedSSO_Admin_abc", "/aws-reserved/sso.amazonaws.com/")


def _role_entry(name: str, path: str) -> dict:
    return {
        "Arn": f"arn:aws:iam::123456789012:role{path}{name}",
        "RoleName": name,
        "Path": path,
        "CreateDate": datetime(2025, 1, 1, tzinfo=UTC),
        "RoleId": "AROAXXXXXXXXXXXX",
    }


def _collect(roles: list[tuple[str, str]], include_aws_managed: bool):
    config = Config(retries={"total_max_attempts": 1, "mode": "standard"})
    client = boto3.client(
        "iam",
        region_name="us-east-1",
        config=config,
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # noqa: S106
    )
    with Stubber(client) as stubber:
        stubber.add_response(
            "list_roles",
            {"Roles": [_role_entry(n, p) for n, p in roles], "IsTruncated": False},
        )
        expected = roles if include_aws_managed else [r for r in roles if r[1] == "/"]
        for name, path in expected:
            stubber.add_response("get_role", {"Role": _role_entry(name, path)})
            stubber.add_response("list_role_tags", {"Tags": [], "IsTruncated": False})
        return list(collect_roles(client, include_aws_managed=include_aws_managed))


def test_aws_reserved_roles_excluded_by_default() -> None:
    roles = _collect([NORMAL, RESERVED], include_aws_managed=False)
    assert [r.name for r in roles] == ["normal-role"]


def test_aws_reserved_roles_included_when_include_aws_managed() -> None:
    roles = {r.name: r for r in _collect([NORMAL, RESERVED], include_aws_managed=True)}
    reserved = roles[RESERVED[0]]
    assert reserved.is_aws_reserved is True
    assert reserved.is_aws_managed is True
    assert roles["normal-role"].is_aws_reserved is False
    assert roles["normal-role"].is_aws_managed is False
