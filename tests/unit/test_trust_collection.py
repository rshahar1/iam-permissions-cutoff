"""Parsing of Principal/NotPrincipal, role trust-policy collection and pipeline wiring."""

from __future__ import annotations

import json
import urllib.parse
from datetime import UTC, datetime

import boto3
from botocore.config import Config
from botocore.stub import Stubber

from iam_audit.collectors.policies import _parse_policy_document, load_policy_document
from iam_audit.collectors.roles import collect_roles
from iam_audit.models import FindingCategory, IAMRole, PolicyStatement
from iam_audit.pipeline import CHECKS, get_subcommand

TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "*"}}],
}


def _statement(**fields: object) -> PolicyStatement:
    doc = _parse_policy_document(
        {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", **fields}]}
    )
    return doc.statements[0]


def test_principal_star_string_normalizes_to_aws_wildcard() -> None:
    assert _statement(Principal="*").principals == {"AWS": ["*"]}


def test_principal_dict_string_value_normalizes_to_list() -> None:
    assert _statement(Principal={"AWS": "111122223333"}).principals == {"AWS": ["111122223333"]}


def test_principal_dict_list_value_is_preserved() -> None:
    stmt = _statement(Principal={"AWS": ["1", "2"], "Service": "ec2.amazonaws.com"})
    assert stmt.principals == {"AWS": ["1", "2"], "Service": ["ec2.amazonaws.com"]}


def test_not_principal_is_parsed_like_principal() -> None:
    stmt = _statement(NotPrincipal={"AWS": "111122223333"})
    assert stmt.not_principals == {"AWS": ["111122223333"]}
    assert stmt.principals is None


def test_statement_without_principal_defaults_to_none() -> None:
    stmt = _statement()
    assert stmt.principals is None
    assert stmt.not_principals is None


def _collect_with_trust(raw: object) -> list[IAMRole]:
    client = boto3.client(
        "iam", region_name="us-east-1",
        config=Config(retries={"total_max_attempts": 1, "mode": "standard"}),
        aws_access_key_id="testing", aws_secret_access_key="testing",  # noqa: S106
    )
    entry = {
        "Arn": "arn:aws:iam::123456789012:role/app", "RoleName": "app", "Path": "/",
        "CreateDate": datetime(2025, 1, 1, tzinfo=UTC), "RoleId": "AROAXXXXXXXXXXXX",
        "AssumeRolePolicyDocument": raw,
    }
    with Stubber(client) as stubber:
        # botocore decodes the policy string in place, so each response needs its own copy.
        stubber.add_response("list_roles", {"Roles": [{**entry}], "IsTruncated": False})
        stubber.add_response("get_role", {"Role": {**entry}})
        stubber.add_response("list_role_tags", {"Tags": [], "IsTruncated": False})
        return list(collect_roles(client))


def test_collect_roles_populates_trust_policy_from_list_roles() -> None:
    # botocore URL-decodes the stubbed JSON string into a dict, as for real responses.
    (role,) = _collect_with_trust(json.dumps(TRUST))
    assert role.trust_policy is not None
    assert role.trust_policy.statements[0].principals == {"AWS": ["*"]}


def test_load_policy_document_decodes_url_encoded_string() -> None:
    doc = load_policy_document(urllib.parse.quote(json.dumps(TRUST)))
    assert doc.statements[0].actions == ["sts:AssumeRole"]
    assert doc.statements[0].principals == {"AWS": ["*"]}


def test_trust_check_registered_last_and_runs_in_permissions_and_report() -> None:
    assert list(CHECKS)[-1] == "trust"
    assert get_subcommand("permissions").checks[-1] == "trust"
    assert get_subcommand("report").checks[-1] == "trust"
    assert "trust" not in get_subcommand("dormancy").checks
    assert CHECKS["trust"].needs_policies is False


def test_trust_policy_category_has_display_name_and_value() -> None:
    assert FindingCategory.TRUST_POLICY.value == "trust_policy"
    assert FindingCategory.TRUST_POLICY.display_name == "Trust Policy Findings"
    assert list(FindingCategory)[-1] is FindingCategory.TRUST_POLICY
