from __future__ import annotations

import pytest

from iam_audit.collectors.policies import _parse_policy_document


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("s3:DeleteBucket", ["s3:DeleteBucket"]),
        (["s3:DeleteBucket", "s3:Get*"], ["s3:DeleteBucket", "s3:Get*"]),
    ],
)
def test_parse_notaction_accepts_string_or_list(raw, expected) -> None:
    doc = {"Statement": [{"Effect": "Allow", "NotAction": raw, "Resource": "*"}]}
    stmt = _parse_policy_document(doc).statements[0]
    assert stmt.not_actions == expected
    assert stmt.actions == []


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("arn:aws:s3:::b", ["arn:aws:s3:::b"]),
        (["arn:aws:s3:::b", "arn:aws:s3:::c"], ["arn:aws:s3:::b", "arn:aws:s3:::c"]),
    ],
)
def test_parse_notresource_accepts_string_or_list(raw, expected) -> None:
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "NotResource": raw}]}
    stmt = _parse_policy_document(doc).statements[0]
    assert stmt.not_resources == expected
    assert stmt.resources == []


def test_parse_missing_action_and_resource_yield_empty_lists() -> None:
    stmt = _parse_policy_document({"Statement": [{"Effect": "Deny"}]}).statements[0]
    assert stmt.actions == []
    assert stmt.resources == []
    assert stmt.not_actions == []
    assert stmt.not_resources == []


def test_parse_single_statement_dict_is_supported() -> None:
    doc = {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}
    parsed = _parse_policy_document(doc)
    assert len(parsed.statements) == 1
    assert parsed.statements[0].actions == ["s3:GetObject"]
    assert parsed.statements[0].resources == ["*"]
