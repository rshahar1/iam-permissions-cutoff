from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from iam_audit.aws_client import check_iam_permissions, create_iam_client, get_account_id


def test_create_iam_client_returns_client() -> None:
    with patch("iam_audit.aws_client.create_session") as mock_create_session:
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_create_session.return_value = mock_session
        result = create_iam_client()
    assert result is mock_client
    assert hasattr(result, "list_roles")


def test_get_account_id() -> None:
    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_session.client.return_value = mock_sts
    result = get_account_id(mock_session)
    assert result == "123456789012"


def test_check_iam_permissions_success() -> None:
    mock_client = MagicMock()
    mock_client.list_roles.return_value = {"Roles": [], "IsTruncated": False}
    check_iam_permissions(mock_client)
    mock_client.list_roles.assert_called_once_with(MaxItems=1)


def test_check_iam_permissions_access_denied() -> None:
    mock_client = MagicMock()
    mock_client.list_roles.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "User is not authorized"}},
        "ListRoles",
    )
    with pytest.raises(PermissionError) as exc_info:
        check_iam_permissions(mock_client)
    assert "Missing required IAM permission" in str(exc_info.value)
    assert "iam:ListRoles" in str(exc_info.value)


def test_check_iam_permissions_invalid_token() -> None:
    mock_client = MagicMock()
    mock_client.list_roles.side_effect = ClientError(
        {"Error": {"Code": "InvalidClientTokenId", "Message": "The security token is invalid"}},
        "ListRoles",
    )
    with pytest.raises(PermissionError) as exc_info:
        check_iam_permissions(mock_client)
    assert "Missing required IAM permission" in str(exc_info.value)


def test_check_iam_permissions_other_client_error_reraised() -> None:
    mock_client = MagicMock()
    mock_client.list_roles.side_effect = ClientError(
        {"Error": {"Code": "ServiceUnavailable", "Message": "Temporary failure"}},
        "ListRoles",
    )
    with pytest.raises(ClientError):
        check_iam_permissions(mock_client)
