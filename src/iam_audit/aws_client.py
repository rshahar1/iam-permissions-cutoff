from __future__ import annotations

from typing import TYPE_CHECKING

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_iam import IAMClient

_RETRY_CONFIG = Config(retries={"total_max_attempts": 10, "mode": "standard"})


def create_session(region: str | None = None) -> boto3.Session:
    return boto3.Session(region_name=region)


def create_iam_client(
    region: str | None = None, session: boto3.Session | None = None
) -> IAMClient:
    if session is None:
        session = create_session(region)
    return session.client("iam", config=_RETRY_CONFIG)


def get_account_id(session: boto3.Session) -> str:
    sts = session.client("sts", config=_RETRY_CONFIG)
    return str(sts.get_caller_identity()["Account"])


def check_iam_permissions(iam_client: IAMClient) -> None:
    try:
        iam_client.list_roles(MaxItems=1)
    except ClientError as e:
        if e.response["Error"]["Code"] in ("AccessDenied", "InvalidClientTokenId"):
            raise PermissionError(
                f"Missing required IAM permission: iam:ListRoles. {e.response['Error'].get('Message', str(e))}"
            ) from e
        raise
