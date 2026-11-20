from __future__ import annotations

from typing import TYPE_CHECKING

from iam_audit.models import IAMUser

if TYPE_CHECKING:
    from collections.abc import Generator


def _fetch_user_tags(iam_client, user_name: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    marker = None
    while True:
        kwargs: dict = {"UserName": user_name}
        if marker:
            kwargs["Marker"] = marker
        resp = iam_client.list_user_tags(**kwargs)
        for tag in resp.get("Tags", []):
            tags[tag["Key"]] = tag["Value"]
        if not resp.get("IsTruncated"):
            break
        marker = resp.get("Marker")
    return tags


def _most_recent_access_key_used(iam_client, user_name: str):
    access_key_paginator = iam_client.get_paginator("list_access_keys")
    most_recent = None
    for page in access_key_paginator.paginate(UserName=user_name):
        for key in page.get("AccessKeyMetadata", []):
            key_id = key["AccessKeyId"]
            used = iam_client.get_access_key_last_used(AccessKeyId=key_id)
            last_used = used.get("AccessKeyLastUsed", {}).get("LastUsedDate")
            if last_used and (most_recent is None or last_used > most_recent):
                most_recent = last_used
    return most_recent


def _fetch_group_names(iam_client, user_name: str) -> list[str]:
    paginator = iam_client.get_paginator("list_groups_for_user")
    groups = []
    for page in paginator.paginate(UserName=user_name):
        for g in page.get("Groups", []):
            groups.append(g["GroupName"])
    return groups


def collect_users(
    iam_client,
    include_aws_managed: bool = False,
) -> Generator[IAMUser, None, None]:
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            access_key_last_used = _most_recent_access_key_used(
                iam_client, user["UserName"]
            )
            group_memberships = _fetch_group_names(iam_client, user["UserName"])
            tags = _fetch_user_tags(iam_client, user["UserName"])

            yield IAMUser(
                arn=user["Arn"],
                name=user["UserName"],
                path=user.get("Path", ""),
                created_date=user["CreateDate"],
                password_last_used=user.get("PasswordLastUsed"),
                access_key_last_used=access_key_last_used,
                group_memberships=group_memberships,
                is_aws_managed=False,
                tags=tags,
            )
