"""Collect and parse the IAM credential report (one CSV row per user plus the root account)."""

from __future__ import annotations

import csv
import io
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from botocore.exceptions import ClientError

from iam_audit.models import DataGap

if TYPE_CHECKING:
    from collections.abc import Callable

    from mypy_boto3_iam import IAMClient

ROOT_USER = "<root_account>"
GAP_PRINCIPAL = "credential-report"
DEFAULT_TIMEOUT_SECONDS = 60.0
_MAX_DELAY_SECONDS = 8.0


@dataclass(frozen=True)
class AccessKeyInfo:
    """One of the two access key slots of a credential report row."""

    slot: int
    active: bool
    last_rotated: datetime | None
    last_used_date: datetime | None


@dataclass(frozen=True)
class CredentialReportRow:
    """The credential report columns the credential checks read."""

    user: str
    arn: str
    user_creation_time: datetime | None
    password_enabled: bool | None
    password_last_used: datetime | None
    mfa_active: bool
    access_keys: tuple[AccessKeyInfo, ...]

    @property
    def is_root(self) -> bool:
        """True for the account root row."""
        return self.user == ROOT_USER

    @property
    def active_keys(self) -> list[AccessKeyInfo]:
        """Access keys that are currently active."""
        return [key for key in self.access_keys if key.active]


def parse_bool(value: str | None) -> bool | None:
    """Parse ``true``/``false``; anything else (``not_supported``, ``N/A``) is None."""
    text = (value or "").strip().lower()
    if text == "true":
        return True
    if text == "false":
        return False
    return None


def parse_timestamp(value: str | None) -> datetime | None:
    """Parse an ISO 8601 timestamp; ``N/A``, ``no_information``, ``not_supported`` give None."""
    text = (value or "").strip()
    if not text or text in {"N/A", "no_information", "not_supported"}:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _parse_key(record: dict[str, str], slot: int) -> AccessKeyInfo:
    prefix = f"access_key_{slot}_"
    return AccessKeyInfo(
        slot=slot,
        active=parse_bool(record.get(prefix + "active")) is True,
        last_rotated=parse_timestamp(record.get(prefix + "last_rotated")),
        last_used_date=parse_timestamp(record.get(prefix + "last_used_date")),
    )


def parse_credential_report(content: bytes | str) -> list[CredentialReportRow]:
    """Decode the credential report CSV into rows."""
    text = content.decode("utf-8-sig") if isinstance(content, bytes) else content
    rows: list[CredentialReportRow] = []
    for record in csv.DictReader(io.StringIO(text)):
        rows.append(
            CredentialReportRow(
                user=record.get("user", ""),
                arn=record.get("arn", ""),
                user_creation_time=parse_timestamp(record.get("user_creation_time")),
                password_enabled=parse_bool(record.get("password_enabled")),
                password_last_used=parse_timestamp(record.get("password_last_used")),
                mfa_active=parse_bool(record.get("mfa_active")) is True,
                access_keys=(_parse_key(record, 1), _parse_key(record, 2)),
            )
        )
    return rows


def _wait_until_complete(
    iam_client: IAMClient, sleep: Callable[[float], None], timeout: float
) -> None:
    """Request generation and poll with exponential backoff until COMPLETE or timeout."""
    waited = 0.0
    delay = 1.0
    while iam_client.generate_credential_report().get("State") != "COMPLETE":
        if waited >= timeout:
            raise TimeoutError(f"credential report not ready after {timeout:.0f}s")
        sleep(delay)
        waited += delay
        delay = min(delay * 2, _MAX_DELAY_SECONDS)


def collect_credential_report(
    iam_client: IAMClient,
    sleep: Callable[[float], None] = time.sleep,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[list[CredentialReportRow], list[DataGap]]:
    """Generate and fetch the credential report; failures become a ``DataGap``."""
    try:
        _wait_until_complete(iam_client, sleep, timeout)
        content = iam_client.get_credential_report()["Content"]
        return parse_credential_report(content), []
    except (ClientError, TimeoutError) as exc:
        reason = f"Credential report unavailable: {exc}"
        return [], [DataGap(principal_arn=GAP_PRINCIPAL, reason=reason)]
