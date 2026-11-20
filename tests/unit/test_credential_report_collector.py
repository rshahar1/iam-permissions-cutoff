"""Tests for credential report generation, polling and CSV parsing."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from iam_audit.collectors.credential_report import (
    collect_credential_report,
    parse_bool,
    parse_credential_report,
    parse_timestamp,
)

HEADER = (
    "user,arn,user_creation_time,password_enabled,password_last_used,mfa_active,"
    "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
    "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date"
)
ROOT_LINE = (
    "<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,not_supported,"
    "2026-11-01T00:00:00+00:00,false,false,N/A,N/A,false,N/A,N/A"
)
USER_LINE = (
    "alice,arn:aws:iam::123456789012:user/alice,2026-01-01T00:00:00+00:00,true,no_information,"
    "true,true,2026-01-02T00:00:00+00:00,N/A,false,N/A,N/A"
)
CSV = "\n".join([HEADER, ROOT_LINE, USER_LINE]) + "\n"


class StubClient:
    """Minimal IAM client stub: reports STARTED for ``pending`` calls, then COMPLETE."""

    def __init__(self, pending: int = 0, error: ClientError | None = None) -> None:
        self.pending = pending
        self.error = error
        self.generate_calls = 0

    def generate_credential_report(self) -> dict[str, Any]:
        self.generate_calls += 1
        if self.error:
            raise self.error
        done = self.generate_calls > self.pending
        return {"State": "COMPLETE" if done else "STARTED"}

    def get_credential_report(self) -> dict[str, Any]:
        return {"Content": CSV.encode()}


def _access_denied() -> ClientError:
    error = {"Error": {"Code": "AccessDenied", "Message": "denied"}}
    return ClientError(error, "GenerateCredentialReport")  # type: ignore[arg-type]


def test_parse_bool_maps_true_false_and_unknown_values() -> None:
    assert parse_bool("true") is True
    assert parse_bool("false") is False
    assert parse_bool("not_supported") is None
    assert parse_bool(None) is None


def test_parse_timestamp_returns_none_for_placeholder_values() -> None:
    for value in ("N/A", "no_information", "not_supported", "", None, "garbage"):
        assert parse_timestamp(value) is None


def test_parse_timestamp_reads_iso_8601_with_offset() -> None:
    assert parse_timestamp("2026-01-02T03:04:05+00:00") == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert parse_timestamp("2026-01-02T03:04:05Z") == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_parse_credential_report_decodes_root_and_user_rows() -> None:
    root, alice = parse_credential_report(CSV.encode())
    assert root.is_root
    assert root.password_enabled is None
    assert root.mfa_active is False
    assert root.password_last_used == datetime(2026, 11, 1, tzinfo=UTC)
    assert not alice.is_root
    assert alice.password_enabled is True
    assert alice.password_last_used is None
    assert [key.slot for key in alice.active_keys] == [1]
    key = alice.access_keys[0]
    assert key.last_rotated == datetime(2026, 1, 2, tzinfo=UTC)
    assert key.last_used_date is None


def test_collect_polls_until_report_is_complete_with_backoff() -> None:
    sleeps: list[float] = []
    client = StubClient(pending=3)
    rows, gaps = collect_credential_report(client, sleep=sleeps.append)  # type: ignore[arg-type]
    assert len(rows) == 2
    assert gaps == []
    assert sleeps == [1.0, 2.0, 4.0]


def test_collect_times_out_and_records_a_data_gap() -> None:
    sleeps: list[float] = []
    client = StubClient(pending=10_000)
    rows, gaps = collect_credential_report(client, sleep=sleeps.append, timeout=10)  # type: ignore[arg-type]
    assert rows == []
    assert [g.principal_arn for g in gaps] == ["credential-report"]
    assert "not ready" in gaps[0].reason
    assert sum(sleeps) >= 10


def test_collect_access_denied_records_a_data_gap() -> None:
    client = StubClient(error=_access_denied())
    rows, gaps = collect_credential_report(client, sleep=lambda _: None)  # type: ignore[arg-type]
    assert rows == []
    assert gaps[0].principal_arn == "credential-report"
    assert "AccessDenied" in gaps[0].reason


@mock_aws
def test_collect_parses_a_real_moto_credential_report() -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Example-Passw0rd!")  # moto emulator only
    iam.create_access_key(UserName="alice")
    rows, gaps = collect_credential_report(iam, sleep=lambda _: None)
    assert gaps == []
    alice = next(row for row in rows if row.user == "alice")
    assert alice.arn == "arn:aws:iam::123456789012:user/alice"
    assert alice.password_enabled is True
    assert alice.mfa_active is False
    assert [key.slot for key in alice.active_keys] == [1]
    assert alice.access_keys[0].last_used_date is None
