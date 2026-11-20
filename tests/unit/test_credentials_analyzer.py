"""Tests for the credential hygiene rules and the ``credentials`` check wiring."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from iam_audit import cli
from iam_audit.analyzers.credentials import analyze_credentials, run
from iam_audit.collectors.credential_report import AccessKeyInfo, CredentialReportRow
from iam_audit.models import DataGap, FindingCategory, Severity
from iam_audit.pipeline import AuditContext, get_subcommand
from tests.conftest import make_role, make_user

NOW = datetime(2026, 11, 20, tzinfo=UTC)
ROOT_ARN = "arn:aws:iam::123456789012:root"
COLLECTOR = "iam_audit.analyzers.credentials.collect_credential_report"


def _ago(days: int) -> datetime:
    return NOW - timedelta(days=days)


def _key(
    slot: int = 1, active: bool = False, rotated: int | None = None, used: int | None = None
) -> AccessKeyInfo:
    return AccessKeyInfo(
        slot=slot,
        active=active,
        last_rotated=_ago(rotated) if rotated is not None else None,
        last_used_date=_ago(used) if used is not None else None,
    )


def _pair(keys: tuple[AccessKeyInfo, ...]) -> tuple[AccessKeyInfo, AccessKeyInfo]:
    first = keys[0] if keys else _key(1)
    second = keys[1] if len(keys) > 1 else _key(2)
    return first, second


def _user(
    name: str = "alice",
    *,
    password: bool = False,
    mfa: bool = True,
    password_used: int | None = None,
    created: int = 365,
    keys: tuple[AccessKeyInfo, ...] = (),
) -> CredentialReportRow:
    return CredentialReportRow(
        user=name,
        arn=f"arn:aws:iam::123456789012:user/{name}",
        user_creation_time=_ago(created),
        password_enabled=password,
        password_last_used=_ago(password_used) if password_used is not None else None,
        mfa_active=mfa,
        access_keys=_pair(keys),
    )


def _root(
    *, mfa: bool = True, keys: tuple[AccessKeyInfo, ...] = (), used: int | None = None
) -> CredentialReportRow:
    return CredentialReportRow(
        user="<root_account>",
        arn=ROOT_ARN,
        user_creation_time=_ago(2000),
        password_enabled=None,
        password_last_used=_ago(used) if used is not None else None,
        mfa_active=mfa,
        access_keys=_pair(keys),
    )


def _rules(rows: list[CredentialReportRow], days: int = 90, key_max_age: int = 90) -> list[str]:
    findings = analyze_credentials(rows, NOW, days, key_max_age)
    return sorted(str(f.metadata["rule_id"]) for f in findings)


def test_root_active_access_key_raises_critical_cred_001() -> None:
    findings = analyze_credentials([_root(keys=(_key(1), _key(2, active=True)))], NOW, 90, 90)
    assert [f.metadata["rule_id"] for f in findings] == ["CRED-001"]
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].metadata["active_key_slots"] == [2]
    assert findings[0].category is FindingCategory.CREDENTIAL
    assert findings[0].principal_type == "root"


def test_root_with_mfa_and_no_keys_is_clean() -> None:
    assert _rules([_root()]) == []


def test_root_without_mfa_raises_critical_cred_002() -> None:
    findings = analyze_credentials([_root(mfa=False)], NOW, 90, 90)
    assert [(f.metadata["rule_id"], f.severity) for f in findings] == [("CRED-002", Severity.CRITICAL)]


def test_root_recent_password_use_raises_cred_003_only_inside_window() -> None:
    assert _rules([_root(used=10)]) == ["CRED-003"]
    assert _rules([_root(used=90)]) == ["CRED-003"]
    assert _rules([_root(used=91)]) == []
    assert _rules([_root(used=None)]) == []


def test_user_console_without_mfa_raises_high_cred_004() -> None:
    findings = analyze_credentials([_user(password=True, mfa=False, password_used=1)], NOW, 90, 90)
    assert [(f.metadata["rule_id"], f.severity) for f in findings] == [("CRED-004", Severity.HIGH)]


def test_user_console_with_mfa_or_no_console_is_not_cred_004() -> None:
    assert _rules([_user(password=True, mfa=True, password_used=1)]) == []
    assert _rules([_user(password=False, mfa=False)]) == []


def test_key_not_rotated_within_max_age_raises_cred_005_per_key() -> None:
    keys = (_key(1, active=True, rotated=100, used=1), _key(2, active=True, rotated=100, used=1))
    findings = analyze_credentials([_user(keys=keys)], NOW, 90, 90)
    cred5 = [f for f in findings if f.metadata["rule_id"] == "CRED-005"]
    assert sorted(str(f.metadata["key_slot"]) for f in cred5) == ["1", "2"]
    assert all(f.severity is Severity.MEDIUM for f in cred5)


def test_key_max_age_option_changes_cred_005_boundary() -> None:
    row = _user(keys=(_key(1, active=True, rotated=100, used=1),))
    assert _rules([row], key_max_age=90) == ["CRED-005"]
    assert _rules([row], key_max_age=100) == []
    assert _rules([row], key_max_age=365) == []


def test_inactive_key_is_ignored_by_key_rules() -> None:
    assert _rules([_user(keys=(_key(1, active=False, rotated=500),))]) == []


def test_never_used_active_key_raises_cred_006_when_older_than_days() -> None:
    old = _user(keys=(_key(1, active=True, rotated=91),))
    assert _rules([old], key_max_age=365) == ["CRED-006"]
    fresh = _user(keys=(_key(1, active=True, rotated=10),))
    assert _rules([fresh]) == []
    used = _user(keys=(_key(1, active=True, rotated=91, used=5),))
    assert _rules([used], key_max_age=365) == []


def test_two_active_keys_raise_low_cred_007() -> None:
    keys = (_key(1, active=True, rotated=1, used=1), _key(2, active=True, rotated=1, used=1))
    findings = analyze_credentials([_user(keys=keys)], NOW, 90, 90)
    assert [(f.metadata["rule_id"], f.severity) for f in findings] == [("CRED-007", Severity.LOW)]
    assert _rules([_user(keys=(_key(1, active=True, rotated=1, used=1),))]) == []


def test_unused_console_password_raises_cred_008_only_for_old_users() -> None:
    assert _rules([_user(password=True, password_used=None, created=200)]) == ["CRED-008"]
    assert _rules([_user(password=True, password_used=None, created=10)]) == []
    assert _rules([_user(password=True, password_used=5, created=200)]) == []
    assert _rules([_user(password=False, password_used=None, created=200)]) == []


def test_metadata_dates_are_json_serialisable_iso_strings() -> None:
    row = _user(keys=(_key(1, active=True, rotated=100),))
    findings = analyze_credentials([row], NOW, 90, 90)
    finding = next(f for f in findings if f.metadata["rule_id"] == "CRED-005")
    assert finding.metadata["last_rotated"] == _ago(100).isoformat()
    assert finding.metadata["last_used_date"] is None


def _options(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "days": 90, "key_max_age": 90, "path_prefix": None, "name": None, "tag": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _ctx(options: argparse.Namespace) -> AuditContext:
    return AuditContext(
        iam_client=None,  # type: ignore[arg-type]  # collector is patched
        account_id="123456789012",
        options=options,
        principals=[make_user("alice"), make_role("a-role")],
        now=NOW,
    )


ROWS = [
    _root(mfa=False),
    _user("alice", password=True, mfa=False, password_used=1),
    _user("bob", password=True, mfa=False, password_used=1),
]


def test_run_scopes_to_filtered_users_and_includes_root_without_filters() -> None:
    with patch(COLLECTOR, return_value=(ROWS, [])):
        findings = run(_ctx(_options()))
    assert sorted(f.principal_name for f in findings) == ["<root_account>", "alice"]


def test_run_skips_root_row_when_a_principal_filter_is_applied() -> None:
    for overrides in ({"path_prefix": "/x/"}, {"name": "a*"}, {"tag": ["k=v"]}):
        with patch(COLLECTOR, return_value=(ROWS, [])):
            findings = run(_ctx(_options(**overrides)))
        assert [f.principal_name for f in findings] == ["alice"], overrides


def test_run_appends_collector_data_gaps_and_returns_no_findings() -> None:
    gap = DataGap(principal_arn="credential-report", reason="denied")
    ctx = _ctx(_options())
    with patch(COLLECTOR, return_value=([], [gap])):
        assert run(ctx) == []
    assert ctx.data_gaps == [gap]


def test_credentials_subcommand_and_report_run_the_check() -> None:
    assert get_subcommand("credentials").checks == ("credentials",)
    assert get_subcommand("report").checks[-1] == "credentials"


def test_key_max_age_flag_defaults_to_90_and_is_parsed_on_every_subcommand() -> None:
    parser = cli._build_parser()
    assert parser.parse_args(["credentials"]).key_max_age == 90
    assert parser.parse_args(["report", "--key-max-age", "30"]).key_max_age == 30
