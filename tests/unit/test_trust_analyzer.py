"""Rule-by-rule tests for trust-policy analysis."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime

import pytest

from iam_audit.analyzers.trust import add_trust_arguments, analyze_role_trust, run
from iam_audit.collectors.policies import _parse_policy_document
from iam_audit.models import Finding, FindingCategory, IAMRole, IAMUser, Severity
from iam_audit.pipeline import AuditContext

ACCOUNT = "123456789012"
OTHER = "999988887777"
GH = "token.actions.githubusercontent.com"
GH_ARN = f"arn:aws:iam::{ACCOUNT}:oidc-provider/{GH}"


def _role(statements: list[dict], path: str = "/", **flags: bool) -> IAMRole:
    doc = _parse_policy_document({"Version": "2012-10-17", "Statement": statements})
    return IAMRole(
        arn=f"arn:aws:iam::{ACCOUNT}:role{path}r", name="r", path=path,
        created_date=datetime(2025, 1, 1, tzinfo=UTC), trust_policy=doc, **flags,
    )


def _stmt(principal: object, action: str = "sts:AssumeRole", **extra: object) -> dict:
    return {"Effect": "Allow", "Action": action, "Principal": principal, **extra}


def _analyze(statements: list[dict], trusted: frozenset[str] = frozenset(), **kw: bool) -> list[Finding]:
    return analyze_role_trust(_role(statements, **kw), ACCOUNT, trusted)


def _ids(findings: list[Finding]) -> list[str]:
    return [str(f.metadata["rule_id"]) for f in findings]


# --- TRUST-001 ---------------------------------------------------------------

def test_trust_001_critical_for_wildcard_aws_principal_without_condition() -> None:
    findings = _analyze([_stmt({"AWS": "*"})])
    assert _ids(findings) == ["TRUST-001"]
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].category is FindingCategory.TRUST_POLICY


def test_trust_001_fires_for_bare_string_principal_star() -> None:
    assert _ids(_analyze([_stmt("*")])) == ["TRUST-001"]


@pytest.mark.parametrize("key", [
    "aws:PrincipalOrgID", "aws:PrincipalOrgPaths", "aws:PrincipalAccount", "aws:PrincipalArn",
    "aws:SourceAccount", "aws:SourceArn", "aws:SourceOrgID",
])
def test_trust_001_suppressed_by_each_restricting_key(key: str) -> None:
    assert _analyze([_stmt("*", Condition={"StringEquals": {key: "o-abc"}})]) == []


def test_trust_001_restricting_key_is_case_insensitive_and_any_operator() -> None:
    cond = {"ForAnyValue:StringLike": {"AWS:PRINCIPALORGID": ["o-abc"]}}
    assert _analyze([_stmt("*", Condition=cond)]) == []


def test_trust_001_not_suppressed_by_non_restricting_condition() -> None:
    cond = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    assert _ids(_analyze([_stmt("*", Condition=cond)])) == ["TRUST-001"]


# --- TRUST-002 ---------------------------------------------------------------

def test_trust_002_high_for_allow_with_not_principal() -> None:
    stmt = {"Effect": "Allow", "Action": "sts:AssumeRole",
            "NotPrincipal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}}
    findings = _analyze([stmt])
    assert _ids(findings) == ["TRUST-002"]
    assert findings[0].severity is Severity.HIGH


def test_trust_002_not_raised_for_deny_with_not_principal() -> None:
    stmt = {"Effect": "Deny", "Action": "sts:AssumeRole", "NotPrincipal": {"AWS": "x"}}
    assert _analyze([stmt]) == []


# --- TRUST-003 / TRUST-004 ---------------------------------------------------

def test_trust_003_high_for_foreign_account_id_without_external_id() -> None:
    findings = _analyze([_stmt({"AWS": OTHER})])
    assert _ids(findings) == ["TRUST-003"]
    assert findings[0].severity is Severity.HIGH


def test_trust_003_detects_account_in_role_arn() -> None:
    findings = _analyze([_stmt({"AWS": f"arn:aws:iam::{OTHER}:role/x"})])
    assert _ids(findings) == ["TRUST-003"]
    assert OTHER in str(findings[0].metadata["principal"])


def test_trust_004_low_when_external_id_present() -> None:
    cond = {"StringEquals": {"sts:ExternalId": "abc"}}
    findings = _analyze([_stmt({"AWS": OTHER}, Condition=cond)])
    assert _ids(findings) == ["TRUST-004"]
    assert findings[0].severity is Severity.LOW


def test_trust_003_external_id_key_is_case_insensitive() -> None:
    cond = {"StringEquals": {"STS:EXTERNALID": "abc"}}
    assert _ids(_analyze([_stmt({"AWS": OTHER}, Condition=cond)])) == ["TRUST-004"]


def test_cross_account_rules_skip_audited_account() -> None:
    assert _analyze([_stmt({"AWS": [ACCOUNT, f"arn:aws:iam::{ACCOUNT}:root"]})]) == []


def test_cross_account_rules_skip_trusted_accounts() -> None:
    assert _analyze([_stmt({"AWS": OTHER})], trusted=frozenset({OTHER})) == []


def test_cross_account_one_finding_per_statement_listing_all_accounts() -> None:
    findings = _analyze([_stmt({"AWS": [OTHER, "111122223333"]})])
    assert len(findings) == 1
    assert OTHER in str(findings[0].metadata["principal"])
    assert "111122223333" in str(findings[0].metadata["principal"])


def test_cross_account_ignores_service_principals() -> None:
    assert _analyze([_stmt({"Service": "lambda.amazonaws.com"})]) == []


# --- GitHub OIDC -------------------------------------------------------------

def _gh(**conditions: object) -> dict:
    stmt = _stmt({"Federated": GH_ARN}, "sts:AssumeRoleWithWebIdentity")
    if conditions:
        stmt["Condition"] = {"StringLike": conditions}
    return stmt


def test_trust_005_critical_for_github_without_sub_condition() -> None:
    findings = _analyze([_gh()])
    assert _ids(findings) == ["TRUST-005"]
    assert findings[0].severity is Severity.CRITICAL
    assert "repo:my-org/my-repo" in findings[0].recommendation


@pytest.mark.parametrize("sub", ["*", "repo:*", "repo:*:*"])
def test_trust_005_fires_for_wildcard_sub(sub: str) -> None:
    assert _ids(_analyze([_gh(**{f"{GH}:sub": sub})])) == ["TRUST-005"]


def test_trust_005_fires_when_every_sub_value_is_wildcard() -> None:
    assert _ids(_analyze([_gh(**{f"{GH}:sub": ["*", "repo:*"]})])) == ["TRUST-005"]


def test_trust_005_not_raised_when_a_sub_value_is_specific() -> None:
    cond = {f"{GH}:sub": ["repo:org/app:*"], f"{GH}:aud": "sts.amazonaws.com"}
    assert _analyze([_gh(**cond)]) == []


def test_github_condition_keys_are_case_insensitive() -> None:
    cond = {f"{GH.upper()}:SUB": "repo:org/app:*", f"{GH}:AUD": "sts.amazonaws.com"}
    assert _analyze([_gh(**cond)]) == []


def test_trust_006_medium_for_valid_sub_without_aud() -> None:
    findings = _analyze([_gh(**{f"{GH}:sub": "repo:org/app:ref:refs/heads/main"})])
    assert _ids(findings) == ["TRUST-006"]
    assert findings[0].severity is Severity.MEDIUM


def test_trust_006_not_raised_alongside_trust_005() -> None:
    assert _ids(_analyze([_gh()])) == ["TRUST-005"]


def test_github_bare_host_federated_value_is_recognised() -> None:
    stmt = _stmt({"Federated": GH}, "sts:AssumeRoleWithWebIdentity")
    assert _ids(_analyze([stmt])) == ["TRUST-005"]


# --- other OIDC / Cognito / SAML --------------------------------------------

def test_trust_007_high_for_other_oidc_without_sub() -> None:
    arn = f"arn:aws:iam::{ACCOUNT}:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABC"
    findings = _analyze([_stmt({"Federated": arn}, "sts:AssumeRoleWithWebIdentity")])
    assert _ids(findings) == ["TRUST-007"]
    assert findings[0].severity is Severity.HIGH


def test_trust_007_suppressed_by_provider_sub_condition() -> None:
    host = "oidc.eks.us-east-1.amazonaws.com/id/ABC"
    stmt = _stmt(
        {"Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/{host}"},
        "sts:AssumeRoleWithWebIdentity",
        Condition={"StringEquals": {f"{host}:sub": "system:serviceaccount:ns:sa"}},
    )
    assert _analyze([stmt]) == []


def test_trust_007_applies_to_bare_provider_host() -> None:
    stmt = _stmt({"Federated": "accounts.google.com"}, "sts:AssumeRoleWithWebIdentity")
    assert _ids(_analyze([stmt])) == ["TRUST-007"]


def test_trust_008_high_for_cognito_without_aud() -> None:
    stmt = _stmt({"Federated": "cognito-identity.amazonaws.com"}, "sts:AssumeRoleWithWebIdentity")
    findings = _analyze([stmt])
    assert _ids(findings) == ["TRUST-008"]
    assert findings[0].severity is Severity.HIGH


def test_trust_008_suppressed_by_cognito_aud() -> None:
    cond = {"StringEquals": {"cognito-identity.amazonaws.com:aud": "us-east-1:pool"}}
    stmt = _stmt(
        {"Federated": "cognito-identity.amazonaws.com"}, "sts:AssumeRoleWithWebIdentity", Condition=cond
    )
    assert _analyze([stmt]) == []


def test_trust_009_medium_for_saml_without_aud() -> None:
    stmt = _stmt({"Federated": f"arn:aws:iam::{ACCOUNT}:saml-provider/Okta"}, "sts:AssumeRoleWithSAML")
    findings = _analyze([stmt])
    assert _ids(findings) == ["TRUST-009"]
    assert findings[0].severity is Severity.MEDIUM


def test_trust_009_suppressed_by_saml_aud_case_insensitive() -> None:
    cond = {"StringEquals": {"saml:aud": "https://signin.aws.amazon.com/saml"}}
    stmt = _stmt(
        {"Federated": f"arn:aws:iam::{ACCOUNT}:saml-provider/Okta"}, "sts:AssumeRoleWithSAML", Condition=cond
    )
    assert _analyze([stmt]) == []


# --- statement and role scoping ---------------------------------------------

def test_deny_statements_are_ignored() -> None:
    stmt = {"Effect": "Deny", "Action": "sts:AssumeRole", "Principal": "*"}
    assert _analyze([stmt]) == []


def test_statements_without_assume_action_are_ignored() -> None:
    assert _analyze([_stmt("*", action="s3:GetObject")]) == []


@pytest.mark.parametrize("action", ["sts:*", "*", "STS:ASSUMEROLE", "sts:AssumeRole*"])
def test_assume_action_globs_are_case_insensitive(action: str) -> None:
    assert _ids(_analyze([_stmt("*", action=action)])) == ["TRUST-001"]


def test_not_action_excluding_every_assume_action_is_ignored() -> None:
    stmt = {"Effect": "Allow", "NotAction": "sts:*", "Principal": "*"}
    assert _analyze([stmt]) == []


def test_service_linked_role_is_skipped() -> None:
    assert _analyze([_stmt("*")], is_service_linked=True) == []


def test_aws_reserved_role_is_skipped() -> None:
    assert _analyze([_stmt("*")], is_aws_reserved=True) == []


def test_reserved_path_role_is_skipped_even_without_flags() -> None:
    role = _role([_stmt("*")], path="/aws-reserved/sso.amazonaws.com/")
    assert analyze_role_trust(role, ACCOUNT, frozenset()) == []


def test_role_without_trust_policy_yields_no_findings() -> None:
    role = _role([])
    role.trust_policy = None
    assert analyze_role_trust(role, ACCOUNT, frozenset()) == []


def test_finding_metadata_has_rule_sid_principal_and_condition_keys() -> None:
    cond = {"StringEquals": {"sts:ExternalId": "x"}}
    finding = _analyze([_stmt({"AWS": OTHER}, Sid="Partner", Condition=cond)])[0]
    assert finding.metadata == {
        "rule_id": "TRUST-004", "statement_sid": "Partner",
        "principal": OTHER, "condition_keys": ["sts:externalid"],
    }
    assert finding.principal_type == "role"


# --- check entry point and CLI flag -----------------------------------------

def _ctx(options: argparse.Namespace, principals: list) -> AuditContext:
    return AuditContext(
        iam_client=None,  # type: ignore[arg-type]  # the trust check never calls AWS
        account_id=ACCOUNT, options=options, principals=principals,
    )


def test_run_skips_users_and_honours_trusted_accounts_option() -> None:
    user = IAMUser(
        arn="arn:aws:iam::1:user/u", name="u", path="/", created_date=datetime(2025, 1, 1, tzinfo=UTC)
    )
    role = _role([_stmt({"AWS": OTHER})])
    opts = argparse.Namespace(trusted_accounts=[f"111122223333, {OTHER}"])
    assert run(_ctx(opts, [user, role])) == []
    assert _ids(run(_ctx(argparse.Namespace(trusted_accounts=None), [user, role]))) == ["TRUST-003"]


def test_run_works_when_option_missing_from_namespace() -> None:
    assert _ids(run(_ctx(argparse.Namespace(), [_role([_stmt("*")])]))) == ["TRUST-001"]


def test_trusted_accounts_flag_is_repeatable_and_comma_separated() -> None:
    parser = argparse.ArgumentParser()
    add_trust_arguments(parser)
    args = parser.parse_args(
        ["--trusted-accounts", "111122223333,444455556666", "--trusted-accounts", OTHER]
    )
    assert args.trusted_accounts == ["111122223333,444455556666", OTHER]


def test_trusted_accounts_flag_rejects_non_account_ids() -> None:
    parser = argparse.ArgumentParser()
    add_trust_arguments(parser)
    with pytest.raises(SystemExit):
        parser.parse_args(["--trusted-accounts", "not-an-account"])
