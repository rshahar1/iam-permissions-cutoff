"""Trust-policy analysis: flags risky ``AssumeRolePolicyDocument`` statements on roles.

Scope is roles only; service-linked and ``/aws-reserved/`` roles are skipped because AWS
manages their trust. Only ``Allow`` statements that grant an assume action are examined.
Each rule in :data:`RULES` is a data row (id, severity, text) plus a detector that returns
the offending principals of one statement; one finding is emitted per statement per rule.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Callable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

from iam_audit.models import Finding, FindingCategory, IAMRole, PolicyStatement, Severity

if TYPE_CHECKING:
    from iam_audit.pipeline import AuditContext

ASSUME_ACTIONS = ("sts:assumerole", "sts:assumerolewithwebidentity", "sts:assumerolewithsaml")
RESTRICTING_KEYS = frozenset(
    key.lower()
    for key in (
        "aws:PrincipalOrgID", "aws:PrincipalOrgPaths", "aws:PrincipalAccount",
        "aws:PrincipalArn", "aws:SourceAccount", "aws:SourceArn", "aws:SourceOrgID",
    )
)
GITHUB_PROVIDER = "token.actions.githubusercontent.com"
COGNITO_PROVIDER = "cognito-identity.amazonaws.com"
_ACCOUNT_RE = re.compile(r"^(?:arn:aws[\w-]*:(?:iam|sts)::)?(\d{12})(?::.*)?$")
_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
_BARE_HOST_RE = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+(/.*)?$")


@dataclass(frozen=True)
class StatementView:
    """One applicable trust statement with its normalized condition keys and scan inputs."""

    statement: PolicyStatement
    conditions: dict[str, list[str]]
    account_id: str
    trusted_accounts: frozenset[str]

    @property
    def principals(self) -> dict[str, list[str]]:
        """The statement's ``Principal`` map (empty when absent)."""
        return self.statement.principals or {}


Detector = Callable[[StatementView], list[str]]


@dataclass(frozen=True)
class TrustRule:
    """A trust-policy rule: static text plus the detector that finds offending principals."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    detect: Detector


def is_constraining_operator(operator: str) -> bool:
    """True if a condition operator requires the key to be present and to match.

    Negated operators (``StringNotEquals``, ``ArnNotLike``, ...), ``Null`` and
    ``...IfExists`` variants (which pass when the key is missing) do not limit who
    can assume the role, so they never count as a restricting condition.
    """
    name = operator.split(":")[-1].lower()
    return "not" not in name and name != "null" and not name.endswith("ifexists")


def normalize_conditions(conditions: dict[str, Any] | None) -> dict[str, list[str]]:
    """Flatten ``{operator: {key: value}}`` to ``{lowercase key: [values]}``.

    Only constraining operators are kept (see :func:`is_constraining_operator`).
    """
    result: dict[str, list[str]] = {}
    for operator, operator_block in (conditions or {}).items():
        if not isinstance(operator_block, dict) or not is_constraining_operator(str(operator)):
            continue
        for key, value in operator_block.items():
            values = value if isinstance(value, list) else [value]
            result.setdefault(str(key).lower(), []).extend(str(v) for v in values)
    return result


def grants_assume(statement: PolicyStatement) -> bool:
    """True if an ``Allow`` statement grants an assume action (via Action or NotAction)."""
    if statement.effect != "Allow":
        return False
    if statement.not_actions:
        return any(
            not any(fnmatchcase(action, pattern.lower()) for pattern in statement.not_actions)
            for action in ASSUME_ACTIONS
        )
    return any(
        fnmatchcase(action, pattern.lower())
        for pattern in statement.actions
        for action in ASSUME_ACTIONS
    )


def _federated(view: StatementView) -> list[str]:
    return view.principals.get("Federated", [])


def _account_of(principal: str) -> str | None:
    match = _ACCOUNT_RE.match(principal)
    return match.group(1) if match else None


def _oidc_provider(value: str) -> str | None:
    """Return the OIDC provider host/path for a Federated value, or None if not OIDC."""
    lowered = value.lower()
    if "oidc-provider/" in lowered:
        return lowered.split("oidc-provider/", 1)[1]
    if lowered.startswith("arn:") or ":" in lowered:
        return None
    return lowered if _BARE_HOST_RE.match(lowered) else None


def _detect_any_account(view: StatementView) -> list[str]:
    if "*" in view.principals.get("AWS", []) and not RESTRICTING_KEYS & view.conditions.keys():
        return ["*"]
    return []


def _detect_not_principal(view: StatementView) -> list[str]:
    not_principals = view.statement.not_principals
    if not_principals is None:
        return []
    return [f"{kind}:{value}" for kind, values in not_principals.items() for value in values]


def _untrusted_accounts(view: StatementView) -> list[str]:
    allowed = view.trusted_accounts | {view.account_id}
    found = []
    for principal in view.principals.get("AWS", []):
        account = _account_of(principal)
        if account is not None and account not in allowed:
            found.append(principal)
    return found


def _detect_cross_account(view: StatementView) -> list[str]:
    return [] if "sts:externalid" in view.conditions else _untrusted_accounts(view)


def _detect_cross_account_external_id(view: StatementView) -> list[str]:
    return _untrusted_accounts(view) if "sts:externalid" in view.conditions else []


def _github_subs_ok(view: StatementView) -> bool:
    subs = view.conditions.get(f"{GITHUB_PROVIDER}:sub", [])
    return bool(subs) and not all(s == "*" or s.startswith("repo:*") for s in subs)


def _is_github(value: str) -> bool:
    return _oidc_provider(value) == GITHUB_PROVIDER


def _detect_github_any_repo(view: StatementView) -> list[str]:
    github = [v for v in _federated(view) if _is_github(v)]
    return [] if _github_subs_ok(view) else github


def _detect_github_no_audience(view: StatementView) -> list[str]:
    github = [v for v in _federated(view) if _is_github(v)]
    if not github or not _github_subs_ok(view):
        return []
    return [] if f"{GITHUB_PROVIDER}:aud" in view.conditions else github


def _detect_oidc_no_sub(view: StatementView) -> list[str]:
    found = []
    for value in _federated(view):
        provider = _oidc_provider(value)
        if provider in (None, GITHUB_PROVIDER, COGNITO_PROVIDER):
            continue
        if f"{provider}:sub" not in view.conditions:
            found.append(value)
    return found


def _detect_cognito_no_audience(view: StatementView) -> list[str]:
    cognito = [v for v in _federated(view) if v.lower() == COGNITO_PROVIDER]
    return [] if f"{COGNITO_PROVIDER}:aud" in view.conditions else cognito


def _detect_saml_no_audience(view: StatementView) -> list[str]:
    saml = [v for v in _federated(view) if "saml-provider/" in v.lower()]
    return [] if "saml:aud" in view.conditions else saml


RULES: tuple[TrustRule, ...] = (
    TrustRule(
        "TRUST-001", Severity.CRITICAL, "Any AWS account can assume this role",
        "The trust policy allows the AWS principal '*' without a condition on the caller's "
        "organization, account or ARN, so any principal in any AWS account can assume the role.",
        "Replace '*' with specific account or role ARNs, or add a condition such as "
        "aws:PrincipalOrgID to restrict callers to your organization.",
        _detect_any_account,
    ),
    TrustRule(
        "TRUST-002", Severity.HIGH, "Trust policy allows every principal except those listed",
        "An Allow statement uses NotPrincipal, which trusts every principal except the ones "
        "listed, including principals in accounts you do not control.",
        "Replace NotPrincipal with an explicit Principal list of the accounts or roles that "
        "need to assume this role.",
        _detect_not_principal,
    ),
    TrustRule(
        "TRUST-003", Severity.HIGH, "Cross-account trust without ExternalId",
        "The role trusts another AWS account that is not on the trusted list and the "
        "statement has no sts:ExternalId condition, leaving it open to the confused deputy problem.",
        "Add a StringEquals condition on sts:ExternalId for third-party access, or list the "
        "account in --trusted-accounts if you own it.",
        _detect_cross_account,
    ),
    TrustRule(
        "TRUST-004", Severity.LOW, "Cross-account trust to an account not on the trusted list",
        "The role trusts another AWS account that is not on the trusted list (an "
        "sts:ExternalId condition is present). Informational: verify the third party.",
        "Confirm the account is a known third party, then add it to --trusted-accounts.",
        _detect_cross_account_external_id,
    ),
    TrustRule(
        "TRUST-005", Severity.CRITICAL, "Any GitHub repository can assume this role",
        "The role trusts GitHub Actions OIDC without constraining the "
        f"{GITHUB_PROVIDER}:sub claim (or every value is a wildcard), so workflows in any "
        "GitHub repository can assume it.",
        f"Add a StringEquals/StringLike condition on {GITHUB_PROVIDER}:sub limiting it to your "
        "repository and branch, e.g. repo:my-org/my-repo:ref:refs/heads/main.",
        _detect_github_any_repo,
    ),
    TrustRule(
        "TRUST-006", Severity.MEDIUM, "GitHub OIDC trust without an audience condition",
        "The role trusts GitHub Actions OIDC with a restricted sub claim but has no "
        f"{GITHUB_PROVIDER}:aud condition.",
        f"Add a StringEquals condition on {GITHUB_PROVIDER}:aud set to sts.amazonaws.com.",
        _detect_github_no_audience,
    ),
    TrustRule(
        "TRUST-007", Severity.HIGH, "OIDC trust without a subject condition",
        "The role trusts an OIDC identity provider without a condition on its :sub claim, "
        "so any identity issued by that provider can assume it.",
        "Add a StringEquals condition on <provider>:sub limiting the role to the specific "
        "subject(s) that need it.",
        _detect_oidc_no_sub,
    ),
    TrustRule(
        "TRUST-008", Severity.HIGH, "Cognito identity pool trust without an audience condition",
        "The role trusts cognito-identity.amazonaws.com without a "
        f"{COGNITO_PROVIDER}:aud condition, so any Cognito identity pool can assume it.",
        f"Add a StringEquals condition on {COGNITO_PROVIDER}:aud set to your identity pool ID.",
        _detect_cognito_no_audience,
    ),
    TrustRule(
        "TRUST-009", Severity.MEDIUM, "SAML trust without an audience condition",
        "The role trusts a SAML provider without a SAML:aud condition.",
        "Add a StringEquals condition on SAML:aud set to https://signin.aws.amazon.com/saml.",
        _detect_saml_no_audience,
    ),
)


def _parse_accounts(value: str) -> str:
    """argparse type: validate a comma-separated list of 12-digit account IDs."""
    for item in value.split(","):
        if not _ACCOUNT_ID_RE.match(item.strip()):
            raise argparse.ArgumentTypeError(f"not a 12-digit AWS account ID: {item.strip()!r}")
    return value


def add_trust_arguments(parser: argparse.ArgumentParser) -> None:
    """Register ``--trusted-accounts`` (comma-separated, repeatable)."""
    parser.add_argument(
        "--trusted-accounts", type=_parse_accounts, action="append", default=None,
        metavar="ACCOUNT_IDS", dest="trusted_accounts",
        help="Comma-separated AWS account IDs whose trust is expected; repeatable "
        "(trust analysis ignores these accounts)",
    )


def _trusted_accounts(raw: list[str] | None) -> frozenset[str]:
    return frozenset(a.strip() for item in raw or [] for a in item.split(",") if a.strip())


def _make_finding(role: IAMRole, rule: TrustRule, view: StatementView, offenders: list[str]) -> Finding:
    return Finding(
        principal_arn=role.arn,
        principal_name=role.name,
        principal_type=role.principal_type,
        category=FindingCategory.TRUST_POLICY,
        severity=rule.severity,
        title=f"Trust policy: {rule.title}",
        description=rule.description,
        recommendation=rule.recommendation,
        metadata={
            "rule_id": rule.rule_id,
            "statement_sid": view.statement.sid,
            "principal": ", ".join(offenders),
            "condition_keys": sorted(view.conditions),
        },
    )


def analyze_role_trust(
    role: IAMRole, account_id: str, trusted_accounts: frozenset[str]
) -> list[Finding]:
    """Evaluate every rule against each assume-granting statement of one role."""
    if role.trust_policy is None or role.is_service_linked or role.is_aws_reserved:
        return []
    if role.path.startswith(("/aws-service-role/", "/aws-reserved/")):
        return []
    findings: list[Finding] = []
    for statement in role.trust_policy.statements:
        if not grants_assume(statement):
            continue
        view = StatementView(
            statement, normalize_conditions(statement.conditions), account_id, trusted_accounts
        )
        for rule in RULES:
            offenders = rule.detect(view)
            if offenders:
                findings.append(_make_finding(role, rule, view, offenders))
    return findings


def run(ctx: AuditContext) -> list[Finding]:
    """Pipeline check: analyze the trust policy of every role in scope."""
    trusted = _trusted_accounts(getattr(ctx.options, "trusted_accounts", None))
    findings: list[Finding] = []
    for principal in ctx.principals:
        if isinstance(principal, IAMRole):
            findings.extend(analyze_role_trust(principal, ctx.account_id, trusted))
    return findings
