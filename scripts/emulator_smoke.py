"""Self-checking smoke test: run the real iam-audit CLI against a local moto IAM emulator.

Usage:
    python scripts/emulator_smoke.py [--keep-reports DIR]

The script starts an in-process moto server on 127.0.0.1, seeds one IAM principal
per known scenario, runs ``python -m iam_audit report --format json`` twice
(default and ``--include-aws-managed``) and compares the findings against the
``EXPECTED_PERMISSION`` table below. To add a scenario, seed it in ``seed()`` and
add a row to the table.

Exit codes: 0 = all checks pass, 1 = expectation mismatch, 2 = setup error.

Safety: the seeding client and the CLI subprocess run with a scrubbed environment
(all ``AWS_*`` variables removed, dummy credentials, endpoint forced to the local
emulator, no config/credentials files), so real AWS can never be contacted.

Limitations: moto does not implement Access Advisor
(``generate_service_last_accessed_details``), so unused-permission analysis is not
exercised. Dormancy findings are not asserted (fresh principals are "never used").
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

os.environ["MOTO_IAM_LOAD_MANAGED_POLICIES"] = "true"

import boto3  # noqa: E402
from moto.server import ThreadedMotoServer  # noqa: E402

EXIT_OK, EXIT_MISMATCH, EXIT_SETUP = 0, 1, 2
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
SEVERITY_ORDER = ["low", "medium", "high", "critical"]
SSO_ROLE = "AWSReservedSSO_Admin_abc123"
SERVICE_ROLE = "AWSServiceRoleForECS"

# Default-run expectations: principal -> highest permission severity (None = no finding),
# optional metadata equality checks and recommendation substring.
EXPECTED_PERMISSION: dict[str, dict[str, Any]] = {
    "ci-admin": {"severity": "critical", "metadata": {"policy_is_aws_managed": True},
                 "recommendation_contains": "cannot be edited"},
    "mixed-star": {"severity": "critical"},
    "bucket-star": {"severity": "high"},
    "power-notaction": {"severity": "high", "metadata": {"not_actions": ["iam:*"]},
                        "recommendation_contains": "NotAction"},
    "mixed-resource": {"severity": "medium"},
    "deploy-bot": {"severity": "medium"},
    "tight-reader": {"severity": None},
}
DEFAULT_SCANNED = 7
MANAGED_SCANNED = 9


class SetupError(Exception):
    """Raised when the environment, emulator or CLI cannot be set up."""


def free_port() -> int:
    """Return a free TCP port on 127.0.0.1."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def isolated_env(endpoint: str) -> dict[str, str]:
    """Build an environment that can only talk to the local emulator."""
    host = endpoint.split("//", 1)[-1].split(":", 1)[0]
    if host not in ("127.0.0.1", "localhost"):
        raise SetupError(f"refusing non-local endpoint: {endpoint}")
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env.update({
        "AWS_ENDPOINT_URL": endpoint,
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
    })
    return env


def doc(*statements: dict[str, Any]) -> str:
    """Build an IAM policy document JSON string."""
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def make_role(iam: Any, name: str, path: str = "/", inline: str | None = None,
              managed: list[str] | None = None) -> None:
    """Create a role with an optional inline policy and managed attachments."""
    iam.create_role(RoleName=name, Path=path, AssumeRolePolicyDocument=TRUST)
    if inline:
        iam.put_role_policy(RoleName=name, PolicyName=f"{name}-inline", PolicyDocument=inline)
    for arn in managed or []:
        iam.attach_role_policy(RoleName=name, PolicyArn=arn)


def seed_roles(iam: Any) -> None:
    """Seed the role scenarios."""
    make_role(iam, "ci-admin", managed=[ADMIN])
    make_role(iam, "power-notaction",
              inline=doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}))
    make_role(iam, "bucket-star", inline=doc(
        {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::data-bucket/*"}))
    make_role(iam, "mixed-star", inline=doc(
        {"Effect": "Allow", "Action": ["*", "s3:GetObject"], "Resource": "*"}))
    make_role(iam, "mixed-resource", inline=doc({
        "Effect": "Allow",
        "Action": ["iam:PassRole", "iam:CreateAccessKey"],
        "Resource": ["arn:aws:iam::123456789012:role/app", "*"],
    }))
    make_role(iam, "tight-reader", inline=doc(
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::data-bucket/*"}))
    make_role(iam, SSO_ROLE, path="/aws-reserved/sso.amazonaws.com/", managed=[ADMIN])
    make_role(iam, SERVICE_ROLE, path="/aws-service-role/ecs.amazonaws.com/")


def seed_users(iam: Any) -> None:
    """Seed a user whose group has a customer-managed partial-wildcard policy."""
    arn = iam.create_policy(
        PolicyName="deployers-read",
        PolicyDocument=doc({"Effect": "Allow", "Action": "s3:Get*",
                            "Resource": "arn:aws:s3:::artifacts/*"}),
    )["Policy"]["Arn"]
    iam.create_group(GroupName="deployers")
    iam.attach_group_policy(GroupName="deployers", PolicyArn=arn)
    iam.create_user(UserName="deploy-bot")
    iam.add_user_to_group(GroupName="deployers", UserName="deploy-bot")


def seed(endpoint: str) -> None:
    """Seed all scenarios using an explicitly local, dummy-credential client."""
    iam = boto3.client(
        "iam", region_name="us-east-1", endpoint_url=endpoint,
        aws_access_key_id="testing", aws_secret_access_key="testing",
    )
    seed_roles(iam)
    seed_users(iam)


def run_cli(env: dict[str, str], out: Path, extra: list[str]) -> dict[str, Any]:
    """Run the real CLI and return its parsed JSON report."""
    cmd = [sys.executable, "-m", "iam_audit", "report", "--format", "json",
           "--output", str(out), *extra]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False, timeout=300)
    if proc.returncode != EXIT_MISMATCH:
        raise SetupError(f"CLI exit {proc.returncode} (expected 1): {proc.stderr.strip()[-500:]}")
    try:
        data: dict[str, Any] = json.loads(out.read_text())
    except (OSError, ValueError) as exc:
        raise SetupError(f"cannot parse {out}: {exc}") from exc
    return data


def top_permission(findings: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    """Return the highest-severity permission finding for a principal, if any."""
    mine = [f for f in findings
            if f["principal_name"] == name and f["category"] == "permission"]
    if not mine:
        return None
    return max(mine, key=lambda f: SEVERITY_ORDER.index(f["severity"]))


def check_permission(name: str, spec: dict[str, Any],
                     findings: list[dict[str, Any]]) -> list[tuple[str, bool]]:
    """Evaluate one row of EXPECTED_PERMISSION."""
    top = top_permission(findings, name)
    want = spec["severity"]
    got = top["severity"] if top else None
    results = [(f"{name}: top permission severity == {want} (got {got})", got == want)]
    if top is None:
        return results
    for key, value in spec.get("metadata", {}).items():
        actual = top["metadata"].get(key)
        results.append((f"{name}: metadata.{key} == {value!r} (got {actual!r})", actual == value))
    needle = spec.get("recommendation_contains")
    if needle:
        results.append((f"{name}: recommendation contains {needle!r}",
                        needle in top["recommendation"]))
    return results


def check_scope(default: dict[str, Any], managed: dict[str, Any]) -> list[tuple[str, bool]]:
    """Evaluate principal counts and AWS-managed inclusion behaviour."""
    names = {f["principal_name"] for f in default["findings"]}
    sso = top_permission(managed["findings"], SSO_ROLE)
    return [
        (f"default: principals_scanned == {DEFAULT_SCANNED} "
         f"(got {default['summary']['principals_scanned']})",
         default["summary"]["principals_scanned"] == DEFAULT_SCANNED),
        (f"default: {SSO_ROLE} and {SERVICE_ROLE} absent",
         not ({SSO_ROLE, SERVICE_ROLE} & names)),
        (f"managed: principals_scanned == {MANAGED_SCANNED} "
         f"(got {managed['summary']['principals_scanned']})",
         managed["summary"]["principals_scanned"] == MANAGED_SCANNED),
        (f"managed: {SSO_ROLE} has critical permission finding",
         sso is not None and sso["severity"] == "critical"),
    ]


def evaluate(default: dict[str, Any], managed: dict[str, Any]) -> list[tuple[str, bool]]:
    """Run every check and return (description, passed) pairs."""
    results = check_scope(default, managed)
    for name, spec in EXPECTED_PERMISSION.items():
        results.extend(check_permission(name, spec, default["findings"]))
    return results


def run(report_dir: Path) -> int:
    """Start the emulator, seed, run the CLI twice and report check results."""
    port = free_port()
    endpoint = f"http://127.0.0.1:{port}"
    env = isolated_env(endpoint)
    logging.disable(logging.CRITICAL)  # silence expected moto NotImplemented tracebacks
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=port, verbose=False)
    server.start()
    try:
        seed(endpoint)
        default = run_cli(env, report_dir / "default.json", [])
        managed = run_cli(env, report_dir / "managed.json", ["--include-aws-managed"])
    finally:
        server.stop()
    results = evaluate(default, managed)
    for desc, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}: {desc}")
    gaps = len(default.get("data_gaps", []))
    print(f"INFO: data gaps in default run: {gaps} (moto does not implement Access Advisor "
          "generate_service_last_accessed_details; unused-permission analysis not exercised)")
    failed = sum(1 for _, ok in results if not ok)
    print(f"SUMMARY: {len(results) - failed}/{len(results)} checks passed")
    return EXIT_MISMATCH if failed else EXIT_OK


def main() -> int:
    """Parse arguments and run the smoke test; return the process exit code."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--keep-reports", metavar="DIR", help="write JSON reports to DIR")
    args = parser.parse_args()
    try:
        if args.keep_reports:
            keep = Path(args.keep_reports)
            keep.mkdir(parents=True, exist_ok=True)
            return run(keep)
        with tempfile.TemporaryDirectory() as tmp:
            return run(Path(tmp))
    except Exception as exc:  # noqa: BLE001 - any setup failure maps to exit 2
        print(f"SETUP ERROR: {exc}", file=sys.stderr)
        return EXIT_SETUP


if __name__ == "__main__":
    sys.exit(main())
