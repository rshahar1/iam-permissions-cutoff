# Security Policy

## Supported versions

Only the latest release on `main` receives security fixes.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability reporting:
<https://github.com/rshahar1/iam-permissions-cutoff/security/advisories/new>

Never open a public issue, pull request or discussion for a vulnerability.

Please include:

- A description of the problem and its impact.
- The affected version or commit, and your Python version and OS.
- Steps to reproduce, ideally with a minimal example.
- Any suggested fix or mitigation.

Never include real credentials, real AWS account IDs, ARNs or principal names in a report. Redact them
(for example, use the placeholder account `123456789012`).

## Response targets

- Acknowledgement within 7 days.
- Status update within 14 days.
- Coordinated disclosure after a fix is available.

## Scope

In scope:

- The tool's code.
- Its outputs, for example HTML report escaping or secrets leaking into logs or reports.
- Dependencies as used by this project.
- The CI workflow.

Out of scope:

- Findings in your own AWS accounts.
- Behavior of AWS services themselves.

`iam-audit` is designed to be read-only: it only calls IAM and STS read APIs. Any code path that issues a
mutating AWS call is treated as a security bug.
