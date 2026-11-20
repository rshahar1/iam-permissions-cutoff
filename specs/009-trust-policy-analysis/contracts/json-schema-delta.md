# JSON schema delta: trust policy findings

`schema_version` stays `1.0.0`; the change is additive.

- `findings[].category` may now be `"trust_policy"` (display name "Trust Policy Findings").
- `summary.by_category` gains a `trust_policy` key when such findings exist.
- `findings[].principal_type` is always `"role"` for these findings.
- `findings[].metadata` for `trust_policy` findings:

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | string | `TRUST-001` .. `TRUST-009` |
| `statement_sid` | string \| null | `Sid` of the offending trust statement |
| `principal` | string | Offending principal(s), comma-separated (`*`, account IDs/ARNs, federated providers, or `Type:value` for `NotPrincipal`) |
| `condition_keys` | string[] | Sorted, lower-cased condition keys present on the statement |

Severities: TRUST-001 and TRUST-005 critical; TRUST-002, 003, 007, 008 high; TRUST-006 and 009 medium; TRUST-004 low.
