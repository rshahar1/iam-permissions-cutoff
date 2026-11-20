# JSON schema delta: privilege escalation

Additive only; `schema_version` stays `1.0.0`.

- `findings[].category` may now be `"privilege_escalation"`.
- For that category `findings[].metadata` contains:
  - `rule_id` (string, `PE-001`..`PE-024`)
  - `rule_name` (string)
  - `matched_actions` (array of canonical action names, e.g. `["iam:PassRole", "ec2:RunInstances"]`)
  - `granting_policies` (sorted array of policy names, including group policies)
- `title` is `"Privilege escalation path: {rule_name}"`; `severity` comes from the rule table.
- Existing fields and categories are unchanged.
