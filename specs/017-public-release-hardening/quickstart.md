# Runbook: apply repository settings after going public

Rulesets and branch protection are unavailable for private repositories on GitHub Free, so apply everything below
**after** the repository is public. All commands run from the repository root with an authenticated `gh` that has admin
rights on the repository.

```bash
REPO=rshahar1/iam-permissions-cutoff
RULES=specs/017-public-release-hardening/contracts
```

## 0. Before publishing (owner decisions)

- Commit author emails in the history become public. Rewrite them first (for example `git filter-repo --mailmap`) if
  any must stay private, and enable *Settings → Emails → Keep my email addresses private* for future commits.
- Merge this feature's PR so the license, policies and CODEOWNERS are on `main` when the repository goes public.
- Make it public: *Settings → General → Danger Zone → Change visibility → Public*.

## 1. Merge settings (squash only)

```bash
gh repo edit "$REPO" --enable-squash-merge --enable-merge-commit=false --enable-rebase-merge=false \
  --delete-branch-on-merge --allow-update-branch
gh api -X PATCH "repos/$REPO" -f squash_merge_commit_title=PR_TITLE -f squash_merge_commit_message=PR_BODY
```

## 2. GitHub Actions

```bash
# Read-only GITHUB_TOKEN by default; workflows may not approve pull requests.
gh api -X PUT "repos/$REPO/actions/permissions/workflow" \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
# Fork PR workflows need the owner's approval for every outside contributor.
gh api -X PUT "repos/$REPO/actions/permissions/fork-pr-contributor-approval" \
  -f approval_policy=all_external_contributors
# Only GitHub-owned actions (actions/*, github/*), pinned to full commit SHAs.
gh api -X PUT "repos/$REPO/actions/permissions" -F enabled=true -f allowed_actions=selected -F sha_pinning_required=true
gh api -X PUT "repos/$REPO/actions/permissions/selected-actions" \
  -F github_owned_allowed=true -F verified_allowed=false
```

UI equivalent: *Settings → Actions → General*.

## 3. Security features

```bash
gh api -X PATCH "repos/$REPO" --input - <<'JSON'
{"security_and_analysis": {"secret_scanning": {"status": "enabled"},
                           "secret_scanning_push_protection": {"status": "enabled"}}}
JSON
```

```bash
gh api -X PUT "repos/$REPO/vulnerability-alerts"
```

```bash
gh api -X PUT "repos/$REPO/automated-security-fixes"
```

```bash
gh api -X PUT "repos/$REPO/private-vulnerability-reporting"
```

```bash
gh api -X PATCH "repos/$REPO/code-scanning/default-setup" -f state=configured -f query_suite=default
```

UI equivalent: *Settings → Advanced Security* (Code security).

## 4. Rulesets on `main`

```bash
gh api -X POST "repos/$REPO/rulesets" --input "$RULES/ruleset-ci-gate.json"
```

```bash
gh api -X POST "repos/$REPO/rulesets" --input "$RULES/ruleset-review-gate.json"
```

## 5. Verify

```bash
gh api "repos/$REPO/rulesets" --jq '.[] | "\(.name): \(.enforcement)"'
```

```bash
gh api "repos/$REPO" --jq '{visibility, allow_squash_merge, allow_merge_commit, allow_rebase_merge, delete_branch_on_merge, security_and_analysis}'
```

```bash
gh api "repos/$REPO/actions/permissions/workflow"
```

```bash
gh api "repos/$REPO/private-vulnerability-reporting"
```

Then confirm end to end:

- `git push origin HEAD:main` from a scratch commit is rejected.
- A PR with a failing check cannot be merged; with green checks the owner can merge it (admin bypass of the review gate
  only).
- The *Community standards* page (*Insights → Community standards*) shows every item complete.

## Keep in mind

- Do not add collaborators with write access: on a personal account they could merge PRs and approve each other.
- Renaming a CI job requires updating `ruleset-ci-gate.json` and the live ruleset in the same PR.
