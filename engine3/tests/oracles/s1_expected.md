# Stage 1 Expected Oracle Outcomes (`s1_expected.md`)

This document defines the hand-derived expected matches for the 13-node/21-edge `iamgraph_fixture.json` when evaluated against `active_rulebook.json`.

## 1. Rulebook Overview (12 Active Rules)
- `RULE-IAM-001`: `iam:PassRole` on IAM role (`relationship: can_pass_role`, `principal_type: role`)
- `RULE-IAM-002`: `iam:PassRole` on IAM role (`relationship: can_pass_role`, `principal_type: user`)
- `RULE-IAM-003`: `secretsmanager:GetSecretValue` on secret resource (`relationship: can_read_secret`, `principal_type: role`)
- `RULE-IAM-004`: `iam:AttachRolePolicy` (`relationship: can_attach_policy`, `principal_type: role`)
- `RULE-IAM-005`: `iam:PutRolePolicy` (`relationship: can_put_policy`, `principal_type: role`)
- `RULE-IAM-006`: `iam:CreatePolicyVersion` (`relationship: can_create_policy_version`, `principal_type: role`)
- `RULE-IAM-007`: `iam:SetDefaultPolicyVersion` (`relationship: can_set_policy_version`, `principal_type: role`)
- `RULE-IAM-008`: `iam:CreateAccessKey` (`relationship: can_create_access_key`, `principal_type: user`)
- `RULE-IAM-009`: `iam:UpdateAssumeRolePolicy` (`relationship: can_update_assume_role_policy`, `principal_type: role`)
- `RULE-IAM-010`: `sts:AssumeRole` on Role (`relationship: can_assume_role`, `principal_type: role`)
- `RULE-IAM-011`: `sts:AssumeRole` on Role (`relationship: can_assume_role`, `principal_type: user`)
- `RULE-IAM-012`: `iam:PassRole` + `lambda:CreateFunction` (`relationship: not_representable`, `principal_type: role`)

---

## 2. Expected Match Matrix against `iamgraph_fixture.json`

| Rule ID | Matched Principal | Matched Permission Node | Target Node | Match Result / Status | Notes |
|---|---|---|---|---|---|
| `RULE-IAM-001` | `arn:aws:iam::111122223333:role/DeployRole` | `perm:passrole:01` | `arn:aws:iam::111122223333:role/BuildRole` | `MATCHED` | `DeployRole` holds `iam:PassRole` |
| `RULE-IAM-002` | `arn:aws:iam::111122223333:user/dev-alice` | `perm:passrole:dev` | `arn:aws:iam::111122223333:role/DeployRole` | `MATCHED` | Flagged `condition_unevaluated` |
| `RULE-IAM-003` | `arn:aws:iam::111122223333:role/DeployRole` | `perm:getsecret:01` | `arn:aws:secretsmanager:us-east-1:111122223333:secret:prod-db-EXAMPLE` | `MATCHED` | `DeployRole` reads secret |
| `RULE-IAM-003` | `arn:aws:iam::111122223333:role/AdminRole` | `perm:admin:01` | `arn:aws:secretsmanager:us-east-1:111122223333:secret:prod-db-EXAMPLE` | `MATCHED` | `AdminRole` holds wildcard `*` action |
| `RULE-IAM-004` to `011` | N/A | N/A | N/A | `NO_MATCH` | No matching statements in fixture |
| `RULE-IAM-012` | N/A | N/A | N/A | `NOT_REPRESENTABLE` | Resource type/action pair unrepresented in v0.1 |

---

## 3. Wildcard & Statement-Level Rule Matching Specifications
- `actions` matching supports `*` and `?` wildcard matching. Case-insensitive for action strings.
- Deny statements with overlapping actions flag `deny_present: true` on the match object.
- Condition blocks flag `condition_unevaluated: true`.

---

## 4. Edge Cases and Negative Match Matrix
- **No Active Rules (All DRAFT)**: When all input rules are `status="DRAFT"`, matcher receives 0 active rules and returns empty match results list.
- **Empty Graph**: When IAMGraph has 0 principals and 0 permissions, matcher executes cleanly and returns `NO_MATCH` for all active rules.
- **Deny Statement / Deny Condition**: When a permission statement has `effect: "Deny"`, matcher flags `deny_present: true` and does not grant permission.
- **Deterministic Match Ordering**: Match results MUST be sorted by `rule_id` ascending; within a rule result, matches MUST be sorted by `principal_id` ascending, then `target_id` ascending. Exact assertion `[m.principal_id for m in matches] == sorted([m.principal_id for m in matches])` required.
