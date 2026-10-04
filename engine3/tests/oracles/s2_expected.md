# Stage 2 Expected Oracle Outcomes (`s2_expected.md`)

This document defines the hand-derived expected attack paths for `iamgraph_fixture.json` given Stage 1 rule matches.

## 1. Candidate Path Specifications
- **Depth Cap**: 6 hops max.
- **Cycle Handling**: No repeated node IDs in any single path trajectory.
- **Path ID**: Deterministic SHA-256 hash of ordered edge IDs.

---

## 2. Expected Candidate Paths Matrix

| Path Index | Start Node | Trajectory (Hops) | Target Node | Deterministic Path ID Basis | Expected Assumptions / Limitations |
|---|---|---|---|---|---|
| 1 | `arn:aws:iam::111122223333:user/dev-alice` | `dev-alice` --(`sts:AssumeRole`)--> `DevRole` --(`sts:AssumeRole`)--> `DeployRole` --(`secretsmanager:GetSecretValue`)--> `secret` | `arn:aws:secretsmanager:us-east-1:111122223333:secret:prod-db-EXAMPLE` | `edge:TRUSTED_BY:01 -> edge:TRUSTED_BY:03 -> edge:APPLIES_TO:05` | Includes `trust_structural_only` |
| 2 | `arn:aws:iam::111122223333:user/dev-alice` | `dev-alice` --(`sts:AssumeRole`, MFA cond)--> `DeployRole` --(`secretsmanager:GetSecretValue`)--> `secret` | `arn:aws:secretsmanager:us-east-1:111122223333:secret:prod-db-EXAMPLE` | `edge:TRUSTED_BY:02 -> edge:APPLIES_TO:05` | Includes `condition_unevaluated` |
| 3 | `arn:aws:iam::111122223333:user/dev-alice` | `dev-alice` --(`sts:AssumeRole`)--> `AdminRole` --(`secretsmanager:GetSecretValue`)--> `secret` | `arn:aws:secretsmanager:us-east-1:111122223333:secret:prod-db-EXAMPLE` | `edge:TRUSTED_BY:04 -> edge:APPLIES_TO:06` | Includes `trust_structural_only` |

---

## 3. Boundary & Error Requirements
- Unresolved cross-account trust warnings yield 0 paths through that edge and record a warning.
- Partial collection status marks all discovered paths with `degraded: true`.
- Output must explicitly include limitation string: `"A missing attack path is never proof of safety."`
