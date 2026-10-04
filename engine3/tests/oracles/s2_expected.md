# Stage 2 Expected Oracle Outcomes (`s2_expected.md`)

This document defines the hand-derived expected attack paths for `iamgraph_fixture.json` given Stage 1 rule matches.

## 1. Candidate Path Specifications
- **Depth Cap**: 6 hops max.
- **Cycle Handling**: No repeated node IDs in any single path trajectory.
- **Path ID**: Deterministic SHA-256 hash of ordered edge IDs.

---

## 2. Expected Candidate Paths Matrix (Full 18-Path Hand Enumeration)

| Path Index | Start Node | Trajectory (Hops) | Target Node | Edge Sequence Basis | Expected Flags / Assumptions |
|---|---|---|---|---|---|
| 1 | `dev-alice` | `dev-alice` -> `DevRole` -> `DeployRole` -> `secret` | `secret:prod-db-EXAMPLE` | `TRUSTED_BY:01 -> TRUSTED_BY:03 -> APPLIES_TO:05` | `trust_structural_only` |
| 2 | `dev-alice` | `dev-alice` -> `DeployRole` -> `secret` | `secret:prod-db-EXAMPLE` | `TRUSTED_BY:02 -> APPLIES_TO:05` | `condition_unevaluated` |
| 3 | `dev-alice` | `dev-alice` -> `AdminRole` -> `secret` | `secret:prod-db-EXAMPLE` | `TRUSTED_BY:04 -> APPLIES_TO:06` | `trust_structural_only` |
| 4 | `dev-alice` | `dev-alice` -> `DevRole` -> `DeployRole` -> `BuildRole` (t1) | `role:BuildRole` | `TRUSTED_BY:01 -> TRUSTED_BY:03 -> APPLIES_TO:01` | `trust_structural_only` |
| 5 | `dev-alice` | `dev-alice` -> `DevRole` -> `DeployRole` -> `BuildRole` (t2) | `role:BuildRole` | `TRUSTED_BY:01 -> TRUSTED_BY:03 -> APPLIES_TO:02` | `trust_structural_only` |
| 6 | `dev-alice` | `dev-alice` -> `DevRole` -> `DeployRole` -> `BuildRole` (t3) | `role:BuildRole` | `TRUSTED_BY:01 -> TRUSTED_BY:03 -> APPLIES_TO:03` | `trust_structural_only` |
| 7 | `dev-alice` | `dev-alice` -> `DeployRole` -> `BuildRole` (t1) | `role:BuildRole` | `TRUSTED_BY:02 -> APPLIES_TO:01` | `condition_unevaluated` |
| 8 | `dev-alice` | `dev-alice` -> `DeployRole` -> `BuildRole` (t2) | `role:BuildRole` | `TRUSTED_BY:02 -> APPLIES_TO:02` | `condition_unevaluated` |
| 9 | `dev-alice` | `dev-alice` -> `DeployRole` -> `BuildRole` (t3) | `role:BuildRole` | `TRUSTED_BY:02 -> APPLIES_TO:03` | `condition_unevaluated` |
| 10 | `dev-alice` | `dev-alice` -> `DevRole` -> `DeployRole` -> `DevRole` | `role:DevRole` | `TRUSTED_BY:01 -> TRUSTED_BY:03 -> APPLIES_TO:04` | `trust_structural_only` |
| 11 | `dev-alice` | `dev-alice` -> `DeployRole` -> `DevRole` | `role:DevRole` | `TRUSTED_BY:02 -> APPLIES_TO:04` | `condition_unevaluated` |
| 12 | `dev-alice` | `dev-alice` -> `AdminRole` -> `BuildRole` (t1) | `role:BuildRole` | `TRUSTED_BY:04 -> APPLIES_TO:06` | `trust_structural_only` |
| 13 | `dev-alice` | `dev-alice` -> `AdminRole` -> `BuildRole` (t2) | `role:BuildRole` | `TRUSTED_BY:04 -> APPLIES_TO:06` | `trust_structural_only` |
| 14 | `dev-alice` | `dev-alice` -> `AdminRole` -> `BuildRole` (t3) | `role:BuildRole` | `TRUSTED_BY:04 -> APPLIES_TO:06` | `trust_structural_only` |
| 15 | `dev-alice` | `dev-alice` -> `AdminRole` -> `DevRole` | `role:DevRole` | `TRUSTED_BY:04 -> APPLIES_TO:06` | `trust_structural_only` |
| 16 | `dev-alice` | `dev-alice` -> `AdminRole` -> `DeployRole` | `role:DeployRole` | `TRUSTED_BY:04 -> APPLIES_TO:06` | `trust_structural_only` |
| 17 | `dev-alice` | `dev-alice` -> `dev-alice` | `user:dev-alice` | `APPLIES_TO:dev` | `condition_unevaluated` |
| 18 | `dev-alice` | `dev-alice` -> `DeployRole` | `role:DeployRole` | `APPLIES_TO:dev` | `condition_unevaluated` |

---

## 3. Boundary & Error Requirements
- Unresolved cross-account trust warnings yield 0 paths through that edge and record a warning.
- Partial collection status marks all discovered paths with `degraded: true`.
- Output must explicitly include limitation string: `"A missing attack path is never proof of safety."`
