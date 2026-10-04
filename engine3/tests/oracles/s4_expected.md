# Stage 4 Expected Oracle Outcomes (`s4_expected.md`)

This document defines the hand-derived expected evaluation results for the Policy Simulator interface across local evaluator responses and live refusal safety checks.

## 1. Local Evaluator Hops Evaluation Matrix

| Path Hops | Evaluated Hop Decisions | Trust Policy Check | Final Path Verification Status | Source Label |
|---|---|---|---|---|
| `dev-alice` -> `DevRole` -> `DeployRole` -> `secret` | All action hops `ALLOWED` | Structural trust satisfied | `POLICY_ALLOWED` | `source: "local_evaluator"` |
| `dev-alice` -> `DeployRole` (MFA missing context) -> `secret` | Action hop `ALLOWED` with missing context | Structural trust satisfied (with condition flag) | `POLICY_ALLOWED` | `source: "local_evaluator"` |
| Any path with an `explicitDeny` or `implicitDeny` hop | At least one hop `DENIED` | N/A | `POLICY_DENIED` | `source: "local_evaluator"` |

---

## 2. Live Simulator Safety Gate Rule
- `LivePolicySimulator` MUST refuse to execute without the explicit gate parameter (`APPROVE-LIVE-SIM`) AND a valid named AWS profile.
- If invoked without approval, `LivePolicySimulator` raises `PermissionError("Refusing live AWS simulator call without APPROVE-LIVE-SIM gate token")`.
