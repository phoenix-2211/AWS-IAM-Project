# Stage 6 Expected Oracle Outcomes (`s6_expected.md`)

This document defines expected verification result assembly rules.

## 1. Verification Status Mapping Table
| Simulator Result | Sandbox Result | Final Status |
|---|---|---|
| Hop Denied | Any | `POLICY_DENIED` |
| All Hops Allowed (Local Evaluator / Offline) | Sandbox Not Run / Failed / Offline | `SANDBOX_FAILED` |
| All Hops Allowed (Live) | Real Exploit Success | `VERIFIED_EXPLOITABLE` |

---

## 2. Metric & Contract Rules
- `runtime_metrics` MUST contain real measured execution times in milliseconds (not hardcoded zero).
- Output MUST validate cleanly against `verification_result_v0.1.schema.json`.
