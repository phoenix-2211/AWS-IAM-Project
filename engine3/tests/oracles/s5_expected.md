# Stage 5 Expected Oracle Outcomes (`s5_expected.md`)

This document defines expected sandbox execution behavior and safety gates.

## 1. Safety Gate Refusals
- **No `APPROVE-DEPLOY` Token**: `CloudGoatSandboxRunner` MUST refuse execution and return `SANDBOX_FAILED` with log stating `"Refusing deploy without APPROVE-DEPLOY gate token"`.
- **`budget_confirmed: false`**: Runner MUST refuse execution and return `SANDBOX_FAILED` with log stating `"Refusing deploy without budget_confirmed: true in sandbox.yaml"`.
- **Missing Account ID Confirmation**: Runner MUST refuse execution without confirmed sandbox account ID.

---

## 2. Sandbox Execution Output Table
| Path Condition | Gate Approval | Sandbox Outcome | Result Status |
|---|---|---|---|
| Unmapped scenario / Offline mode | N/A | `sandbox_attempted: false` | `SANDBOX_FAILED` (reason recorded in logs) |
| Mapped scenario, no gates approved | Missing tokens | `sandbox_attempted: false` | `SANDBOX_FAILED` (reason: gate tokens missing) |
