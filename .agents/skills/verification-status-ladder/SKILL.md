---
name: verification-status-ladder
description: Use in Stages 3-8 whenever assigning or describing a status.
---

# Verification Status Ladder

## Rules
- Statuses are VERIFIED_IN_SANDBOX, SANDBOX_FAILED, POLICY_DENIED, POLICY_ALLOWED_UNCONFIRMED, INCONCLUSIVE, NOT_VERIFIABLE, NOT_REPRESENTABLE, SKIPPED_BY_BUDGET, ERROR (proposed to Engine 4, pending their agreement).
- Precedence top-down: ERROR, SKIPPED_BY_BUDGET, NOT_REPRESENTABLE, POLICY_DENIED, sandbox result, POLICY_ALLOWED_UNCONFIRMED, INCONCLUSIVE, NOT_VERIFIABLE (the table in status_ladder.md is authoritative once APPROVE-LADDER is given).
- VERIFIED_IN_SANDBOX means scripted steps ran AND the end condition was observed in a lab (verification_scope = lab_reproduction); it never means the analysed account is exploitable.
- POLICY_ALLOWED_UNCONFIRMED means the simulator allowed permission hops while trust hops remained unconfirmed and nothing was executed.
- Never promote a status for convenience.
- Status derivation is one pure function with a truth-table test.

## Verified facts
(none yet)

## Unverified / to confirm
- [ ] Engine 4's acceptance of the enum and of the VERIFIED_IN_SANDBOX name
