# Engine 3 — Attack + Verification Engine

Engine 3 consumes `IAMGraph v0.1` (from Engine 2) and `SecurityRule v0.1` (from Engine 1) to discover attack paths and run verification checks emitting `VerificationResult v0.1` for Engine 4.

## Quick Start & Execution

To run the pipeline offline on the synthetic fixture:
```powershell
python -m engine3.cli run --graph docs/contracts/iamgraph_fixture.json --rules rulebook/active_rulebook.json --out runs/latest
```

## Mandatory Safety Gates
- **`APPROVE-VOCAB`**: Gate token for vocabulary adapter locking.
- **`APPROVE-LIVE-SIM`**: Gate token for live AWS Policy Simulator execution.
- **`APPROVE-DEPLOY`**: Gate token for CloudGoat sandbox deployments.
- **`APPROVE-DESTROY`**: Gate token for teardown confirmation.

## Limitations & Scope
- Missing edges in `IAMGraph` are non-proof of safety.
- Offline local policy simulator calls emit `SANDBOX_FAILED` (with `local_evaluator, not AWS` limitation) and never `VERIFIED_EXPLOITABLE`.
