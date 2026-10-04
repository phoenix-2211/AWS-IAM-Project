---
name: policy-simulator-usage
description: Load when writing, testing or running anything that uses the AWS IAM Policy Simulator (SimulatePrincipalPolicy / simulate_principal_policy).
---

# Policy Simulator Usage

## Verified facts
(none yet)

## Unverified / to confirm
- [ ] Exact API request and response shape (boto3 simulate_principal_policy)
- [ ] Pagination behaviour
- [ ] ContextEntries format, and how to supply values for condition keys
- [ ] How resource policies and permissions boundaries can be supplied
- [ ] What it evaluates AND what it does not evaluate: specifically role trust policies, SCPs, RCPs, session policies
- [ ] IAM permissions needed to call it
- [ ] Whether the simulated principal must exist in the account

## Procedure
1. All simulator access goes through a SimulatorBackend interface with two implementations: RecordedBackend (replays stored real responses; used for offline tests) and LiveBackend.
2. Save the raw request and raw response for every call under runs/<run_id>/04_simulator/raw/.
3. Attach a limitations[] list to every verdict.
4. If a condition's keys cannot be derived, do not guess: mark the verdict INCONCLUSIVE and say why.

## Never do
- Run any Live call without the human typing APPROVE-LIVE-SIM.
- Report a simulator "allowed" as a confirmed exploit (use POLICY_ALLOWED).
- Fabricate a Live result from a synthetic fixture.
- Log credentials.
