---
name: contract-guard
description: Load when reading, parsing, validating or generating any Engine 1, Engine 2, Engine 3 or Engine 4 contract data (ApprovedRule/SecurityRule, IAMGraph, VerificationResult).
---

# Contract Guard

## Verified facts
(none yet — contract documents not provided)

## Unverified / to confirm
- [ ] Exact value vocabularies for the rule fields: relationship, principal_type, resource_type, condition
- [ ] Final VerificationResult v0.1 schema (to be agreed with the Engine 4 owner)
- [ ] Final ID scheme in IAMGraph (draft has a known collision: "|" can appear in IAM paths)
- [ ] Whether Engine 2 or Engine 3 generates APPLIES_TO edges

## Procedure
1. All access to contract JSON goes through a RuleAdapter and a GraphAdapter, each with a contract-version check.
2. Reject unknown major versions.
3. snapshot.collection_status = partial means degraded mode: every output is flagged degraded, and no output may claim that no attack path exists.
4. Do not treat APPLIES_TO edges as ground truth. Recompute matching independently and raise a contract_discrepancy warning on any disagreement.
5. Record every attack class the graph cannot represent in docs/scope_gaps.md (known so far: actions targeting a User, a managed policy or a group; non-Secrets-Manager resources; SCPs, RCPs, session policies, resource-based policies).

## Never do
- Parse or split IDs; treat them as opaque strings.
- Hard-code a vocabulary or enum that the team did not provide.
- Silently choose between two sources that disagree.
- Treat a draft contract as frozen.
