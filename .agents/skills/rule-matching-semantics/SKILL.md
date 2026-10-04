---
name: rule-matching-semantics
description: Use in Stage 1 and whenever deciding whether a rule matches a statement.
---

# Rule Matching Semantics

## Rules
- Only Allow statements match; Deny statements are never matches but are recorded as overlaps (including group-derived).
- A condition is flagged CONDITIONAL, never evaluated.
- Non-null permissions boundary is flagged BOUNDARY_PRESENT.
- NotAction, NotResource and policy variables are flagged, never silently matched or dropped.
- Engine 3 recomputes resource matching itself and reports any difference from Engine 2's APPLIES_TO edges as APPLIES_TO_MISMATCH.
- IDs are opaque (never split or parse them).
- NO_MATCH is not proof of safety.
- A rule whose resource type is not in the snapshot's collected types is NOT_REPRESENTABLE.

## Verified facts
(none yet)

## Unverified / to confirm
- [ ] Exact case-sensitivity of action/resource matching
- [ ] Wildcard grammar details
- [ ] NotAction + Allow semantics
- [ ] Behaviour of ? and * inside ARNs
