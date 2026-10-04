---
name: path-discovery-bounds
description: Use in Stages 2 and 3 for traversal, cycle handling, bounds, IDs and ordering.
---

# Path Discovery Bounds

## Rules
- Simple paths only.
- Deterministic traversal (sorted neighbours).
- All bounds explicit and defaults documented (max_assume_hops, max_paths_total, max_paths_per_goal, time_budget_s).
- Hitting a bound is REPORTED in discovery_report.json, never silent.
- Duplicates collapsed by canonical signature and counted.
- Path IDs are length-prefixed hashes, never delimiter-joined.
- Trust edges are structural only (conditions, explicit Deny, boundaries, SCPs can all change the outcome).
- Identity-side sts:AssumeRole is recorded as ALLOW_FOUND / NONE_FOUND / UNKNOWN, never as success.
- A missing path means nothing about safety.
- The queue orders verification effort and is NOT a risk score.

## Verified facts
(none yet)

## Unverified / to confirm
- [ ] Same-account vs account-root vs cross-account trust semantics
- [ ] How conditions in trust policies interact with identity policies
