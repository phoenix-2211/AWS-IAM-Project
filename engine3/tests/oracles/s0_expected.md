# Stage 0 Oracle Expectations (`s0_expected.md`)

This document defines the hand-derived expected behavior of the Stage 0 loader (`s0_load.py`) for valid inputs and 13 specified mutation cases.

## 1. Valid Baseline Inputs
- **Inputs**: `iamgraph_fixture.json` (13 nodes, 21 edges) + `SecurityRule_sample.json` (5 rules: 4 ACTIVE, 1 DRAFT).
- **Expected Outcome**:
  - `is_valid`: `True`
  - `graph.snapshot.collection_status`: `"complete"`
  - `rules_active`: 4
  - `rules_skipped`: 1 (rule `TEST-IAM-005` with status `DRAFT`)
  - `limitations`: Includes `"A missing edge in the IAMGraph is never treated as proof of safety."`
  - `errors`: `[]`

---

## 2. Mutation Test Case Matrix

| Case # | Mutation Description | Target Input | Hand-Derived Expected Outcome | Expected Error Code / Behavior |
|---|---|---|---|---|
| 1 | Duplicate node ID (`arn:aws:iam::111122223333:user/dev`) | IAMGraph `nodes` | Reject load (`is_valid=False`) | `ERR_DUPLICATE_NODE_ID` |
| 2 | Dangling edge target (target points to non-existent node) | IAMGraph `edges` | Reject load (`is_valid=False`) | `ERR_DANGLING_EDGE_TARGET` |
| 3 | Invalid edge endpoint (e.g. `HAS_PERMISSION` pointing User -> Role) | IAMGraph `edges` | Reject load (`is_valid=False`) | `ERR_INVALID_EDGE_ENDPOINT` |
| 4 | Unknown enum value in `snapshot.origin` (`"invalid_origin"`) | IAMGraph `snapshot` | Reject load (`is_valid=False`) | `ERR_SCHEMA_VALIDATION` |
| 5 | Missing `contract_version` | IAMGraph root | Reject load (`is_valid=False`) | `ERR_MISSING_CONTRACT_VERSION` |
| 6 | Wrong `contract_version` (`"99.0"`) | IAMGraph root | Reject load (`is_valid=False`) | `ERR_WRONG_CONTRACT_VERSION` |
| 7 | `collection_status` is `"partial"` but all coverage items report `"complete"` | IAMGraph `snapshot` | Reject load (`is_valid=False`) | `ERR_INCONSISTENT_COVERAGE` |
| 8 | Warning references missing node ID (`"arn:aws:iam::111122223333:role/nonexistent"`) | IAMGraph `warnings` | Reject load (`is_valid=False`) | `ERR_DANGLING_WARNING_REFERENCE` |
| 9 | Permission node specifies both `actions` and `not_actions` | IAMGraph `nodes` | Reject load (`is_valid=False`) | `ERR_BOTH_ACTIONS_AND_NOT_ACTIONS` |
| 10 | Removed `x_provenance` top-level field | IAMGraph root | Accept load (`is_valid=True`) with note | `x_provenance field is absent` in notes |
| 11 | Node ID contains `|` (e.g., `arn:aws:iam::111122223333:role|dev|role`) | IAMGraph `nodes` | Accept load (`is_valid=True`), no collision | `is_valid=True` |
| 12 | SecurityRule with unknown severity (`"APOCALYPTIC"`) | SecurityRule item | Reject load (`is_valid=False`) | `ERR_UNKNOWN_RULE_SEVERITY` |
| 13 | SecurityRule with `DRAFT` status | SecurityRule item | Accept load (`is_valid=True`), skip DRAFT rule | `rules_active=4`, `rules_skipped=1` |
