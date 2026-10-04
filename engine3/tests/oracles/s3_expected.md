# Stage 3 Expected Oracle Outcomes (`s3_expected.md`)

This document defines the hand-derived expected queue ranking for paths discovered from `iamgraph_fixture.json`.

## 1. Tuple Sort Ranking Rules
Sort tuple per candidate path: `(-max_severity_weight, hop_count, assumption_count, path_id)`
Severity weights: `CRITICAL = 4`, `HIGH = 3`, `MEDIUM = 2`, `LOW = 1`.

---

## 2. Worked Example Ranking Table

| Rank | Path ID | Max Rule Severity | Hop Count | Assumptions | Worked Sort Key Tuple | Expected Rank Reason |
|---|---|---|---|---|---|---|
| 1 | `b7389812df93f...` | `CRITICAL` (4) | 2 hops | 0 assumptions | `(-4, 2, 0, "b738...")` | `severity CRITICAL, 2 hops, 0 assumptions` |
| 2 | `a90184b2c124a...` | `CRITICAL` (4) | 3 hops | 1 assumption | `(-4, 3, 1, "a901...")` | `severity CRITICAL, 3 hops, 1 assumption` |
| 3 | `c1234918ef918...` | `HIGH` (3) | 2 hops | 1 assumption | `(-3, 2, 1, "c123...")` | `severity HIGH, 2 hops, 1 assumption` |

---

## 3. Ladder & Scenario Key Rules
- All paths assigned initial ladder status: `CANDIDATE` (or `QUEUED`). Never any stronger status.
- `sandbox_group_key` assigned `NOT_MAPPED` until Stage 5 scenario mapping is executed.
