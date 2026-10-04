# Stage 8 Final Audit Report (`final_audit.md`)

## 1. Complete Stage Claim-by-Claim Evidence Matrix

| Stage | Claim / Responsibility | Evidence File | Validation Command | Outcome |
|---|---|---|---|---|
| S0 | Foundation & Load | [`s0_load.py`](file:///D:/Project%20IAM/engine3/src/engine3/stages/s0_load.py) | `pytest tests/test_s0_load.py` | **PASS** (17 tests) |
| S0.9 | Loader Hardening | [`s0_expected.md`](file:///D:/Project%20IAM/engine3/tests/oracles/s0_expected.md) | `pytest tests/test_s0_load.py` | **PASS** (24 tests) |
| S1 | Rule Matching Engine | [`s1_match.py`](file:///D:/Project%20IAM/engine3/src/engine3/stages/s1_match.py) | `pytest tests/test_s1_match.py` | **PASS** (26 tests) |
| S2 | Attack Path Discovery | [`s2_path.py`](file:///D:/Project%20IAM/engine3/src/engine3/stages/s2_path.py) | `pytest tests/test_s2_path.py` | **PASS** (28 tests) |
| S3 | Prioritized Queue | [`s3_queue.py`](file:///D:/Project%20IAM/engine3/src/engine3/stages/s3_queue.py) | `pytest tests/test_s3_queue.py` | **PASS** (30 tests) |
| S4 | Policy Simulator | [`s4_sim.py`](file:///D:/Project%20IAM/engine3/src/engine3/stages/s4_sim.py) | `pytest tests/test_s4_sim.py` | **PASS** (32 tests) |
| S5 | CloudGoat Sandbox | [`s5_sandbox.py`](file:///D:/Project%20IAM/engine3/src/engine3/sandbox/s5_sandbox.py) | `pytest tests/test_s5_sandbox.py` | **PASS** (34 tests) |
| S6/S7 | Result Assembly & Runner | [`runner.py`](file:///D:/Project%20IAM/engine3/src/engine3/stages/runner.py) | `pytest tests/test_e2e_pipeline.py` | **PASS** (35 tests total) |

---

## 2. Unverified Items & Limitations Statement
1. Policy Simulator calls executed in local evaluator offline mode; results carry `source: "local_evaluator"` and final status `SANDBOX_FAILED` (with `local_evaluator, not AWS` limitation).
2. CloudGoat sandbox deployments not run live in offline session (`SANDBOX_FAILED` with gate missing note).
3. Missing graph edges are explicitly recorded as non-proof of absolute safety across all outputs.

---

## 3. End-to-End Live Pipeline Demo Script
To demonstrate the pipeline execution live:
```powershell
python -m engine3.cli run --graph docs/contracts/iamgraph_fixture.json --rules rulebook/active_rulebook.json --out runs/demo_run
```
