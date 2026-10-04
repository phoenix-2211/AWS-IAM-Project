"""Tests for Stage 5 CloudGoat Sandbox Runner."""

from engine3.sandbox.s5_sandbox import CloudGoatSandboxRunner
from engine3.stages.s2_path import CandidatePath
from engine3.stages.s3_queue import QueuedPath


def test_s5_sandbox_refuses_without_budget():
    dummy_path = QueuedPath(
        queue_rank=1,
        path_id="test1234",
        queue_reason="test",
        path=CandidatePath(
            path_id="test1234",
            hops=[],
            start_node="user",
            target_node="target",
        ),
    )
    runner = CloudGoatSandboxRunner(budget_confirmed=False)
    res = runner.execute_sandbox(dummy_path, gate_token="APPROVE-DEPLOY")
    assert res.status == "SANDBOX_FAILED"
    assert "budget_confirmed is false" in res.reason


def test_s5_sandbox_refuses_without_gate():
    dummy_path = QueuedPath(
        queue_rank=1,
        path_id="test1234",
        queue_reason="test",
        path=CandidatePath(
            path_id="test1234",
            hops=[],
            start_node="user",
            target_node="target",
        ),
    )
    runner = CloudGoatSandboxRunner(budget_confirmed=True, account_id_confirmed="111122223333")
    res = runner.execute_sandbox(dummy_path, gate_token=None)
    assert res.status == "SANDBOX_FAILED"
    assert "APPROVE-DEPLOY gate token missing" in res.reason
