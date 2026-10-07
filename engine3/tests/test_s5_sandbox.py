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


def test_mock_sandbox_policy_denied_skipped():
    from engine3.sandbox.s5_sandbox import MockCloudGoatSandboxRunner
    from engine3.stages.s2_path import CandidatePath, PathHop

    dummy_path = QueuedPath(
        queue_rank=1,
        path_id="test1234",
        queue_reason="test",
        path=CandidatePath(
            path_id="test1234",
            hops=[PathHop(from_node="user", to_node="role", action_used="sts:AssumeRole", edge_id="e1", edge_type="TRUSTED_BY")],
            start_node="user",
            target_node="role",
        ),
    )
    mock_runner = MockCloudGoatSandboxRunner()
    res = mock_runner.evaluate_sandbox_path(dummy_path, sim_status="POLICY_DENIED")

    assert res.sandbox_attempted is False
    assert res.sandbox_execution_success is None
    assert res.reason == "blocked_at_policy_simulator"
    assert res.sandbox_mode == "MOCKED"


def test_mock_sandbox_policy_allowed_evaluates():
    from engine3.sandbox.s5_sandbox import MockCloudGoatSandboxRunner
    from engine3.stages.s2_path import CandidatePath, PathHop

    dummy_path = QueuedPath(
        queue_rank=1,
        path_id="a1b2c3d4",
        queue_reason="test",
        path=CandidatePath(
            path_id="a1b2c3d4",
            hops=[
                PathHop(from_node="user", to_node="role", action_used="sts:AssumeRole", edge_id="e1", edge_type="TRUSTED_BY"),
                PathHop(from_node="role", to_node="bucket", action_used="s3:GetObject", edge_id="e2", edge_type="APPLIES_TO"),
            ],
            start_node="user",
            target_node="bucket",
        ),
    )
    mock_runner = MockCloudGoatSandboxRunner()
    res = mock_runner.evaluate_sandbox_path(dummy_path, sim_status="POLICY_ALLOWED")

    assert res.sandbox_attempted is True
    assert res.sandbox_scenario_name == "cloud_breach_s3"
    assert res.sandbox_mode == "MOCKED"
    assert len(res.sandbox_logs) > 0
    assert res.sandbox_logs[0].startswith("[MOCKED]")

