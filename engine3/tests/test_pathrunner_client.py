"""Unit tests for PathrunnerClient hierarchy, Subprocess safety gates, and Mock verification tagging."""

import pytest
from engine3.sandbox.pathrunner_client import (
    PathrunnerClient,
    SubprocessPathrunnerClient,
    MockPathrunnerClient,
    ModuleResult,
)
from engine3.sandbox.orchestrator import BranchOrchestrator, OrchestratorRunResult
from engine3.sandbox.terraform_generator import BranchJSON, BranchHop
from engine3.s0_intake import Stage0LoadResult
from engine3.s3_prioritization import QueuedPath
from engine3.s4_policy_verification import PathSimResult
from engine3.s5_sandbox import CustomSandboxRunner
from engine3.s8_output import Stage8OutputAssembler
from engine3.adapters.graph_adapter import GraphAdapter
from engine3.adapters.rule_adapter import RuleAdapter


# ---------------------------------------------------------------------------
# STEP B: Client Hierarchy & Orchestrator Credential Passing
# ---------------------------------------------------------------------------


def test_mock_pathrunner_client_returns_mock_tagged_result():
    client = MockPathrunnerClient()
    res = client.run_module(
        module_id="iam-001",
        options={"target": "target-role", "principal": "initial-user"},
        credentials={"access_key_id": "test"},
    )

    assert res.success is True
    assert res.exit_code == 0
    assert res.verification_source == "MOCK"
    assert "[MOCK]" in res.stdout
    assert res.captured_credentials is not None
    assert "access_key_id" in res.captured_credentials


def test_orchestrator_stops_if_intermediate_hop_yields_no_credentials():
    """If a non-terminal intermediate hop succeeds but yields no credentials, chain stops immediately."""
    class NoCredsMockClient(PathrunnerClient):
        def run_module(self, module_id, options, credentials=None) -> ModuleResult:
            return ModuleResult(
                success=True,
                exit_code=0,
                stdout="[MOCK] executed without yielding credentials",
                stderr="",
                captured_credentials=None,  # No credentials yielded!
                verification_source="MOCK",
            )

    branch = BranchJSON(
        branch_id="b-multi-hop",
        hops=[
            BranchHop(source="user_a", action="sts:AssumeRole", target="role_b"),
            BranchHop(source="role_b", action="s3:GetObject", target="bucket_c"),
        ],
        goal="Read bucket_c",
    )

    orchestrator = BranchOrchestrator(client=NoCredsMockClient())
    result = orchestrator.execute_branch(branch)

    # Chain must stop at hop 1 because role_b credentials were not captured
    assert result.status == "SANDBOX_FAILED"
    assert "yielded no captured credentials" in result.reason
    assert len(result.hops) == 1
    assert result.hops[0].result == "sandbox_failed"


def test_orchestrator_no_string_sniffing_handles_module_failure():
    """Failure is driven strictly by ModuleResult.success / exit_code, not action string contents."""
    class FailingClient(PathrunnerClient):
        def run_module(self, module_id, options, credentials=None) -> ModuleResult:
            return ModuleResult(
                success=False,
                exit_code=1,
                stdout="[MOCK] module failure",
                stderr="Execution error occurred",
                captured_credentials=None,
                verification_source="MOCK",
            )

    branch = BranchJSON(
        branch_id="b-fail",
        hops=[
            BranchHop(source="user_a", action="iam:CreatePolicyVersion", target="policy_b"),
        ],
        goal="Escalate",
    )

    orchestrator = BranchOrchestrator(client=FailingClient())
    result = orchestrator.execute_branch(branch)

    assert result.status == "SANDBOX_FAILED"
    assert "exit code 1" in result.reason
    assert len(result.hops) == 1
    assert result.hops[0].result == "sandbox_failed"


# ---------------------------------------------------------------------------
# STEP C: Mock Verification Tagging & S8 Output Integrity
# ---------------------------------------------------------------------------


def test_mock_client_run_tagged_mock_in_stage8_output():
    """Any run through MockPathrunnerClient must tag the VerificationResult with verification_source/sandbox_mode='MOCKED'."""
    runner = CustomSandboxRunner(client=MockPathrunnerClient())

    from engine3.stages.s2_path import CandidatePath, PathHop
    qp = QueuedPath(
        queue_rank=1,
        path_id="test-p1",
        queue_reason="test",
        path=CandidatePath(
            path_id="test-p1",
            hops=[
                PathHop(from_node="user_a", to_node="role_b", action_used="sts:AssumeRole", edge_id="e1", edge_type="TRUSTED_BY"),
                PathHop(from_node="role_b", to_node="bucket_c", action_used="s3:GetObject", edge_id="e2", edge_type="APPLIES_TO"),
            ],
            start_node="user_a",
            target_node="bucket_c",
        ),
    )

    sb_res = runner.evaluate_sandbox_path(qp, sim_status="POLICY_ALLOWED")
    assert sb_res.sandbox_mode == "MOCKED"
    assert sb_res.status == "VERIFIED_EXPLOITABLE"

    assembler = Stage8OutputAssembler()
    load_res = Stage0LoadResult(is_valid=True, iamgraph_content_sha256="sha", rulebook_sha256="sha")
    sim_res = PathSimResult(
        path_id="test-p1",
        status="POLICY_ALLOWED",
        status_reason="test policy allowed",
        source="local_evaluator",
    )

    doc = assembler.assemble(
        load_res=load_res,
        queue_paths=[qp],
        sim_results=[sim_res],
        sandbox_results=[sb_res],
        output_file=None,
    )

    assert doc["run"]["sandbox_mode"] == "MOCKED"
    assert doc["paths"][0]["status"] == "VERIFIED_EXPLOITABLE"


# ---------------------------------------------------------------------------
# STEP D: SubprocessPathrunnerClient Safety Gates & Dry-Run Argv Validation
# ---------------------------------------------------------------------------


def test_subprocess_client_safety_gates_refuse_without_budget():
    client = SubprocessPathrunnerClient(
        budget_confirmed=False,
        account_id_confirmed="111122223333",
        gate_token="APPROVE-DEPLOY",
    )
    with pytest.raises(PermissionError, match="budget_confirmed must be True"):
        client.run_module("iam-001", {"target": "role-1"})


def test_subprocess_client_safety_gates_refuse_without_account_id():
    client = SubprocessPathrunnerClient(
        budget_confirmed=True,
        account_id_confirmed=None,
        gate_token="APPROVE-DEPLOY",
    )
    with pytest.raises(PermissionError, match="account_id_confirmed missing"):
        client.run_module("iam-001", {"target": "role-1"})


def test_subprocess_client_safety_gates_refuse_unauthorized_account():
    client = SubprocessPathrunnerClient(
        budget_confirmed=True,
        account_id_confirmed="999999999999",  # Not in ALLOWED_ACCOUNTS
        gate_token="APPROVE-DEPLOY",
    )
    with pytest.raises(PermissionError, match="not in ALLOWED_ACCOUNTS"):
        client.run_module("iam-001", {"target": "role-1"})


def test_subprocess_client_safety_gates_refuse_without_gate_token():
    client = SubprocessPathrunnerClient(
        budget_confirmed=True,
        account_id_confirmed="111122223333",
        gate_token="WRONG_TOKEN",
    )
    with pytest.raises(PermissionError, match="APPROVE-DEPLOY gate token missing"):
        client.run_module("iam-001", {"target": "role-1"})


def test_subprocess_client_build_argv_safe_dry_run():
    """Verify build_argv creates a safe list of strings without invoking any subprocess or AWS call."""
    client = SubprocessPathrunnerClient(
        executable_path="pathrunner",
        budget_confirmed=True,
        account_id_confirmed="111122223333",
        gate_token="APPROVE-DEPLOY",
    )
    argv = client.build_argv(
        module_id="iam-001",
        options={
            "target": "arn:aws:iam::111122223333:policy/admin-policy",
            "principal": "arn:aws:iam::111122223333:user/test-user",
        },
    )

    assert isinstance(argv, list)
    assert argv[0] == "pathrunner"
    assert argv[1] == "run"
    assert argv[2] == "--module"
    assert argv[3] == "iam-001"
    assert "--principal" in argv
    assert "arn:aws:iam::111122223333:user/test-user" in argv
    assert "--target" in argv
    assert "arn:aws:iam::111122223333:policy/admin-policy" in argv
