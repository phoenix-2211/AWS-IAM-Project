"""Unit tests proving the strict separation of Stage 6 Evidence and Stage 7 Decision."""

import pytest
from engine3.s2_path_discovery import CandidatePath, PathHop
from engine3.s3_prioritization import QueuedPath
from engine3.s4_policy_verification import HopSimResult, PathSimResult
from engine3.s5_sandbox import SandboxRunResult
from engine3.s6_evidence import PathEvidence, Stage6EvidenceAggregator
from engine3.s7_decision import Stage7DecisionEngine, VerificationDecision


@pytest.fixture
def sample_queued_path() -> QueuedPath:
    return QueuedPath(
        queue_rank=1,
        path_id="BRANCH-TEST-100",
        queue_reason="Testing stage separation",
        path=CandidatePath(
            path_id="BRANCH-TEST-100",
            start_node="UserA",
            target_node="AdminRole",
            hops=[
                PathHop(
                    from_node="UserA",
                    to_node="AdminRole",
                    action_used="sts:AssumeRole",
                    edge_id="e1",
                    edge_type="TRUSTED_BY",
                )
            ],
        ),
    )


def test_s6_evidence_collects_only_no_status(sample_queued_path):
    """Confirm Stage 6 collects graph, policy, and sandbox evidence and contains NO status enum field."""
    sim_res = PathSimResult(
        path_id="BRANCH-TEST-100",
        status="POLICY_ALLOWED",
        status_reason="All hops allowed",
        hop_results=[
            HopSimResult(
                hop_index=0,
                from_node="UserA",
                to_node="AdminRole",
                action_used="sts:AssumeRole",
                decision="ALLOWED",
                eval_decision="allowed",
            )
        ],
    )
    sb_res = SandboxRunResult(
        path_id="BRANCH-TEST-100",
        status="VERIFIED_EXPLOITABLE",
        sandbox_scenario_name="custom-branch",
        sandbox_attempted=True,
        sandbox_execution_success=True,
    )

    aggregator = Stage6EvidenceAggregator()
    evidence = aggregator.collect_path_evidence(sample_queued_path, sim_res, sb_res)

    assert isinstance(evidence, PathEvidence)
    # Explicitly confirm PathEvidence contains NO status field
    assert not hasattr(evidence, "status")
    assert evidence.policy_simulator_result == "ALLOWED"
    assert evidence.sandbox_scenario_name == "custom-branch"
    assert evidence.sandbox_execution_success is True


def test_s7_decision_verified_exploitable(sample_queued_path):
    """1. VERIFIED_EXPLOITABLE: All policy hops allowed, scenario mapped, exploit succeeded."""
    sim_res = PathSimResult(path_id="BRANCH-TEST-100", status="POLICY_ALLOWED", status_reason="Allowed")
    sb_res = SandboxRunResult(
        path_id="BRANCH-TEST-100",
        status="VERIFIED_EXPLOITABLE",
        sandbox_scenario_name="custom-branch",
        sandbox_attempted=True,
        sandbox_execution_success=True,
    )

    engine = Stage7DecisionEngine()
    decision = engine.evaluate_decision(sim_res, sb_res)

    assert decision.status == "VERIFIED_EXPLOITABLE"
    assert decision.confidence_tier == "FULL_CHAIN_VERIFIED"


def test_s7_decision_policy_denied(sample_queued_path):
    """2. POLICY_DENIED: Policy simulator returns POLICY_DENIED at a hop."""
    sim_res = PathSimResult(
        path_id="BRANCH-TEST-100",
        status="POLICY_DENIED",
        status_reason="Denied by explicit deny on sts:AssumeRole",
        denying_hop_index=0,
        denying_action="sts:AssumeRole",
    )
    sb_res = None

    engine = Stage7DecisionEngine()
    decision = engine.evaluate_decision(sim_res, sb_res)

    assert decision.status == "POLICY_DENIED"
    assert decision.confidence_tier == "POLICY_DENIED"


def test_s7_decision_sandbox_failed(sample_queued_path):
    """3. SANDBOX_FAILED: Policy allowed, scenario mapped, but execution failed."""
    sim_res = PathSimResult(path_id="BRANCH-TEST-100", status="POLICY_ALLOWED", status_reason="Allowed")
    sb_res = SandboxRunResult(
        path_id="BRANCH-TEST-100",
        status="SANDBOX_FAILED",
        sandbox_scenario_name="custom-branch",
        sandbox_attempted=True,
        sandbox_execution_success=False,
        reason="Runtime assertion failed during execution",
    )

    engine = Stage7DecisionEngine()
    decision = engine.evaluate_decision(sim_res, sb_res)

    assert decision.status == "SANDBOX_FAILED"
    assert decision.confidence_tier == "SANDBOX_EXECUTION_FAILED"


def test_s7_decision_policy_verified_no_sandbox(sample_queued_path):
    """4. POLICY_VERIFIED_NO_SANDBOX: All hops policy-ALLOWED, but no scenario/module mapped."""
    sim_res = PathSimResult(path_id="BRANCH-TEST-100", status="POLICY_ALLOWED", status_reason="Allowed")
    sb_res = SandboxRunResult(
        path_id="BRANCH-TEST-100",
        status="POLICY_VERIFIED_NO_SANDBOX",
        sandbox_scenario_name=None,  # No module/scenario available
        sandbox_attempted=False,
        sandbox_execution_success=None,
    )

    engine = Stage7DecisionEngine()
    decision = engine.evaluate_decision(sim_res, sb_res)

    assert decision.status == "POLICY_VERIFIED_NO_SANDBOX"
    assert decision.confidence_tier == "POLICY_VERIFIED_NO_SANDBOX"


def test_s7_decision_partial_chain_verified(sample_queued_path):
    """5. PARTIAL_CHAIN_VERIFIED: Multi-hop path partially verified due to technical limitation skip."""
    sim_res = PathSimResult(
        path_id="BRANCH-TEST-100",
        status="PARTIAL_CHAIN_VERIFIED",
        status_reason="Hop 1 skipped due to technical limitation",
    )
    sb_res = None

    engine = Stage7DecisionEngine()
    decision = engine.evaluate_decision(sim_res, sb_res)

    assert decision.status == "PARTIAL_CHAIN_VERIFIED"
    assert decision.confidence_tier == "PARTIAL_CHAIN_VERIFIED"
