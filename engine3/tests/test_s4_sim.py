"""Tests for Stage 4 Policy Simulator Engine."""

from pathlib import Path

import pytest

from engine3.adapters.graph_adapter import GraphAdapter
from engine3.adapters.rule_adapter import RuleAdapter
from engine3.stages.s1_match import Stage1Matcher
from engine3.stages.s2_path import Stage2PathFinder
from engine3.stages.s3_queue import Stage3Prioritizer
from engine3.stages.s4_sim import LivePolicySimulator, LocalPolicySimulator


def test_s4_local_simulator_baseline():
    import json
    fixture_path = Path("docs/contracts/iamgraph_fixture.json")
    rulebook_path = Path("rulebook/active_rulebook.json")

    with open(fixture_path, "r", encoding="utf-8") as f:
        graph_data = json.load(f)
    with open(rulebook_path, "r", encoding="utf-8") as f:
        rules_data = json.load(f)

    graph = GraphAdapter.from_json(graph_data)
    rules = RuleAdapter.from_json_list(rules_data)

    matcher = Stage1Matcher()
    match_results = matcher.match_rules(graph, rules)

    finder = Stage2PathFinder(max_depth=6)
    disc_res = finder.discover_paths(graph, match_results)

    prioritizer = Stage3Prioritizer()
    queue_res = prioritizer.prioritize_paths(disc_res.paths, rules)

    sim = LocalPolicySimulator()
    for q_path in queue_res.queue:
        res = sim.evaluate_path(q_path)
        assert res.status == "POLICY_ALLOWED"
        assert res.source == "local_evaluator"
        assert "local_evaluator, not AWS" in res.limitations


def test_s4_live_simulator_refuses_without_gate():
    live_sim = LivePolicySimulator()
    with pytest.raises(PermissionError, match="APPROVE-LIVE-SIM"):
        live_sim.evaluate_path(None, gate_token=None)


def test_s4_live_simulator_mocked_boto3(monkeypatch, tmp_path):
    from unittest.mock import MagicMock
    from engine3.stages.s2_path import CandidatePath, PathHop

    mock_boto3 = MagicMock()
    mock_client = MagicMock()
    mock_boto3.Session.return_value.client.return_value = mock_client
    mock_client.simulate_principal_policy.return_value = {
        "EvaluationResults": [{"EvalDecision": "allowed", "MissingContextValues": []}]
    }

    import sys
    sys.modules["boto3"] = mock_boto3

    hop = PathHop(
        from_node="arn:aws:iam::1111:role/R1",
        to_node="arn:aws:s3:::bucket",
        action_used="s3:GetObject",
        matched_rule_id="R1",
        edge_id="e1",
        edge_type="APPLIES_TO",
    )
    path = CandidatePath(
        path_id="p1",
        start_node="arn:aws:iam::1111:role/R1",
        target_node="arn:aws:s3:::bucket",
        hops=[hop],
    )
    from engine3.stages.s3_queue import QueuedPath
    q_path = QueuedPath(queue_rank=1, path_id="p1", queue_reason="test", path=path)

    live_sim = LivePolicySimulator()
    res = live_sim.evaluate_path(q_path, gate_token="APPROVE-LIVE-SIM", aws_profile="pbl-iam")

    assert res.status == "POLICY_ALLOWED"
    assert res.source == "aws_policy_simulator"
    assert "Evaluated against live AWS Policy Simulator API" in res.limitations

