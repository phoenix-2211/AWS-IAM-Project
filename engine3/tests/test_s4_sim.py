"""Tests for Stage 4 Policy Simulator Engine."""

from pathlib import Path

import pytest

from engine3.adapters.graph_adapter import GraphAdapter
from engine3.adapters.rule_adapter import RuleAdapter
from engine3.stages.s1_match import Stage1Matcher
from engine3.stages.s2_path import Stage2PathFinder
from engine3.stages.s3_queue import Stage3Prioritizer
from engine3.stages.s4_sim import LivePolicySimulator, RecordedPolicySimulator


def test_s4_recorded_simulator_baseline():
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

    sim = RecordedPolicySimulator()
    for q_path in queue_res.queue:
        res = sim.evaluate_path(q_path)
        assert res.status == "POLICY_ALLOWED_UNCONFIRMED"
        assert res.source == "local_evaluator"
        assert "Offline local evaluation, not independent verification" in res.limitations


def test_s4_live_simulator_refuses_without_gate():
    live_sim = LivePolicySimulator()
    with pytest.raises(PermissionError, match="APPROVE-LIVE-SIM"):
        live_sim.evaluate_path(None, gate_token=None)
