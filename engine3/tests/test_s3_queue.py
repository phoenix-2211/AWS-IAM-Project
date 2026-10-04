"""Tests for Stage 3 Prioritized Queue Engine."""

import json
from pathlib import Path

from engine3.adapters.graph_adapter import GraphAdapter
from engine3.adapters.rule_adapter import RuleAdapter
from engine3.stages.s1_match import Stage1Matcher
from engine3.stages.s2_path import Stage2PathFinder
from engine3.stages.s3_queue import Stage3Prioritizer


def test_s3_prioritizer_baseline():
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

    assert queue_res.total_paths == len(disc_res.paths)
    assert len(queue_res.queue) >= 2

    ranks = [item.queue_rank for item in queue_res.queue]
    assert ranks == list(range(1, len(queue_res.queue) + 1))


def test_s3_prioritizer_empty_paths():
    prioritizer = Stage3Prioritizer()
    queue_res = prioritizer.prioritize_paths([], [])
    assert queue_res.total_paths == 0
    assert "No candidate paths" in queue_res.message


def test_s3_worked_score_and_tie_break():
    from engine3.contracts.models import Rule
    from engine3.stages.s2_path import CandidatePath, PathHop

    rule_crit = Rule(
        rule_id="RULE-CRIT",
        title="Critical Rule",
        description="desc",
        severity="CRITICAL",
        principal_type="role",
        action="action:crit",
        resource_type="res",
        relationship="rel",
        source={"name": "src"},
        version="0.1",
        status="ACTIVE",
    )
    rule_high = Rule(
        rule_id="RULE-HIGH",
        title="High Rule",
        description="desc",
        severity="HIGH",
        principal_type="role",
        action="action:high",
        resource_type="res",
        relationship="rel",
        source={"name": "src"},
        version="0.1",
        status="ACTIVE",
    )

    hop_crit = PathHop(from_node="n1", to_node="n2", action_used="action:crit", matched_rule_id="RULE-CRIT", edge_id="e1", edge_type="APPLIES_TO")
    hop_high = PathHop(from_node="n1", to_node="n2", action_used="action:high", matched_rule_id="RULE-HIGH", edge_id="e2", edge_type="APPLIES_TO")

    # Path 1: HIGH severity, 2 hops, 0 assumptions
    path1 = CandidatePath(path_id="path-b", start_node="n1", target_node="n2", hops=[hop_high, hop_high], assumptions=[])
    # Path 2: CRITICAL severity, 3 hops, 1 assumption
    path2 = CandidatePath(path_id="path-a", start_node="n1", target_node="n2", hops=[hop_crit, hop_crit, hop_crit], assumptions=["cond_unevaluated"])
    # Path 3: HIGH severity, 1 hop, 0 assumptions
    path3 = CandidatePath(path_id="path-c", start_node="n1", target_node="n2", hops=[hop_high], assumptions=[])

    prioritizer = Stage3Prioritizer()
    res = prioritizer.prioritize_paths([path1, path2, path3], [rule_crit, rule_high])

    # Rank 1 must be path2 (CRITICAL severity takes priority over hop count)
    assert res.queue[0].path_id == "path-a"
    assert res.queue[0].queue_rank == 1
    assert "severity CRITICAL" in res.queue[0].queue_reason

    # Rank 2 must be path3 (HIGH severity, 1 hop < 2 hops)
    assert res.queue[1].path_id == "path-c"
    assert res.queue[1].queue_rank == 2

    # Rank 3 must be path1 (HIGH severity, 2 hops)
    assert res.queue[2].path_id == "path-b"
    assert res.queue[2].queue_rank == 3

