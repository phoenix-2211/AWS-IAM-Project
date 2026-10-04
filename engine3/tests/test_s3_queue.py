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
