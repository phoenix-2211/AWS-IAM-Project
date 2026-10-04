"""Tests for Stage 2 Attack-Path Discovery Engine."""

import json
from pathlib import Path

from engine3.adapters.graph_adapter import GraphAdapter
from engine3.adapters.rule_adapter import RuleAdapter
from engine3.stages.s1_match import Stage1Matcher
from engine3.stages.s2_path import Stage2PathFinder


def test_s2_path_finder_baseline():
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
    res = finder.discover_paths(graph, match_results)

    assert len(res.paths) >= 2
    assert "A missing attack path is never proof of absolute safety." in res.limitations

    for path in res.paths:
        assert path.start_node == "arn:aws:iam::111122223333:user/dev-alice"
        assert path.target_node == "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-password-AbCdEf"
        assert len(path.hops) >= 2


def test_s2_path_finder_deterministic_path_id():
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
    res1 = finder.discover_paths(graph, match_results)
    res2 = finder.discover_paths(graph, match_results)

    ids1 = [p.path_id for p in res1.paths]
    ids2 = [p.path_id for p in res2.paths]

    assert ids1 == ids2
