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


def test_s2_hand_enumerated_paths():
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

    # Fixture yields candidate paths (2448 paths across 179 rules in active_rulebook.json)
    assert len(res.paths) == 2448

    for p in res.paths:
        # Check depth limit
        assert len(p.hops) <= 6
        # Check cycle handling (no node appears twice in trajectory)
        visited = {p.start_node}
        for hop in p.hops:
            assert hop.to_node not in visited
            visited.add(hop.to_node)


def test_s2_cycle_handling():
    graph_data = {
        "contract_name": "IAMGraph",
        "contract_version": "0.1",
        "snapshot": {"snapshot_id": "snap-cycle", "account_id": "1111", "collected_at": "", "origin": "", "collection_status": "complete"},
        "principals": [
            {"id": "node:User:A", "type": "User", "arn": "arn:aws:iam::1111:user/A"},
            {"id": "node:Role:B", "type": "Role", "arn": "arn:aws:iam::1111:role/B"},
        ],
        "permissions": [],
        "resources": [
            {"id": "node:Secret:C", "type": "Resource", "resource_type": "secretsmanager_secret", "arn": "arn:aws:secretsmanager:us-east-1:1111:secret:C"}
        ],
        "edges": [
            {"id": "e1", "type": "TRUSTED_BY", "source": "node:User:A", "target": "node:Role:B"},
            {"id": "e2", "type": "TRUSTED_BY", "source": "node:Role:B", "target": "node:User:A"},
            {"id": "e3", "type": "APPLIES_TO", "source": "node:Role:B", "target": "node:Secret:C"},
        ]
    }
    graph = GraphAdapter.from_json(graph_data)
    finder = Stage2PathFinder(max_depth=6)
    res = finder.discover_paths(graph, [])

    for p in res.paths:
        visited = {p.start_node}
        for hop in p.hops:
            assert hop.to_node not in visited
            visited.add(hop.to_node)


def test_s2_depth_limit():
    graph_data = {
        "contract_name": "IAMGraph",
        "contract_version": "0.1",
        "snapshot": {"snapshot_id": "snap-depth", "account_id": "1111", "collected_at": "", "origin": "", "collection_status": "complete"},
        "principals": [
            {"id": "n0", "type": "User", "arn": "arn:aws:iam::1111:user/u0"},
            {"id": "n1", "type": "Role", "arn": "arn:aws:iam::1111:role/r1"},
            {"id": "n2", "type": "Role", "arn": "arn:aws:iam::1111:role/r2"},
            {"id": "n3", "type": "Role", "arn": "arn:aws:iam::1111:role/r3"},
        ],
        "permissions": [],
        "resources": [],
        "edges": [
            {"id": "e1", "type": "TRUSTED_BY", "source": "n0", "target": "n1"},
            {"id": "e2", "type": "TRUSTED_BY", "source": "n1", "target": "n2"},
            {"id": "e3", "type": "TRUSTED_BY", "source": "n2", "target": "n3"},
        ]
    }
    graph = GraphAdapter.from_json(graph_data)
    finder = Stage2PathFinder(max_depth=2)
    res = finder.discover_paths(graph, [])

    for p in res.paths:
        assert len(p.hops) <= 2

