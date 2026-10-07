"""Tests for Stage 1 Rule Matcher."""

import json
from pathlib import Path

from engine3.adapters.graph_adapter import GraphAdapter
from engine3.adapters.rule_adapter import RuleAdapter
from engine3.stages.s1_match import Stage1Matcher


def test_s1_matcher_baseline():
    fixture_path = Path("docs/contracts/iamgraph_fixture.json")
    rulebook_path = Path("rulebook/active_rulebook.json")

    with open(fixture_path, "r", encoding="utf-8") as f:
        graph_data = json.load(f)
    with open(rulebook_path, "r", encoding="utf-8") as f:
        rules_data = json.load(f)

    graph = GraphAdapter.from_json(graph_data)
    rules = RuleAdapter.from_json_list(rules_data)

    matcher = Stage1Matcher()
    results = matcher.match_rules(graph, rules, rulebook_origin="active")

    # 179 rules total in active_rulebook.json
    assert len(results) == 179

    # Map by rule_id
    res_map = {r.rule_id: r for r in results}

    assert res_map["RULE-IAM-010"].status == "MATCHED"
    assert len(res_map["RULE-IAM-010"].matches) == 1
    assert res_map["RULE-IAM-010"].matches[0].principal_id == "arn:aws:iam::111122223333:user/dev-alice"

    assert res_map["RULE-IAM-012"].status == "MATCHED"
    assert res_map["RULE-IAM-012"].matches[0].principal_id == "arn:aws:iam::111122223333:user/dev-alice"

    assert res_map["RULE-IAM-011"].status == "MATCHED"
    assert res_map["RULE-IAM-011"].matches[0].principal_id == "arn:aws:iam::111122223333:role/DevRole"



def test_s1_matcher_negative_no_match():
    fixture_path = Path("docs/contracts/iamgraph_fixture.json")
    rulebook_path = Path("rulebook/active_rulebook.json")

    with open(fixture_path, "r", encoding="utf-8") as f:
        graph_data = json.load(f)
    with open(rulebook_path, "r", encoding="utf-8") as f:
        rules_data = json.load(f)

    graph = GraphAdapter.from_json(graph_data)
    rules = RuleAdapter.from_json_list(rules_data)

    matcher = Stage1Matcher()
    results = matcher.match_rules(graph, rules)
    res_map = {r.rule_id: r for r in results}

    assert res_map["RULE-IAM-004"].status == "NO_MATCH"


def test_s1_matcher_all_draft_rules():
    fixture_path = Path("docs/contracts/iamgraph_fixture.json")
    rulebook_path = Path("rulebook/active_rulebook.json")

    with open(fixture_path, "r", encoding="utf-8") as f:
        graph_data = json.load(f)
    with open(rulebook_path, "r", encoding="utf-8") as f:
        rules_data = json.load(f)

    # Set all rules to DRAFT
    for r in rules_data:
        r["status"] = "DRAFT"

    graph = GraphAdapter.from_json(graph_data)
    rules = RuleAdapter.from_json_list(rules_data)

    active_rules = [r for r in rules if r.status == "ACTIVE"]
    assert len(active_rules) == 0

    matcher = Stage1Matcher()
    results = matcher.match_rules(graph, active_rules)
    assert len(results) == 0


def test_s1_matcher_empty_graph():
    rulebook_path = Path("rulebook/active_rulebook.json")
    with open(rulebook_path, "r", encoding="utf-8") as f:
        rules_data = json.load(f)

    empty_graph_data = {
        "contract_name": "IAMGraph",
        "contract_version": "0.1",
        "snapshot": {"snapshot_id": "snap-empty", "account_id": "1111", "collected_at": "", "origin": "", "collection_status": "complete"},
        "principals": [],
        "permissions": [],
        "resources": [],
        "edges": []
    }
    graph = GraphAdapter.from_json(empty_graph_data)
    rules = RuleAdapter.from_json_list(rules_data)

    matcher = Stage1Matcher()
    results = matcher.match_rules(graph, rules)
    assert len(results) == len(rules)
    for r in results:
        if r.status != "NOT_REPRESENTABLE":
            assert r.status == "NO_MATCH"
            assert len(r.matches) == 0


def test_s1_matcher_deterministic_ordering():
    fixture_path = Path("docs/contracts/iamgraph_fixture.json")
    rulebook_path = Path("rulebook/active_rulebook.json")

    with open(fixture_path, "r", encoding="utf-8") as f:
        graph_data = json.load(f)
    with open(rulebook_path, "r", encoding="utf-8") as f:
        rules_data = json.load(f)

    graph = GraphAdapter.from_json(graph_data)
    rules = RuleAdapter.from_json_list(rules_data)

    matcher = Stage1Matcher()
    results = matcher.match_rules(graph, rules)

    rule_ids = [r.rule_id for r in results]
    assert rule_ids == sorted(rule_ids)

    for r in results:
        principal_ids = [m.principal_id for m in r.matches]
        assert principal_ids == sorted(principal_ids)


def test_s1_matcher_sample_trees():
    rulebook_path = Path("rulebook/active_rulebook.json")
    with open(rulebook_path, "r", encoding="utf-8") as f:
        rules_data = json.load(f)
    rules = RuleAdapter.from_json_list(rules_data)
    matcher = Stage1Matcher()

    # Tree 1: Benign -> 0 matches
    with open("docs/contracts/fixtures/tree_1_benign.json", "r", encoding="utf-8") as f:
        g1_data = json.load(f)
    g1 = GraphAdapter.from_json(g1_data)
    res1 = matcher.match_rules(g1, rules)
    matched_count_1 = sum(len(r.matches) for r in res1)
    assert matched_count_1 == 0

    # Tree 5: Critical -> multiple matches including CRITICAL severity
    with open("docs/contracts/fixtures/tree_5_critical.json", "r", encoding="utf-8") as f:
        g5_data = json.load(f)
    g5 = GraphAdapter.from_json(g5_data)
    res5 = matcher.match_rules(g5, rules)
    matched_count_5 = sum(len(r.matches) for r in res5)
    assert matched_count_5 > 1

    rule_map_5 = {r.rule_id: r for r in res5 if r.status == "MATCHED"}
    rule_sev_map = {r.rule_id: r.severity for r in rules}
    critical_matches = [
        r_id for r_id in rule_map_5
        if rule_sev_map.get(r_id) == "CRITICAL"
    ]
    assert len(critical_matches) >= 1


