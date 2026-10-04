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

    # 12 rules total
    assert len(results) == 12

    # Map by rule_id
    res_map = {r.rule_id: r for r in results}

    assert res_map["RULE-IAM-001"].status == "MATCHED"
    assert len(res_map["RULE-IAM-001"].matches) == 3
    assert res_map["RULE-IAM-001"].matches[0].principal_id == "arn:aws:iam::111122223333:role/DeployRole"

    assert res_map["RULE-IAM-002"].status == "MATCHED"
    assert res_map["RULE-IAM-002"].matches[0].principal_id == "arn:aws:iam::111122223333:user/dev-alice"
    assert res_map["RULE-IAM-002"].matches[0].condition_unevaluated is True

    assert res_map["RULE-IAM-003"].status == "MATCHED"
    # Matches DeployRole and AdminRole
    assert len(res_map["RULE-IAM-003"].matches) == 2

    assert res_map["RULE-IAM-012"].status == "NOT_REPRESENTABLE"


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
