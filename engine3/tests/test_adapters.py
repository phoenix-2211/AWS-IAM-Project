"""Tests for GraphAdapter and RuleAdapter round-trip conversion."""

import json
from pathlib import Path

from engine3.adapters.graph_adapter import GraphAdapter
from engine3.adapters.rule_adapter import RuleAdapter


def test_graph_adapter_fixture_counts() -> None:
    fixture_path = Path("docs/contracts/iamgraph_fixture.json")
    with open(fixture_path, "r", encoding="utf-8") as f:
        raw_graph = json.load(f)

    internal_graph = GraphAdapter.from_json(raw_graph)

    # 13 total nodes in fixture
    total_nodes = (
        len(internal_graph.principals)
        + len(internal_graph.permissions)
        + len(internal_graph.resources)
    )
    assert total_nodes == 13
    assert len(internal_graph.principals) == 5  # 1 User, 3 Roles, 1 ServicePrincipal
    assert len(internal_graph.permissions) == 7
    assert len(internal_graph.resources) == 1

    # 21 total edges in fixture
    assert len(internal_graph.edges) == 21

    has_perm_count = sum(1 for e in internal_graph.edges if e.type == "HAS_PERMISSION")
    trusted_by_count = sum(1 for e in internal_graph.edges if e.type == "TRUSTED_BY")
    applies_to_count = sum(1 for e in internal_graph.edges if e.type == "APPLIES_TO")

    assert has_perm_count == 7
    assert trusted_by_count == 5
    assert applies_to_count == 9


def test_rule_adapter_sample() -> None:
    sample_path = Path("docs/contracts/SecurityRule_sample.json")
    with open(sample_path, "r", encoding="utf-8") as f:
        raw_rules = json.load(f)

    rules = RuleAdapter.from_json_list(raw_rules)
    assert len(rules) == 5
    assert rules[0].rule_id == "TEST-IAM-001"
    assert rules[0].action == "iam:PassRole"
    assert rules[0].status == "ACTIVE"
