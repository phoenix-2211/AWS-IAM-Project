"""Prints detailed breakdown of caught and missed IAM-Vulnerable benchmark paths."""

import json
from pathlib import Path

from engine3.adapters.graph_adapter import GraphAdapter
from engine3.adapters.rule_adapter import RuleAdapter
from engine3.stages.s0_load import Stage0Loader
from engine3.stages.s1_match import Stage1Matcher
from engine3.stages.s2_path import Stage2PathFinder

BASE_DIR = Path(__file__).parent.parent
FIXTURE_PATH = BASE_DIR / "docs" / "contracts" / "fixtures" / "tree_7_industry_scale.json"
RULEBOOK_PATH = BASE_DIR / "rulebook" / "active_rulebook.json"

def main():
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        graph_data = json.load(f)
    with open(RULEBOOK_PATH, "r", encoding="utf-8") as f:
        rules_data = json.load(f)

    graph = GraphAdapter.from_json(graph_data)
    rules = RuleAdapter.from_json_list(rules_data)

    matcher = Stage1Matcher()
    match_results = matcher.match_rules(graph, rules)
    finder = Stage2PathFinder(max_depth=6)
    disc_res = finder.discover_paths(graph, match_results)

    matched_rules_by_path = {}

    for r_res in match_results:
        if r_res.status == "MATCHED":
            for m in r_res.matches:
                p_id = m.principal_id
                matched_rules_by_path.setdefault(p_id, []).append((r_res.rule_id, m.target_id))

    print(f"Total Principals with Matched Rules: {len(matched_rules_by_path)}")
    for principal_arn, matches in sorted(matched_rules_by_path.items()):
        p_name = principal_arn.split("/")[-1]
        print(f"\nPrincipal: {p_name}")
        for r_id, target in matches:
            t_name = target.split("/")[-1]
            print(f"  -> Rule: {r_id} | Target: {t_name}")

if __name__ == "__main__":
    main()
