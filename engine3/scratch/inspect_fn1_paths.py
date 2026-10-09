"""Inspects discovered attack paths for fn1-privesc3-partial-user and checks for duplicate hop sequences."""

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

    fn1_paths = [p for p in disc_res.paths if "fn1-privesc3-partial-user" in p.start_node]
    print(f"Total paths starting at 'fn1-privesc3-partial-user': {len(fn1_paths)}")

    # Check for duplicate hop sequences (from_node, to_node, action_used)
    hop_seqs = []
    rule_seqs = []

    for i, p in enumerate(fn1_paths):
        h_seq = tuple((h.from_node, h.to_node, h.action_used) for h in p.hops)
        r_seq = tuple((h.from_node, h.to_node, h.matched_rule_id) for h in p.hops)
        hop_seqs.append(h_seq)
        rule_seqs.append(r_seq)
        print(f"\nPath {i+1} [ID: {p.path_id}]:")
        for h in p.hops:
            print(f"  {h.from_node} -> ({h.action_used} / {h.matched_rule_id}) -> {h.to_node}")

    unique_hop_seqs = set(hop_seqs)
    unique_rule_seqs = set(rule_seqs)
    print(f"\n=======================================================")
    print(f"Total paths for fn1-privesc3-partial-user: {len(fn1_paths)}")
    print(f"Unique (from_node, to_node, action_used) hop sequences: {len(unique_hop_seqs)}")
    print(f"Unique (from_node, to_node, rule_id) sequences: {len(unique_rule_seqs)}")
    print(f"=======================================================")

if __name__ == "__main__":
    main()
