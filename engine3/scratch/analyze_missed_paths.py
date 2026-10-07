"""Analyzes why each of the 31 IAM-Vulnerable benchmark paths was caught or missed."""

import json
from pathlib import Path
from evaluate_iam_vulnerable_benchmark import IAM_VULNERABLE_PATHS, run_benchmark

BASE_DIR = Path(__file__).parent.parent
TF_DIR = BASE_DIR / "scratch" / "iam-vulnerable" / "modules" / "free-resources" / "privesc-paths"
RULEBOOK_PATH = BASE_DIR / "rulebook" / "active_rulebook.json"

def main():
    res = run_benchmark()
    caught = set(res["caught_paths"])
    missed = res["missed_paths"]

    with open(RULEBOOK_PATH, "r", encoding="utf-8") as f:
        rules = json.load(f)

    active_actions = {r["action"].lower() for r in rules if r.get("status") == "ACTIVE"}

    print("\n--- CAUGHT BENCHMARK PATHS ---")
    for p in sorted(list(caught)):
        print(f"  [CAUGHT] {p}")

    print("\n--- MISSED BENCHMARK PATHS ANALYSIS ---")
    rule_gaps = 0
    schema_limitations = 0

    for p in missed:
        tf_file = TF_DIR / f"{p}.tf"
        if not tf_file.exists():
            # Try finding matching file
            matches = list(TF_DIR.glob(f"*{p}*.tf"))
            if matches:
                tf_file = matches[0]

        actions_in_file = []
        if tf_file.exists():
            text = tf_file.read_text(encoding="utf-8")
            import re
            act_matches = re.findall(r'"([a-zA-Z0-9]+:[a-zA-Z0-9*]+)"', text)
            actions_in_file = sorted(list(set(act_matches)))

        # Check if active rulebook has a rule for any of these actions
        has_rule = any(a.lower() in active_actions for a in actions_in_file)
        reason = "Rule Coverage Gap (Rule missing for action)" if not has_rule else "Schema/Graph Target Mapping Gap (APPLIES_TO target type unrepresentable)"
        if not has_rule:
            rule_gaps += 1
        else:
            schema_limitations += 1

        print(f"  [MISSED] {p}")
        print(f"    Actions in TF: {actions_in_file}")
        print(f"    Reason: {reason}\n")

    print(f"Summary of Missed Paths: {rule_gaps} Rule Coverage Gaps, {schema_limitations} Schema/Target Mapping Limitations")

if __name__ == "__main__":
    main()
