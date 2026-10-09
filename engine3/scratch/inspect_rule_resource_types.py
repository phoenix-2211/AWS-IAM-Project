"""Inspects resource_type for missed path actions in active_rulebook.json."""

import json
from pathlib import Path

RULEBOOK_PATH = Path("rulebook/active_rulebook.json")

def main():
    with open(RULEBOOK_PATH, "r", encoding="utf-8") as f:
        rules = json.load(f)

    target_actions = [
        "iam:AddUserToGroup",
        "iam:SetDefaultPolicyVersion",
        "cloudformation:CreateStack",
        "datapipeline:CreatePipeline"
    ]

    for act in target_actions:
        matching_rules = [r for r in rules if r.get("action", "").lower() == act.lower()]
        print(f"Action: {act} -> Matching Rules in Rulebook: {len(matching_rules)}")
        for r in matching_rules:
            print(f"  Rule ID: {r['rule_id']} | resource_type: '{r['resource_type']}' | status: {r['status']}")

if __name__ == "__main__":
    main()
