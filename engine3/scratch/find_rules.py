"""Search active_rulebook.json for policyversion, cloudformation, datapipeline rules."""

import json
from pathlib import Path

with open("rulebook/active_rulebook.json", "r", encoding="utf-8") as f:
    rules = json.load(f)

for term in ["policyversion", "cloudformation", "datapipeline", "passrole"]:
    matches = [r for r in rules if term in r["action"].lower() or term in r["title"].lower() or term in r["description"].lower()]
    print(f"\nTerm: '{term}' -> Found {len(matches)} rules:")
    for r in matches[:5]:
        print(f"  ID: {r['rule_id']} | Action: '{r['action']}' | ResourceType: '{r['resource_type']}' | Title: {r['title']}")
