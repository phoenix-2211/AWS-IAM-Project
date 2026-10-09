"""Check exact node counts and node types in tree_7_industry_scale.json."""

import json

with open("docs/contracts/fixtures/tree_7_industry_scale.json", "r", encoding="utf-8") as f:
    graph = json.load(f)

nodes = graph["nodes"]
edges = graph["edges"]

user_nodes = [n for n in nodes if n["type"] == "User"]
role_nodes = [n for n in nodes if n["type"] == "Role"]
perm_nodes = [n for n in nodes if n["type"] == "Permission"]
resource_nodes = [n for n in nodes if n["type"] == "Resource"]
other_nodes = [n for n in nodes if n["type"] not in ("User", "Role", "Permission", "Resource")]

print(f"Total Nodes in JSON array: {len(nodes)}")
print(f"  User Nodes:       {len(user_nodes)}")
print(f"  Role Nodes:       {len(role_nodes)}")
print(f"  Permission Nodes: {len(perm_nodes)}")
print(f"  Resource Nodes:   {len(resource_nodes)}")
print(f"  Other Nodes:      {len(other_nodes)}")
print(f"Sum: {len(user_nodes) + len(role_nodes) + len(perm_nodes) + len(resource_nodes) + len(other_nodes)}")
print(f"Total Edges in JSON array: {len(edges)}")
