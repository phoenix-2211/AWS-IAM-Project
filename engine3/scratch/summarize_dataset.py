import glob
import yaml
from collections import Counter

yaml_files = sorted(glob.glob("scratch/pathfinding.cloud/data/paths/aws/**/*.yaml", recursive=True))

service_counts = Counter()
category_counts = Counter()
author_counts = Counter()
tools_counts = Counter()

all_paths = []
for fpath in yaml_files:
    with open(fpath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        if not data:
            continue
        pid = data.get("id")
        services = data.get("services", [])
        category = data.get("category")
        attribution = data.get("discoveryAttribution", {}).get("firstDocumented", {})
        author = attribution.get("author", "Unknown")
        org = attribution.get("organization", "Unknown")
        tools = list(data.get("detectionTools", {}).keys())
        
        for s in services:
            service_counts[s] += 1
        category_counts[category] += 1
        author_counts[f"{author} ({org})"] += 1
        for t in tools:
            tools_counts[t] += 1
        
        all_paths.append(data)

print(f"Total paths loaded: {len(all_paths)}")
print("\n--- Services Distribution ---")
for s, c in service_counts.most_common(10):
    print(f"  {s}: {c}")

print("\n--- Categories Distribution ---")
for cat, c in category_counts.most_common():
    print(f"  {cat}: {c}")

print("\n--- Top Authors/Orgs ---")
for a, c in author_counts.most_common(10):
    print(f"  {a}: {c}")

print("\n--- Detection Tools Breakdown ---")
for t, c in tools_counts.most_common():
    print(f"  {t}: {c} paths")
