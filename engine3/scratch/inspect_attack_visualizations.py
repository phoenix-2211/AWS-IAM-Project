import glob
import json
import yaml

target_ids = ["iam-001", "iam-002", "iam-008", "ec2-001"]

for pid in target_ids:
    files = glob.glob(f"scratch/pathfinding.cloud/data/paths/aws/**/{pid}.yaml", recursive=True)
    if files:
        with open(files[0], "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            print(f"=== {pid}: {data.get('name')} ===")
            vis = data.get("attackVisualization", {})
            print(json.dumps(vis, indent=2))
            print("\n")
