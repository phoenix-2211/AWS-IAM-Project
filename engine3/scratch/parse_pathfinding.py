import glob
import json
import yaml

yaml_files = glob.glob("scratch/pathfinding.cloud/data/paths/aws/**/*.yaml", recursive=True)
print(f"Total YAML files found: {len(yaml_files)}")

paths = []
for fpath in sorted(yaml_files):
    with open(fpath, "r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
            if data and "id" in data:
                paths.append((fpath, data))
        except Exception as e:
            print(f"Error reading {fpath}: {e}")

print(f"Successfully loaded {len(paths)} path definitions.")

iam_paths = [p for p in paths if p[1].get("id", "").startswith("iam-")]
print(f"IAM paths count (iam-###): {len(iam_paths)}")

with_detection_tools = [p for p in paths if p[1].get("detectionTools")]
print(f"Paths with detectionTools: {len(with_detection_tools)}")

iam_with_detection = [p for p in iam_paths if p[1].get("detectionTools")]
print(f"IAM paths with detectionTools: {len(iam_with_detection)}")

# Check CloudGoat mappings
cg_scenarios = [
    "vulnerable_lambda", "vulnerable_cognito", "iam_privesc_by_key_rotation",
    "iam_privesc_by_rollback", "lambda_privesc", "cloud_breach_s3",
    "iam_privesc_by_attachment", "ec2_ssrf", "ecs_takeover", "rce_web_app",
    "codebuild_secrets", "cicd", "glue_privesc", "iam_privesc_by_ec2"
]

print("\n--- IAM Paths Breakdown ---")
for fpath, p in iam_paths:
    pid = p.get("id")
    name = p.get("name")
    cat = p.get("category")
    tools = list(p.get("detectionTools", {}).keys()) if p.get("detectionTools") else []
    print(f"ID: {pid:<10} Name: {name:<35} Category: {cat:<20} Tools: {tools}")
