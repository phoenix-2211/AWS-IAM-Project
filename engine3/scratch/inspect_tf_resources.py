"""Inspects all terraform resource block types across iam-vulnerable modules."""

import re
from pathlib import Path

TF_DIR = Path("scratch/iam-vulnerable/modules/free-resources")

def main():
    all_files = list(TF_DIR.glob("**/*.tf"))
    resource_counts = {}

    for f in all_files:
        content = f.read_text(encoding="utf-8")
        matches = re.findall(r'resource\s+"([^"]+)"\s+"([^"]+)"', content)
        for r_type, r_name in matches:
            resource_counts[r_type] = resource_counts.get(r_type, 0) + 1

    print("All Terraform Resource Types in IAM-Vulnerable:")
    for r_type, count in sorted(resource_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {r_type}: {count}")

if __name__ == "__main__":
    main()
