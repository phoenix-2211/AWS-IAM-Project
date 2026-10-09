"""Parser and converter for BishopFox/iam-vulnerable Terraform files into IAMGraph v0.1 format."""

import json
import re
from pathlib import Path
from typing import Any

TF_DIR = Path("scratch/iam-vulnerable/modules/free-resources")


def parse_tf_file(file_path: Path) -> dict[str, Any]:
    content = file_path.read_text(encoding="utf-8")

    # Extract policies, roles, users, attachments
    policies = []
    for match in re.finditer(r'resource\s+"aws_iam_policy"\s+"([^"]+)"\s*\{(.*?)\n\}', content, re.DOTALL):
        p_name = match.group(1)
        p_body = match.group(2)
        # Extract jsonencode block if present
        json_match = re.search(r'policy\s*=\s*jsonencode\(\{(.*?)\}\)', p_body, re.DOTALL)
        policies.append({"name": p_name, "raw_body": p_body, "json_str": json_match.group(1) if json_match else ""})

    roles = []
    for match in re.finditer(r'resource\s+"aws_iam_role"\s+"([^"]+)"\s*\{(.*?)\n\}', content, re.DOTALL):
        r_name = match.group(1)
        r_body = match.group(2)
        roles.append({"name": r_name, "raw_body": r_body})

    users = []
    for match in re.finditer(r'resource\s+"aws_iam_user"\s+"([^"]+)"\s*\{(.*?)\n\}', content, re.DOTALL):
        u_name = match.group(1)
        u_body = match.group(2)
        users.append({"name": u_name, "raw_body": u_body})

    user_attachments = []
    for match in re.finditer(r'resource\s+"aws_iam_user_policy_attachment"\s+"([^"]+)"\s*\{(.*?)\n\}', content, re.DOTALL):
        a_name = match.group(1)
        a_body = match.group(2)
        user_match = re.search(r'user\s*=\s*aws_iam_user\.([^.]+)\.name', a_body)
        policy_match = re.search(r'policy_arn\s*=\s*aws_iam_policy\.([^.]+)\.arn', a_body)
        if user_match and policy_match:
            user_attachments.append({"user": user_match.group(1), "policy": policy_match.group(1)})

    role_attachments = []
    for match in re.finditer(r'resource\s+"aws_iam_role_policy_attachment"\s+"([^"]+)"\s*\{(.*?)\n\}', content, re.DOTALL):
        a_name = match.group(1)
        a_body = match.group(2)
        role_match = re.search(r'role\s*=\s*aws_iam_role\.([^.]+)\.name', a_body)
        policy_match = re.search(r'policy_arn\s*=\s*aws_iam_policy\.([^.]+)\.arn', a_body)
        if role_match and policy_match:
            role_attachments.append({"role": role_match.group(1), "policy": policy_match.group(1)})

    return {
        "file": file_path.name,
        "policies": policies,
        "roles": roles,
        "users": users,
        "user_attachments": user_attachments,
        "role_attachments": role_attachments,
    }


def main():
    privesc_dir = TF_DIR / "privesc-paths"
    tool_dir = TF_DIR / "tool-testing"

    all_files = list(privesc_dir.glob("*.tf")) + list(tool_dir.glob("*.tf"))
    print(f"Total .tf files found: {len(all_files)}")

    parsed_data = [parse_tf_file(f) for f in all_files if f.name != "variables.tf"]
    print(f"Parsed {len(parsed_data)} valid Terraform policy files.")
    print("Sample parsed file:", parsed_data[0]["file"], "Users:", len(parsed_data[0]["users"]), "Policies:", len(parsed_data[0]["policies"]))


if __name__ == "__main__":
    main()
