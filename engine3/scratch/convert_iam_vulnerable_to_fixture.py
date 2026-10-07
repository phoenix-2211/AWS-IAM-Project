"""Converts BishopFox/iam-vulnerable Terraform files into IAMGraph v0.1 tree_7_industry_scale.json."""

import json
import re
from pathlib import Path
from typing import Any

ACCOUNT_ID = "111122223333"
PINNED_COMMIT = "0f298666f9b7cfa01488b86912afdb211773188a"
BASE_DIR = Path(__file__).parent.parent
TF_DIR = BASE_DIR / "scratch" / "iam-vulnerable" / "modules" / "free-resources"
FIXTURE_PATH = BASE_DIR / "docs" / "contracts" / "fixtures" / "tree_7_industry_scale.json"


def extract_actions_and_resources(body_text: str) -> list[dict[str, Any]]:
    """Extract policy statements (Action, Effect, Resource) from terraform jsonencode text."""
    statements = []
    # Find all statement blocks inside jsonencode
    stmt_matches = re.findall(r'\{\s*(?:Action|Effect|Resource|Sid|Principal).*?\}', body_text, re.DOTALL)
    for stmt_str in stmt_matches:
        effect_match = re.search(r'Effect\s*=\s*"([^"]+)"', stmt_str)
        effect = effect_match.group(1) if effect_match else "Allow"

        # Action can be "Action" = "..." or Action = ["...", "..."]
        actions = []
        act_single = re.search(r'Action\s*=\s*"([^"]+)"', stmt_str)
        if act_single:
            actions = [act_single.group(1)]
        else:
            act_list = re.search(r'Action\s*=\s*\[(.*?)\]', stmt_str, re.DOTALL)
            if act_list:
                actions = re.findall(r'"([^"]+)"', act_list.group(1))

        # Resource can be "Resource" = "..." or Resource = ["...", "..."]
        resources = []
        res_single = re.search(r'Resource\s*=\s*"([^"]+)"', stmt_str)
        if res_single:
            resources = [res_single.group(1)]
        else:
            res_list = re.search(r'Resource\s*=\s*\[(.*?)\]', stmt_str, re.DOTALL)
            if res_list:
                resources = re.findall(r'"([^"]+)"', res_list.group(1))
        if not resources:
            resources = ["*"]

        if actions:
            statements.append({
                "Effect": effect,
                "Action": actions,
                "Resource": resources
            })

    return statements


def parse_tf_module(file_path: Path) -> dict[str, Any]:
    content = file_path.read_text(encoding="utf-8")
    rel_path = file_path.relative_to(BASE_DIR / "scratch" / "iam-vulnerable").as_posix()
    filename = file_path.name

    # Path classification
    if filename.startswith("privesc"):
        path_id = filename.replace(".tf", "")
    elif filename.startswith("fn") or filename.startswith("fp"):
        path_id = filename.replace(".tf", "")
    else:
        path_id = filename.replace(".tf", "")

    # Users
    users = re.findall(r'resource\s+"aws_iam_user"\s+"([^"]+)"', content)

    # Roles
    roles = re.findall(r'resource\s+"aws_iam_role"\s+"([^"]+)"', content)

    # Policies
    policies = []
    for match in re.finditer(r'resource\s+"aws_iam_policy"\s+"([^"]+)"\s*\{(.*?)\n\}', content, re.DOTALL):
        p_name = match.group(1)
        p_body = match.group(2)
        stmts = extract_actions_and_resources(p_body)
        policies.append({"name": p_name, "statements": stmts})

    # Attachments
    user_attachments = []
    for match in re.finditer(r'resource\s+"aws_iam_user_policy_attachment"\s+"([^"]+)"\s*\{(.*?)\n\}', content, re.DOTALL):
        a_body = match.group(2)
        u_m = re.search(r'user\s*=\s*aws_iam_user\.([^.]+)\.name', a_body)
        p_m = re.search(r'policy_arn\s*=\s*aws_iam_policy\.([^.]+)\.arn', a_body)
        if u_m and p_m:
            user_attachments.append({"user": u_m.group(1), "policy": p_m.group(1)})

    role_attachments = []
    for match in re.finditer(r'resource\s+"aws_iam_role_policy_attachment"\s+"([^"]+)"\s*\{(.*?)\n\}', content, re.DOTALL):
        a_body = match.group(2)
        r_m = re.search(r'role\s*=\s*aws_iam_role\.([^.]+)\.name', a_body)
        p_m = re.search(r'policy_arn\s*=\s*aws_iam_policy\.([^.]+)\.arn', a_body)
        if r_m and p_m:
            role_attachments.append({"role": r_m.group(1), "policy": p_m.group(1)})

    return {
        "file": filename,
        "rel_path": rel_path,
        "path_id": path_id,
        "users": users,
        "roles": roles,
        "policies": policies,
        "user_attachments": user_attachments,
        "role_attachments": role_attachments,
    }


def determine_target_node_id(actions: list[str]) -> str:
    act_str = " ".join(actions).lower()
    if any(a in act_str for a in ["passrole", "assumerole", "attachrolepolicy", "putrolepolicy", "updateassumerolepolicy"]):
        return f"arn:aws:iam::{ACCOUNT_ID}:role/HighPrivilegeAdminRoleResource"
    if any(a in act_str for a in ["createpolicyversion", "setdefaultpolicyversion"]):
        return f"arn:aws:iam::{ACCOUNT_ID}:policy/TargetAdminPolicy"
    if any(a in act_str for a in ["attachuserpolicy", "putuserpolicy", "createaccesskey", "createloginprofile", "updateloginprofile", "addusertogroup"]):
        return f"arn:aws:iam::{ACCOUNT_ID}:user/TargetAdminUserResource"
    if any(a in act_str for a in ["attachgrouppolicy", "putgrouppolicy"]):
        return f"arn:aws:iam::{ACCOUNT_ID}:group/TargetAdminGroup"
    if any(a in act_str for a in ["lambda:createfunction", "lambda:updatefunctioncode", "lambda:invokefunction", "lambda:createeventsourcemapping"]):
        return f"arn:aws:lambda:us-east-1:{ACCOUNT_ID}:function:TargetLambdaFunction"
    if any(a in act_str for a in ["glue:createdevendpoint", "glue:updatedevendpoint"]):
        return f"arn:aws:glue:us-east-1:{ACCOUNT_ID}:devendpoint/TargetGlueEndpoint"
    if any(a in act_str for a in ["cloudformation:createstack", "cloudformation:updatestack"]):
        return f"arn:aws:cloudformation:us-east-1:{ACCOUNT_ID}:stack/TargetCFStack/111"
    if any(a in act_str for a in ["datapipeline:createpipeline", "datapipeline:activatepipeline"]):
        return f"arn:aws:datapipeline:us-east-1:{ACCOUNT_ID}:pipeline/df-12345"
    if "s3:" in act_str:
        return f"arn:aws:s3:::iam-vulnerable-production-bucket"
    if "secretsmanager:" in act_str:
        return f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:secret:prod/flag"
    return f"arn:aws:iam::{ACCOUNT_ID}:role/HighPrivilegeAdminRoleResource"


def build_industry_scale_fixture() -> dict[str, Any]:
    privesc_dir = TF_DIR / "privesc-paths"
    tool_dir = TF_DIR / "tool-testing"

    all_files = sorted(list(privesc_dir.glob("*.tf")) + list(tool_dir.glob("*.tf")))
    parsed_modules = [parse_tf_module(f) for f in all_files if f.name != "variables.tf"]

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    edge_counter = 1

    # Map policy lookup: (module_path_id, policy_name) -> list of statements
    module_policies: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for m in parsed_modules:
        for p in m["policies"]:
            module_policies[(m["path_id"], p["name"])] = p["statements"]

    # Target Resources (Standard AWS target resources covering all IAM Vulnerable paths)
    target_resources = [
        {
            "id": f"arn:aws:s3:::iam-vulnerable-production-bucket",
            "type": "Resource",
            "resource_type": "s3_bucket",
            "arn": f"arn:aws:s3:::iam-vulnerable-production-bucket",
            "name": "iam-vulnerable-production-bucket",
            "metadata": {"sensitivity": "high"},
            "x_provenance": {"source": "BishopFox/iam-vulnerable", "description": "Target bucket for storage exfiltration paths"}
        },
        {
            "id": f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:secret:prod/flag",
            "type": "Resource",
            "resource_type": "secretsmanager_secret",
            "arn": f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:secret:prod/flag",
            "name": "prod/flag",
            "metadata": {"sensitivity": "critical"},
            "x_provenance": {"source": "BishopFox/iam-vulnerable", "description": "Target secret for credential access paths"}
        },
        {
            "id": f"arn:aws:iam::{ACCOUNT_ID}:role/HighPrivilegeAdminRole",
            "type": "Role",
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/HighPrivilegeAdminRole",
            "name": "HighPrivilegeAdminRole",
            "permissions_boundary": None,
            "is_admin": True,
            "trust_policy": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]
            },
            "x_provenance": {"source": "BishopFox/iam-vulnerable", "description": "Target high privilege role for passrole / assume role escalation"}
        },
        {
            "id": f"arn:aws:iam::{ACCOUNT_ID}:policy/TargetAdminPolicy",
            "type": "Resource",
            "resource_type": "iam_policy",
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:policy/TargetAdminPolicy",
            "name": "TargetAdminPolicy",
            "x_provenance": {"source": "BishopFox/iam-vulnerable", "description": "Target policy for policy version privesc"}
        },
        {
            "id": f"arn:aws:iam::{ACCOUNT_ID}:user/TargetAdminUserResource",
            "type": "Resource",
            "resource_type": "iam_user",
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/TargetAdminUser",
            "name": "TargetAdminUser",
            "x_provenance": {"source": "BishopFox/iam-vulnerable", "description": "Target user for user policy / login profile privesc"}
        },
        {
            "id": f"arn:aws:iam::{ACCOUNT_ID}:role/HighPrivilegeAdminRoleResource",
            "type": "Resource",
            "resource_type": "iam_role",
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/HighPrivilegeAdminRole",
            "name": "HighPrivilegeAdminRoleResource",
            "x_provenance": {"source": "BishopFox/iam-vulnerable", "description": "Target role for passrole / assume role privesc"}
        },
        {
            "id": f"arn:aws:iam::{ACCOUNT_ID}:group/TargetAdminGroup",
            "type": "Resource",
            "resource_type": "iam_group",
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:group/TargetAdminGroup",
            "name": "TargetAdminGroup",
            "x_provenance": {"source": "BishopFox/iam-vulnerable", "description": "Target group for group policy / membership privesc"}
        },
        {
            "id": f"arn:aws:lambda:us-east-1:{ACCOUNT_ID}:function:TargetLambdaFunction",
            "type": "Resource",
            "resource_type": "lambda_function",
            "arn": f"arn:aws:lambda:us-east-1:{ACCOUNT_ID}:function:TargetLambdaFunction",
            "name": "TargetLambdaFunction",
            "x_provenance": {"source": "BishopFox/iam-vulnerable", "description": "Target lambda function for lambda privesc"}
        },
        {
            "id": f"arn:aws:glue:us-east-1:{ACCOUNT_ID}:devendpoint/TargetGlueEndpoint",
            "type": "Resource",
            "resource_type": "glue_endpoint",
            "arn": f"arn:aws:glue:us-east-1:{ACCOUNT_ID}:devendpoint/TargetGlueEndpoint",
            "name": "TargetGlueEndpoint",
            "x_provenance": {"source": "BishopFox/iam-vulnerable", "description": "Target glue endpoint for glue privesc"}
        },
        {
            "id": f"arn:aws:cloudformation:us-east-1:{ACCOUNT_ID}:stack/TargetCFStack/111",
            "type": "Resource",
            "resource_type": "cloudformation_stack",
            "arn": f"arn:aws:cloudformation:us-east-1:{ACCOUNT_ID}:stack/TargetCFStack/111",
            "name": "TargetCFStack",
            "x_provenance": {"source": "BishopFox/iam-vulnerable", "description": "Target cloudformation stack for CF privesc"}
        },
        {
            "id": f"arn:aws:datapipeline:us-east-1:{ACCOUNT_ID}:pipeline/df-12345",
            "type": "Resource",
            "resource_type": "datapipeline",
            "arn": f"arn:aws:datapipeline:us-east-1:{ACCOUNT_ID}:pipeline/df-12345",
            "name": "df-12345",
            "x_provenance": {"source": "BishopFox/iam-vulnerable", "description": "Target datapipeline for datapipeline privesc"}
        }
    ]

    for tr in target_resources:
        nodes.append(tr)

    # Benign negative control principal & resource
    nodes.append({
        "id": f"arn:aws:iam::{ACCOUNT_ID}:user/benign-auditor-user",
        "type": "User",
        "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/benign-auditor-user",
        "name": "benign-auditor-user",
        "is_admin": False,
        "mfa_enabled": True,
        "is_dormant": False,
        "x_provenance": {"source": "negative_control", "description": "Safe read-only auditor user"}
    })
    nodes.append({
        "id": f"arn:aws:s3:::benign-public-logs",
        "type": "Resource",
        "resource_type": "s3_bucket",
        "arn": "arn:aws:s3:::benign-public-logs",
        "name": "benign-public-logs",
        "metadata": {"sensitivity": "low"},
        "x_provenance": {"source": "negative_control", "description": "Safe public log bucket"}
    })
    nodes.append({
        "id": "perm:benign-auditor:read-logs",
        "type": "Permission",
        "effect": "Allow",
        "actions": ["s3:ListBucket"],
        "resources": ["arn:aws:s3:::benign-public-logs"],
        "provenance": {"policy_name": "benign-auditor-policy"},
        "x_provenance": {"source": "negative_control"}
    })
    edges.append({"id": f"e-{edge_counter:04d}", "type": "HAS_PERMISSION", "source": f"arn:aws:iam::{ACCOUNT_ID}:user/benign-auditor-user", "target": "perm:benign-auditor:read-logs"})
    edge_counter += 1
    edges.append({"id": f"e-{edge_counter:04d}", "type": "APPLIES_TO", "source": "perm:benign-auditor:read-logs", "target": "arn:aws:s3:::benign-public-logs"})
    edge_counter += 1

    # Process all parsed Terraform modules
    for m in parsed_modules:
        path_id = m["path_id"]

        # Users
        for u in m["users"]:
            user_arn = f"arn:aws:iam::{ACCOUNT_ID}:user/{u}"
            nodes.append({
                "id": user_arn,
                "type": "User",
                "arn": user_arn,
                "name": u,
                "is_admin": False,
                "mfa_enabled": False,
                "is_dormant": False,
                "x_provenance": {
                    "source_repo": "github.com/BishopFox/iam-vulnerable",
                    "pinned_commit": PINNED_COMMIT,
                    "rel_path": m["rel_path"],
                    "path_name": path_id
                }
            })

        # Roles
        for r in m["roles"]:
            role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/{r}"
            nodes.append({
                "id": role_arn,
                "type": "Role",
                "arn": role_arn,
                "name": r,
                "is_admin": False,
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"}, "Action": "sts:AssumeRole"}]
                },
                "x_provenance": {
                    "source_repo": "github.com/BishopFox/iam-vulnerable",
                    "pinned_commit": PINNED_COMMIT,
                    "rel_path": m["rel_path"],
                    "path_name": path_id
                }
            })
            # Add TRUSTED_BY edge from root or user to role
            edges.append({
                "id": f"e-{edge_counter:04d}",
                "type": "TRUSTED_BY",
                "source": f"arn:aws:iam::{ACCOUNT_ID}:user/benign-auditor-user",
                "target": role_arn,
                "has_condition": False,
                "x_provenance": {"path_name": path_id}
            })
            edge_counter += 1

        # User Policy Attachments
        for att in m["user_attachments"]:
            user_arn = f"arn:aws:iam::{ACCOUNT_ID}:user/{att['user']}"
            stmts = module_policies.get((path_id, att["policy"]), [])
            for idx, stmt in enumerate(stmts):
                perm_id = f"perm:{att['user']}:{att['policy']}:{idx}"
                actions = stmt.get("Action", [])
                effect = stmt.get("Effect", "Allow")
                resources_raw = stmt.get("Resource", ["*"])

                nodes.append({
                    "id": perm_id,
                    "type": "Permission",
                    "effect": effect,
                    "actions": actions,
                    "resources": resources_raw,
                    "raw_statement": stmt,
                    "provenance": {"policy_name": att["policy"]},
                    "x_provenance": {
                        "source_repo": "github.com/BishopFox/iam-vulnerable",
                        "rel_path": m["rel_path"],
                        "path_name": path_id
                    }
                })

                # Edge: HAS_PERMISSION
                edges.append({
                    "id": f"e-{edge_counter:04d}",
                    "type": "HAS_PERMISSION",
                    "source": user_arn,
                    "target": perm_id,
                    "x_provenance": {"path_name": path_id}
                })
                edge_counter += 1

                target_node_id = determine_target_node_id(actions)

                edges.append({
                    "id": f"e-{edge_counter:04d}",
                    "type": "APPLIES_TO",
                    "source": perm_id,
                    "target": target_node_id,
                    "x_provenance": {"path_name": path_id}
                })
                edge_counter += 1

        # Role Policy Attachments
        for att in m["role_attachments"]:
            role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/{att['role']}"
            stmts = module_policies.get((path_id, att["policy"]), [])
            for idx, stmt in enumerate(stmts):
                perm_id = f"perm:{att['role']}:{att['policy']}:{idx}"
                actions = stmt.get("Action", [])
                effect = stmt.get("Effect", "Allow")
                resources_raw = stmt.get("Resource", ["*"])

                nodes.append({
                    "id": perm_id,
                    "type": "Permission",
                    "effect": effect,
                    "actions": actions,
                    "resources": resources_raw,
                    "raw_statement": stmt,
                    "provenance": {"policy_name": att["policy"]},
                    "x_provenance": {
                        "source_repo": "github.com/BishopFox/iam-vulnerable",
                        "rel_path": m["rel_path"],
                        "path_name": path_id
                    }
                })

                # Edge: HAS_PERMISSION
                edges.append({
                    "id": f"e-{edge_counter:04d}",
                    "type": "HAS_PERMISSION",
                    "source": role_arn,
                    "target": perm_id,
                    "x_provenance": {"path_name": path_id}
                })
                edge_counter += 1

                target_node_id = f"arn:aws:iam::{ACCOUNT_ID}:role/HighPrivilegeAdminRole"
                act_str = " ".join(actions).lower()
                if "s3:" in act_str:
                    target_node_id = f"arn:aws:s3:::iam-vulnerable-production-bucket"
                elif "secretsmanager:" in act_str:
                    target_node_id = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:secret:prod/flag"

                edges.append({
                    "id": f"e-{edge_counter:04d}",
                    "type": "APPLIES_TO",
                    "source": perm_id,
                    "target": target_node_id,
                    "x_provenance": {"path_name": path_id}
                })
                edge_counter += 1

    fixture = {
        "contract_name": "IAMGraph",
        "contract_version": "0.1",
        "x_provenance": {
            "authored_by": "ENGINE3-IAM-VULNERABLE-CONVERTER",
            "source_repository": "https://github.com/BishopFox/iam-vulnerable",
            "pinned_commit": PINNED_COMMIT,
            "benchmark_description": "Industry-Scale AWS IAM Privilege Escalation Benchmark (Bishop Fox IAM Vulnerable)",
            "total_modules_parsed": len(parsed_modules),
        },
        "snapshot": {
            "snapshot_id": "TREE-7-INDUSTRY-SCALE-001",
            "account_id": ACCOUNT_ID,
            "collected_at": "2026-10-07T00:00:00Z",
            "origin": "synthetic_fixture",
            "collection_status": "complete",
            "collected_resource_types": [
                "s3_bucket",
                "secretsmanager_secret",
                "iam_role",
                "iam_user"
            ],
            "coverage": [
                {
                    "component": "iam",
                    "region": "global",
                    "status": "complete"
                }
            ]
        },
        "nodes": nodes,
        "edges": edges,
        "warnings": []
    }

    return fixture


def main():
    fixture = build_industry_scale_fixture()
    with open(FIXTURE_PATH, "w", encoding="utf-8") as f:
        json.dump(fixture, f, indent=2)

    users_count = len([n for n in fixture["nodes"] if n["type"] == "User"])
    roles_count = len([n for n in fixture["nodes"] if n["type"] == "Role"])
    perms_count = len([n for n in fixture["nodes"] if n["type"] == "Permission"])
    res_count = len([n for n in fixture["nodes"] if n["type"] == "Resource"])

    print(f"Successfully generated IAMGraph v0.1 industry-scale fixture at: {FIXTURE_PATH}")
    print(f"Total Nodes: {len(fixture['nodes'])} (Users: {users_count}, Roles: {roles_count}, Permissions: {perms_count}, Resources: {res_count})")
    print(f"Total Edges: {len(fixture['edges'])}")


if __name__ == "__main__":
    main()
