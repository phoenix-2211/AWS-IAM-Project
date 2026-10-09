"""IAM-Only Terraform Sandbox Generator for Single Attack-Path Branches.

Generates minimal HCL (.tf) definitions for IAM users, roles, trust policies,
and inline/attached policies required to provision a disposable test sandbox.
"""

import re
from typing import Any
from pydantic import BaseModel, Field


class BranchHop(BaseModel):
    source: str
    action: str | list[str]
    target: str

    @property
    def actions_list(self) -> list[str]:
        if isinstance(self.action, list):
            return self.action
        if "+" in self.action:
            return [a.strip() for a in self.action.split("+")]
        return [self.action]


class BranchJSON(BaseModel):
    branch_id: str
    hops: list[BranchHop] = Field(default_factory=list)
    goal: str = ""


class TerraformGenerator:
    """Generates IAM-only Terraform configurations for a given attack-path branch."""

    @staticmethod
    def _to_hcl_id(name: str) -> str:
        """Sanitizes a resource/node name to a valid HCL identifier."""
        clean = re.sub(r"[^a-zA-Z0-9_]", "_", name).lower()
        clean = re.sub(r"_+", "_", clean).strip("_")
        return clean or "resource"

    def generate_tf_config(self, branch: BranchJSON) -> dict[str, str]:
        """Emits HCL file contents (main.tf, variables.tf) for the branch's IAM resources."""
        hcl_blocks: list[str] = [
            "# Auto-generated IAM Sandbox Terraform Config",
            f"# Branch ID: {branch.branch_id}",
            f"# Goal: {branch.goal}",
            "",
            'terraform {',
            '  required_providers {',
            '    aws = {',
            '      source  = "hashicorp/aws"',
            '      version = "~> 5.0"',
            '    }',
            '  }',
            '}',
            "",
            'provider "aws" {',
            '  region                      = "us-east-1"',
            '  access_key                  = "mock_access_key"',
            '  secret_key                  = "mock_secret_key"',
            '  skip_credentials_validation = true',
            '  skip_requesting_account_id  = true',
            '  skip_metadata_api_check     = true',
            '}',
            "",
        ]

        created_users: set[str] = set()
        created_roles: set[str] = set()

        for idx, hop in enumerate(branch.hops):
            src_node = hop.source
            tgt_node = hop.target
            actions = hop.actions_list

            src_hcl = self._to_hcl_id(src_node)
            tgt_hcl = self._to_hcl_id(tgt_node)

            # 1. Source Principal Provisioning
            if idx == 0 and "role" not in src_node.lower():
                if src_node not in created_users:
                    created_users.add(src_node)
                    hcl_blocks.extend([
                        f'# Initial User: {src_node}',
                        f'resource "aws_iam_user" "{src_hcl}" {{',
                        f'  name = "{src_node}"',
                        '}',
                        f'resource "aws_iam_access_key" "{src_hcl}_key" {{',
                        f'  user = aws_iam_user.{src_hcl}.name',
                        '}',
                        "",
                    ])

            # 2. Target Role Provisioning & Trust Policy
            if tgt_node not in created_roles and ("role" in tgt_node.lower() or "user" in src_node.lower()):
                created_roles.add(tgt_node)

                # AssumeRole trust policy allowing source principal or AWS service
                if "lambda" in [a.lower() for a in actions]:
                    principal_hcl = '{"Service": "lambda.amazonaws.com"}'
                elif "role" in src_node.lower():
                    principal_hcl = f'{{"AWS": "arn:aws:iam::111122223333:role/{src_node}"}}'
                else:
                    principal_hcl = f'{{"AWS": "arn:aws:iam::111122223333:user/{src_node}"}}'

                trust_policy_json = (
                    '{\n'
                    '  "Version": "2012-10-17",\n'
                    '  "Statement": [{\n'
                    '    "Effect": "Allow",\n'
                    f'    "Principal": {principal_hcl},\n'
                    '    "Action": "sts:AssumeRole"\n'
                    '  }]\n'
                    '}'
                )

                hcl_blocks.extend([
                    f'# Target Role: {tgt_node}',
                    f'resource "aws_iam_role" "{tgt_hcl}" {{',
                    f'  name               = "{tgt_node}"',
                    f'  assume_role_policy = <<EOF\n{trust_policy_json}\nEOF',
                    '}',
                    "",
                ])

            # 3. Hop Policy Provisioning (Permissions granted to source principal)
            actions_json = ", ".join(f'"{a}"' for a in actions)
            policy_json = (
                '{\n'
                '  "Version": "2012-10-17",\n'
                '  "Statement": [{\n'
                '    "Effect": "Allow",\n'
                f'    "Action": [{actions_json}],\n'
                '    "Resource": "*"\n'
                '  }]\n'
                '}'
            )

            policy_name = f"policy_hop_{idx+1}_{src_hcl}_to_{tgt_hcl}"
            if "role" in src_node.lower() or src_node in created_roles:
                hcl_blocks.extend([
                    f'# Policy for Hop {idx+1}: {src_node} -> {tgt_node}',
                    f'resource "aws_iam_role_policy" "{policy_name}" {{',
                    f'  name   = "{policy_name}"',
                    f'  role   = aws_iam_role.{src_hcl}.id',
                    f'  policy = <<EOF\n{policy_json}\nEOF',
                    '}',
                    "",
                ])
            elif src_node in created_users:
                hcl_blocks.extend([
                    f'# Policy for Hop {idx+1}: {src_node} -> {tgt_node}',
                    f'resource "aws_iam_user_policy" "{policy_name}" {{',
                    f'  name   = "{policy_name}"',
                    f'  user   = aws_iam_user.{src_hcl}.name',
                    f'  policy = <<EOF\n{policy_json}\nEOF',
                    '}',
                    "",
                ])

        main_tf_content = "\n".join(hcl_blocks)
        variables_tf_content = (
            'variable "aws_region" {\n'
            '  type    = string\n'
            '  default = "us-east-1"\n'
            '}\n'
        )

        return {
            "main.tf": main_tf_content,
            "variables.tf": variables_tf_content,
        }
