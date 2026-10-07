import glob
import json
import yaml

# Map pathfinding path IDs or primary actions to MITRE techniques & CloudGoat scenarios
MITRE_MAP = {
    "iam:CreatePolicyVersion": ("T1098", "Account Manipulation"),
    "iam:CreateAccessKey": ("T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    "iam:CreateLoginProfile": ("T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    "iam:UpdateLoginProfile": ("T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    "iam:PutRolePolicy": ("T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    "iam:PutUserPolicy": ("T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    "iam:PutGroupPolicy": ("T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    "iam:AttachUserPolicy": ("T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    "iam:AttachRolePolicy": ("T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    "iam:AttachGroupPolicy": ("T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    "iam:UpdateAssumeRolePolicy": ("T1098", "Account Manipulation"),
    "iam:AddUserToGroup": ("T1098.003", "Account Manipulation: Additional Cloud Groups"),
    "iam:PassRole": ("T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Privileges"),
    "sts:AssumeRole": ("T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Privileges"),
    "s3:GetObject": ("T1530", "Data from Cloud Storage Object"),
    "secretsmanager:GetSecretValue": ("T1552.005", "Unsecured Credentials: Cloud Secrets"),
    "ec2:RunInstances": ("T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Privileges"),
    "lambda:CreateFunction": ("T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Privileges"),
    "glue:CreateDevEndpoint": ("T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Privileges"),
    "codebuild:CreateProject": ("T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Privileges"),
    "ecs:RegisterTaskDefinition": ("T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Privileges"),
    "ssm:StartSession": ("T1021.007", "Remote Services: AWS Systems Manager Agent")
}

CLOUDGOAT_MAP = {
    "iam-001": "iam_privesc_by_rollback",
    "iam-002": "iam_privesc_by_key_rotation",
    "iam-003": "iam_privesc_by_key_rotation",
    "iam-005": "iam_privesc_by_attachment",
    "iam-007": "iam_privesc_by_attachment",
    "iam-008": "iam_privesc_by_attachment",
    "iam-009": "iam_privesc_by_attachment",
    "iam-010": "iam_privesc_by_attachment",
    "iam-011": "iam_privesc_by_attachment",
    "iam-013": "iam_privesc_by_attachment",
    "iam-014": "iam_privesc_by_attachment",
    "iam-015": "iam_privesc_by_key_rotation",
    "ec2-001": "iam_privesc_by_ec2",
    "lambda-001": "lambda_privesc",
    "glue-001": "glue_privesc",
    "codebuild-001": "codebuild_secrets",
    "ecs-001": "ecs_takeover",
    "s3-001": "cloud_breach_s3"
}

def determine_resource_type(action: str) -> str:
    act_lower = action.lower()
    if "policy" in act_lower:
        if "user" in act_lower:
            return "iam_user"
        elif "role" in act_lower:
            return "iam_role"
        elif "group" in act_lower:
            return "iam_group"
        return "iam_policy"
    elif "accesskey" in act_lower or "loginprofile" in act_lower or "addusertogroup" in act_lower:
        return "iam_user"
    elif "assumerole" in act_lower or "passrole" in act_lower:
        return "iam_role"
    elif "runinstances" in act_lower:
        return "iam_role"
    elif "lambda" in act_lower:
        return "lambda_function"
    elif "glue" in act_lower:
        return "glue_endpoint"
    elif "codebuild" in act_lower:
        return "codebuild_project"
    elif "ecs" in act_lower:
        return "ecs_task"
    elif "s3" in act_lower:
        return "s3_bucket"
    elif "secret" in act_lower:
        return "secretsmanager_secret"
    return "iam_role"

def determine_relationship(action: str) -> str:
    act_lower = action.lower()
    if "createpolicyversion" in act_lower:
        return "create_policy_version"
    elif "createaccesskey" in act_lower:
        return "create_access_key"
    elif "createloginprofile" in act_lower:
        return "create_login_profile"
    elif "updateloginprofile" in act_lower:
        return "update_login_profile"
    elif "attachuserpolicy" in act_lower or "attachrolepolicy" in act_lower or "attachgrouppolicy" in act_lower:
        return "can_attach_policy"
    elif "putuserpolicy" in act_lower or "putrolepolicy" in act_lower or "putgrouppolicy" in act_lower:
        return "can_put_policy"
    elif "updateassumerolepolicy" in act_lower:
        return "update_assume_role_policy"
    elif "addusertogroup" in act_lower:
        return "add_user_to_group"
    elif "assumerole" in act_lower:
        return "can_assume_role"
    elif "passrole" in act_lower:
        return "can_pass_role"
    elif "runinstances" in act_lower:
        return "pass_role_ec2"
    elif "lambda" in act_lower:
        return "pass_role_lambda"
    elif "glue" in act_lower:
        return "pass_role_glue"
    elif "codebuild" in act_lower:
        return "pass_role_codebuild"
    elif "ecs" in act_lower:
        return "pass_role_ecs"
    elif "getobject" in act_lower:
        return "can_read_storage"
    elif "getsecretvalue" in act_lower:
        return "can_read_secret"
    return "can_access"
