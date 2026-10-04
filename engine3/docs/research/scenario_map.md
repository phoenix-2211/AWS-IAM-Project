# Scenario Map (`scenario_map.md`)

This file maps CloudGoat scenarios to verified SecurityRules.

| CloudGoat Scenario Name | Primary Action / Technique | Target Rule ID | Resource / Deployment Cost |
|---|---|---|---|
| `iam_privesc_by_attachment` | `iam:AttachUserPolicy` | `RULE-IAM-001` | IAM Only ($0) |
| `iam_privesc_by_rollback` | `iam:SetDefaultPolicyVersion` | `RULE-IAM-002` | IAM Only ($0) |
| `iam_privesc_by_key_rotation` | `iam:CreateAccessKey` | `RULE-IAM-004` | IAM Only ($0) |
| `iam_privesc_by_ec2` | `iam:PassRole` + `ec2:RunInstances` | `RULE-IAM-005` | Billable (EC2) - Needs explicit budget confirmation |
| `lambda_privesc` | `iam:PassRole` + `lambda:CreateFunction` | `RULE-IAM-006` | Lambda ($0 tier) |
