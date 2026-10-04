# Research Sources & Findings (`SOURCES.md`)

**Date Accessed:** 2026-10-04  
**Primary Sources:**
1. **Datadog Pathfinding.cloud Catalog**:
   - URL: `https://github.com/DataDog/pathfinding.cloud` (cloned locally under `engine3/vendor/pathfinding.cloud/`)
   - Asset extracted: IAM privilege escalation path YAML definitions and schema rules.
2. **AWS IAM Documentation & Boto3 Reference**:
   - URL: `https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html`
   - URL: `https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html`
   - Asset extracted: `simulate_principal_policy` API semantics, parameters (`PolicySourceArn`, `ActionNames`, `ResourceArns`, `ContextEntries`), decision enums (`allowed`, `explicitDeny`, `implicitDeny`), and limitations (SCP/Resource policy evaluation limitations).
3. **CloudGoat Scenarios**:
   - URL: `https://github.com/RhinoSecurityLabs/cloudgoat` (cloned locally under `D:\Project IAM\cloudgoat`)
   - Asset extracted: Executable CLI invocation (`python -m cloudgoat.cloudgoat`), verified scenario list (`iam_privesc_by_attachment`, `iam_privesc_by_key_rotation`, `iam_privesc_by_rollback`, `iam_privesc_by_ec2`, `lambda_privesc`).
4. **MITRE ATT&CK for Cloud**:
   - URL: `https://attack.mitre.org/matrices/enterprise/cloud/`
   - Asset extracted: Technique T1078.004 (Valid Accounts: Cloud Accounts), T1098 (Account Manipulation), T1098.001 (Additional Cloud Credentials), T1098.003 (Additional Cloud Roles).

---

## 2. Research Verification Summary

### Rulebook Seed List & MITRE Mapping
- **`iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion`**: Self-escalation via policy version manipulation. MITRE: `T1098`
- **`iam:AttachUserPolicy` / `iam:AttachRolePolicy`**: Direct attachment of permissive managed policy. MITRE: `T1098.003`
- **`iam:PutUserPolicy` / `iam:PutRolePolicy`**: Inline policy creation with elevated privileges. MITRE: `T1098`
- **`iam:CreateAccessKey`**: Creation of secondary credentials for target user. MITRE: `T1098.001`
- **`iam:PassRole` + `ec2:RunInstances`**: EC2 instance launch with instance profile role. MITRE: `T1078.004`
- **`iam:PassRole` + `lambda:CreateFunction`**: Lambda execution with attached execution role. MITRE: `T1098`
- **`iam:UpdateAssumeRolePolicy` + `sts:AssumeRole`**: Trust policy manipulation to allow self-assumption. MITRE: `T1098.003`

### Policy Simulator Semantics
- Evaluates identity-based policies.
- **Does NOT** evaluate trust policies structurally or cross-account trust automatically.
- Requires `ContextEntries` for unevaluated condition keys.
- Results are simulation decisions, not confirmed exploit execution.

### CloudGoat Scenario Mapping (`scenario_map.md`)
- `iam_privesc_by_attachment` -> `RULE-IAM-001` (`iam:AttachUserPolicy`)
- `iam_privesc_by_key_rotation` -> `RULE-IAM-004` (`iam:CreateAccessKey`)
- `iam_privesc_by_rollback` -> `RULE-IAM-002` (`iam:SetDefaultPolicyVersion`)
- `iam_privesc_by_ec2` -> `RULE-IAM-005` (`iam:PassRole` + `ec2:RunInstances`)
