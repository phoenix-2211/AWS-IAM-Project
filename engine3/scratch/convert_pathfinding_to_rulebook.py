import glob
import json
import yaml

from convert_helpers import MITRE_MAP, CLOUDGOAT_MAP, determine_resource_type, determine_relationship

yaml_files = sorted(glob.glob("scratch/pathfinding.cloud/data/paths/aws/**/*.yaml", recursive=True))

paths_by_id = {}
for fpath in yaml_files:
    with open(fpath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        if data and "id" in data:
            paths_by_id[data["id"]] = data

# Include supplementary data access rules to complete S3 / SecretsManager exfiltration sink matching
extra_data_rules = [
    {
        "rule_id": "RULE-IAM-S3-001",
        "title": "Data Exfiltration via s3:GetObject",
        "description": "Principal can read sensitive objects from S3 storage buckets.",
        "principal_type": "role",
        "action": "s3:GetObject",
        "resource_type": "s3_bucket",
        "relationship": "can_read_storage",
        "severity": "CRITICAL",
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage Object",
        "required_actions": ["s3:GetObject"],
        "evidence_citation": "MITRE ATT&CK T1530 & CloudGoat cloud_breach_s3",
        "condition": None,
        "source": {
            "name": "pathfinding.cloud (DataDog) / Rhino Security Labs",
            "url": "https://pathfinding.cloud",
            "organization": "DataDog / Rhino Security Labs",
            "date": "2019",
            "tier": "CANONICAL_RESEARCH"
        },
        "evidence": {
            "text": "Role principal holds s3:GetObject on target S3 bucket.",
            "detection_tools": ["cloudsplaining", "prowler"]
        },
        "mitre": {
            "technique_id": "T1530",
            "technique_name": "Data from Cloud Storage Object"
        },
        "version": "0.1",
        "status": "ACTIVE",
        "rulebook_origin": "active",
        "extras": {
            "source_path_id": "s3-001",
            "category": "credential-access",
            "detection_tools": {"prowler": "", "cloudsplaining": ""},
            "cloudgoat_scenario": "cloud_breach_s3"
        }
    },
    {
        "rule_id": "RULE-IAM-S3-002",
        "title": "Data Exfiltration via s3:GetObject (User)",
        "description": "User principal can read sensitive objects from S3 storage buckets.",
        "principal_type": "user",
        "action": "s3:GetObject",
        "resource_type": "s3_bucket",
        "relationship": "can_read_storage",
        "severity": "CRITICAL",
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage Object",
        "required_actions": ["s3:GetObject"],
        "evidence_citation": "MITRE ATT&CK T1530 & CloudGoat cloud_breach_s3",
        "condition": None,
        "source": {
            "name": "pathfinding.cloud (DataDog) / Rhino Security Labs",
            "url": "https://pathfinding.cloud",
            "organization": "DataDog / Rhino Security Labs",
            "date": "2019",
            "tier": "CANONICAL_RESEARCH"
        },
        "evidence": {
            "text": "User principal holds s3:GetObject on target S3 bucket.",
            "detection_tools": ["cloudsplaining", "prowler"]
        },
        "mitre": {
            "technique_id": "T1530",
            "technique_name": "Data from Cloud Storage Object"
        },
        "version": "0.1",
        "status": "ACTIVE",
        "rulebook_origin": "active",
        "extras": {
            "source_path_id": "s3-001",
            "category": "credential-access",
            "detection_tools": {"prowler": "", "cloudsplaining": ""},
            "cloudgoat_scenario": "cloud_breach_s3"
        }
    },
    {
        "rule_id": "RULE-IAM-SEC-001",
        "title": "Credential Access via secretsmanager:GetSecretValue",
        "description": "Role principal can retrieve plaintext secret values from AWS Secrets Manager.",
        "principal_type": "role",
        "action": "secretsmanager:GetSecretValue",
        "resource_type": "secretsmanager_secret",
        "relationship": "can_read_secret",
        "severity": "CRITICAL",
        "technique_id": "T1552.005",
        "technique_name": "Unsecured Credentials: Cloud Secrets",
        "required_actions": ["secretsmanager:GetSecretValue"],
        "evidence_citation": "MITRE ATT&CK T1552.005 & DataDog pathfinding.cloud",
        "condition": None,
        "source": {
            "name": "pathfinding.cloud (DataDog) / Community",
            "url": "https://pathfinding.cloud",
            "organization": "DataDog",
            "date": "2021",
            "tier": "CANONICAL_RESEARCH"
        },
        "evidence": {
            "text": "Role principal holds secretsmanager:GetSecretValue on production secret.",
            "detection_tools": ["cloudsplaining", "prowler"]
        },
        "mitre": {
            "technique_id": "T1552.005",
            "technique_name": "Unsecured Credentials: Cloud Secrets"
        },
        "version": "0.1",
        "status": "ACTIVE",
        "rulebook_origin": "active",
        "extras": {
            "source_path_id": "secretsmanager-001",
            "category": "credential-access",
            "detection_tools": {"prowler": "", "cloudsplaining": ""},
            "cloudgoat_scenario": None
        }
    },
    {
        "rule_id": "RULE-IAM-SEC-002",
        "title": "Credential Access via secretsmanager:GetSecretValue (User)",
        "description": "User principal can retrieve plaintext secret values from AWS Secrets Manager.",
        "principal_type": "user",
        "action": "secretsmanager:GetSecretValue",
        "resource_type": "secretsmanager_secret",
        "relationship": "can_read_secret",
        "severity": "CRITICAL",
        "technique_id": "T1552.005",
        "technique_name": "Unsecured Credentials: Cloud Secrets",
        "required_actions": ["secretsmanager:GetSecretValue"],
        "evidence_citation": "MITRE ATT&CK T1552.005 & DataDog pathfinding.cloud",
        "condition": None,
        "source": {
            "name": "pathfinding.cloud (DataDog) / Community",
            "url": "https://pathfinding.cloud",
            "organization": "DataDog",
            "date": "2021",
            "tier": "CANONICAL_RESEARCH"
        },
        "evidence": {
            "text": "User principal holds secretsmanager:GetSecretValue on production secret.",
            "detection_tools": ["cloudsplaining", "prowler"]
        },
        "mitre": {
            "technique_id": "T1552.005",
            "technique_name": "Unsecured Credentials: Cloud Secrets"
        },
        "version": "0.1",
        "status": "ACTIVE",
        "rulebook_origin": "active",
        "extras": {
            "source_path_id": "secretsmanager-001",
            "category": "credential-access",
            "detection_tools": {"prowler": "", "cloudsplaining": ""},
            "cloudgoat_scenario": None
        }
    }
]

priority_pids = [
    "iam-014",             # iam:PassRole (user -> role) -> RULE-IAM-001
    "iam-001",             # iam:CreatePolicyVersion
    "iam-009",             # iam:AttachRolePolicy
    "iam-005",             # iam:PutRolePolicy
    "iam-002",             # iam:CreateAccessKey
    "sts-001",              # sts:AssumeRole
]

ordered_pids = []
for pid in priority_pids:
    if pid in paths_by_id and pid not in ordered_pids:
        ordered_pids.append(pid)

for pid in sorted(paths_by_id.keys()):
    if pid not in ordered_pids:
        ordered_pids.append(pid)

rules = []
rule_counter = 1

critical_actions = {
    "s3:getobject", "secretsmanager:getsecretvalue", "iam:createpolicyversion",
    "iam:attachuserpolicy", "iam:putuserpolicy", "iam:putrolepolicy",
    "iam:attachrolepolicy", "ec2:runinstances"
}

converted_summary = {
    "total_paths_scanned": len(paths_by_id),
    "converted_count": 0,
    "paths_with_detection_tools": 0,
    "paths_with_cloudgoat_scenario": 0,
    "mitre_checked_count": 0
}

# Add extra data access rules first
for er in extra_data_rules:
    rules.append(er)

for pid in ordered_pids:
    data = paths_by_id[pid]
    name = data.get("name", "")
    category = data.get("category", "self-escalation")
    description = data.get("description", "")
    recommendation = data.get("recommendation", "")
    
    # Permissions
    perms_req = data.get("permissions", {}).get("required", [])
    req_actions = [p.get("permission") for p in perms_req if p.get("permission")]
    
    if not req_actions:
        raw_act = name.split(" + ")[0].strip()
        req_actions = [raw_act]
    
    # Clean primary action string
    primary_action = req_actions[0].split(" + ")[0].strip()
            
    # Resource constraints fold into condition
    constraints = [p.get("resourceConstraints") for p in perms_req if p.get("resourceConstraints")]
    condition = {"resource_constraints": constraints} if constraints else None
    
    # Discovery Attribution
    attrib = data.get("discoveryAttribution", {}).get("firstDocumented", {})
    author = attrib.get("author", "Rhino Security Labs / DataDog Research")
    org = attrib.get("organization", "DataDog / Community")
    date_str = str(attrib.get("date", "2019"))
    link = attrib.get("link", "https://pathfinding.cloud")
    
    source = {
        "name": f"pathfinding.cloud (DataDog) / {author}",
        "url": link,
        "organization": org,
        "date": date_str,
        "tier": "CANONICAL_RESEARCH"
    }
    
    # Detection Tools
    detection_tools = data.get("detectionTools", {})
    if detection_tools:
        converted_summary["paths_with_detection_tools"] += 1
        
    # CloudGoat Scenario
    cg_scenario = CLOUDGOAT_MAP.get(pid)
    if cg_scenario:
        converted_summary["paths_with_cloudgoat_scenario"] += 1
        
    # MITRE Mapping
    mitre_info = MITRE_MAP.get(primary_action)
    if not mitre_info:
        for act_key, m_val in MITRE_MAP.items():
            if act_key.lower() in primary_action.lower():
                mitre_info = m_val
                break
    if not mitre_info:
        mitre_info = ("T1098", "Account Manipulation")
        
    t_id, t_name = mitre_info
    converted_summary["mitre_checked_count"] += 1
    
    act_lower = primary_action.lower()
    severity = "CRITICAL" if (category in ("self-escalation", "new-passrole") or act_lower in critical_actions) else "HIGH"
    resource_type = determine_resource_type(primary_action)
    relationship = determine_relationship(primary_action)
    
    p_types = ["user"]
    if category in ("self-escalation", "existing-passrole") or "role" in primary_action.lower() or act_lower in ("sts:assumerole", "iam:passrole", "s3:getobject", "secretsmanager:getsecretvalue"):
        p_types.append("role")

    for p_type in p_types:
        rule_id = f"RULE-IAM-{rule_counter:03d}"
        rule_counter += 1
        
        rule_entry = {
            "rule_id": rule_id,
            "title": f"Privilege Escalation via {primary_action} ({pid} - {p_type})",
            "description": description,
            "principal_type": p_type,
            "action": primary_action,
            "resource_type": resource_type,
            "relationship": relationship,
            "severity": severity,
            "technique_id": t_id,
            "technique_name": t_name,
            "required_actions": req_actions,
            "evidence_citation": f"pathfinding.cloud path {pid} ({category}) | {recommendation}",
            "condition": condition,
            "source": source,
            "evidence": {
                "text": f"Principal ({p_type}) holds permissions satisfying {pid} ({name}).",
                "detection_tools": list(detection_tools.keys())
            },
            "mitre": {
                "technique_id": t_id,
                "technique_name": t_name
            },
            "version": "0.1",
            "status": "ACTIVE",
            "rulebook_origin": "active",
            "extras": {
                "source_path_id": pid,
                "category": category,
                "detection_tools": detection_tools,
                "cloudgoat_scenario": cg_scenario
            }
        }
        rules.append(rule_entry)

converted_summary["converted_count"] = len(rules)

print("--- Conversion Summary ---")
print(json.dumps(converted_summary, indent=2))

with open("rulebook/active_rulebook.json", "w", encoding="utf-8") as f:
    json.dump(rules, f, indent=2)

print(f"Successfully wrote {len(rules)} converted rules into rulebook/active_rulebook.json")
