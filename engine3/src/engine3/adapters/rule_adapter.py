"""RuleAdapter converts raw SecurityRule/ApprovedRule JSON into internal Rule models."""

from typing import Any, Dict, List
from engine3.contracts.models import Rule


class RuleAdapter:
    """Adapts raw SecurityRule JSON list or dict to internal Rule models."""

    SUPPORTED_MAJOR_VERSION = "0"

    @classmethod
    def from_json_list(cls, raw_list: List[Dict[str, Any]]) -> List[Rule]:
        rules: List[Rule] = []
        for raw in raw_list:
            version = str(raw.get("version", "0.1"))
            major_version = version.split(".")[0] if "." in version else version
            if major_version != cls.SUPPORTED_MAJOR_VERSION:
                raise ValueError(f"Unsupported SecurityRule major version '{version}'")

            rule = Rule(
                rule_id=str(raw.get("rule_id", "")),
                title=raw.get("title", ""),
                description=raw.get("description", ""),
                condition=raw.get("condition"),
                principal_type=raw.get("principal_type", ""),
                action=raw.get("action", ""),
                resource_type=raw.get("resource_type", ""),
                relationship=raw.get("relationship", ""),
                severity=raw.get("severity", ""),
                source=raw.get("source", {}),
                evidence=raw.get("evidence", ""),
                mitre=raw.get("mitre"),
                version=version,
                status=raw.get("status", "ACTIVE"),
                extras={k: v for k, v in raw.items() if k not in Rule.model_fields},
            )
            rules.append(rule)

        rules.sort(key=lambda r: r.rule_id)
        return rules
