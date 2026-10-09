"""Stage 0 Intake, Loader and Validator."""

import hashlib
import json
from pathlib import Path
from typing import Any, ClassVar

import jsonschema
from pydantic import BaseModel, Field

from engine3.adapters.graph_adapter import GraphAdapter
from engine3.adapters.rule_adapter import RuleAdapter
from engine3.contracts.models import InternalGraph, Rule


class StructuredError(BaseModel):
    """Structured error definition for loader/validator."""

    code: str
    location: str
    message: str


class Stage0LoadResult(BaseModel):
    """Output result of Stage 0 loading and validation."""

    graph: InternalGraph | None = None
    active_rules: list[Rule] = Field(default_factory=list)
    skipped_rules: list[Rule] = Field(default_factory=list)
    iamgraph_content_sha256: str = ""
    rulebook_sha256: str = ""
    rules_active: int = 0
    rules_skipped: int = 0
    limitations: list[str] = Field(default_factory=list)
    errors: list[StructuredError] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0


# Alias for canonical pipeline stage naming
Stage0IntakeResult = Stage0LoadResult


class Stage0Loader:
    """Loader and validator for Stage 0 inputs."""

    LEGAL_EDGE_ENDPOINTS: ClassVar[dict[str, dict[str, Any]]] = {
        "HAS_PERMISSION": {
            "sources": {"User", "Role", "ServicePrincipal"},
            "targets": {"Permission"},
        },
        "TRUSTED_BY": {
            "sources": {"User", "Role", "ServicePrincipal", "Resource"},
            "targets": {"Role"},
        },
        "APPLIES_TO": {
            "sources": {"Permission"},
            "targets": {"Resource", "Role", "User", "ServicePrincipal"},
        },
    }

    VALID_SEVERITIES: ClassVar[set[str]] = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    VALID_STATUSES: ClassVar[set[str]] = {"ACTIVE", "DISABLED", "DRAFT"}

    def __init__(self, schemas_dir: Path | None = None) -> None:
        if schemas_dir is None:
            candidates = [
                Path(__file__).parents[2] / "schemas",
                Path(__file__).parents[3] / "schemas",
                Path.cwd() / "engine3" / "schemas",
                Path.cwd() / "schemas",
            ]
            for c in candidates:
                if c.exists() and (c / "iamgraph_v0.1.schema.json").exists():
                    schemas_dir = c
                    break
            if schemas_dir is None:
                schemas_dir = Path(__file__).parents[2] / "schemas"
        self.schemas_dir = schemas_dir

    def _load_schema(self, schema_name: str) -> dict[str, Any]:
        schema_path = self.schemas_dir / schema_name
        with open(schema_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def load_and_validate(
        self,
        iamgraph_data: dict[str, Any],
        rulebook_data: list[dict[str, Any]],
        iamgraph_raw_bytes: bytes | None = None,
        rulebook_raw_bytes: bytes | None = None,
        expected_iamgraph_sha256: str | None = None,
    ) -> Stage0LoadResult:
        result = Stage0LoadResult()

        # Limitation statement per rules
        result.limitations.append(
            "A missing edge in the IAMGraph is never treated as proof of safety."
        )

        # Compute SHA-256 hashes
        if iamgraph_raw_bytes is not None:
            computed = hashlib.sha256(iamgraph_raw_bytes).hexdigest()
            result.iamgraph_content_sha256 = computed
            if expected_iamgraph_sha256 and computed != expected_iamgraph_sha256:
                result.errors.append(
                    StructuredError(
                        code="ERR_MANIFEST_HASH_MISMATCH",
                        location="iamgraph_raw_bytes",
                        message=f"Computed hash {computed} does not match expected {expected_iamgraph_sha256}",
                    )
                )
        else:
            result.iamgraph_content_sha256 = hashlib.sha256(
                json.dumps(iamgraph_data, sort_keys=True).encode("utf-8")
            ).hexdigest()

        if rulebook_raw_bytes is not None:
            result.rulebook_sha256 = hashlib.sha256(rulebook_raw_bytes).hexdigest()
        else:
            result.rulebook_sha256 = hashlib.sha256(
                json.dumps(rulebook_data, sort_keys=True).encode("utf-8")
            ).hexdigest()

        # 1. Check schema validation for IAMGraph
        try:
            iamgraph_schema = self._load_schema("iamgraph_v0.1.schema.json")
            jsonschema.validate(instance=iamgraph_data, schema=iamgraph_schema)
        except jsonschema.ValidationError as err:
            result.errors.append(
                StructuredError(
                    code="ERR_SCHEMA_VALIDATION",
                    location=f"iamgraph.{'.'.join(str(p) for p in err.path)}",
                    message=err.message,
                )
            )

        # Check version fields
        if "contract_version" not in iamgraph_data:
            result.errors.append(
                StructuredError(
                    code="ERR_MISSING_CONTRACT_VERSION",
                    location="iamgraph.contract_version",
                    message="Missing contract_version field",
                )
            )
        elif str(iamgraph_data.get("contract_version")) != "0.1":
            result.errors.append(
                StructuredError(
                    code="ERR_WRONG_CONTRACT_VERSION",
                    location="iamgraph.contract_version",
                    message=f"Unsupported contract_version '{iamgraph_data.get('contract_version')}'",
                )
            )

        # Check x_provenance extension note
        if "x_provenance" not in iamgraph_data:
            result.notes.append("x_provenance field is absent from IAMGraph snapshot.")

        # Semantic validation of IAMGraph
        nodes_raw = iamgraph_data.get("nodes", [])
        edges_raw = iamgraph_data.get("edges", [])
        snapshot_raw = iamgraph_data.get("snapshot", {})

        node_map: dict[str, dict[str, Any]] = {}
        for idx, node in enumerate(nodes_raw):
            node_id = node.get("id")
            if not node_id:
                continue
            if node_id in node_map:
                result.errors.append(
                    StructuredError(
                        code="ERR_DUPLICATE_NODE_ID",
                        location=f"iamgraph.nodes[{idx}].id",
                        message=f"Duplicate node ID '{node_id}' found.",
                    )
                )
            else:
                node_map[node_id] = node

            # Check permission node constraints (actions and not_actions together)
            if node.get("type") == "Permission":
                has_actions = bool(node.get("actions"))
                has_not_actions = bool(node.get("not_actions"))
                if has_actions and has_not_actions:
                    result.errors.append(
                        StructuredError(
                            code="ERR_BOTH_ACTIONS_AND_NOT_ACTIONS",
                            location=f"iamgraph.nodes[{idx}]",
                            message=f"Permission node '{node_id}' contains both actions and not_actions.",
                        )
                    )

        # Check edges
        for idx, edge in enumerate(edges_raw):
            edge_id = edge.get("id")
            source_id = edge.get("source")
            target_id = edge.get("target")
            edge_type = edge.get("type")

            source_node = node_map.get(source_id)
            target_node = node_map.get(target_id)

            if not source_node:
                result.errors.append(
                    StructuredError(
                        code="ERR_DANGLING_EDGE_SOURCE",
                        location=f"iamgraph.edges[{idx}].source",
                        message=f"Edge '{edge_id}' references missing source node '{source_id}'.",
                    )
                )
            if not target_node:
                result.errors.append(
                    StructuredError(
                        code="ERR_DANGLING_EDGE_TARGET",
                        location=f"iamgraph.edges[{idx}].target",
                        message=f"Edge '{edge_id}' references missing target node '{target_id}'.",
                    )
                )

            if source_node and target_node and edge_type in self.LEGAL_EDGE_ENDPOINTS:
                legal = self.LEGAL_EDGE_ENDPOINTS[edge_type]
                src_type = source_node.get("type")
                tgt_type = target_node.get("type")
                if src_type not in legal["sources"] or tgt_type not in legal["targets"]:
                    result.errors.append(
                        StructuredError(
                            code="ERR_INVALID_EDGE_ENDPOINT",
                            location=f"iamgraph.edges[{idx}]",
                            message=f"Edge '{edge_id}' of type '{edge_type}' has illegal endpoints ({src_type} -> {tgt_type}).",
                        )
                    )

        # Check warnings references
        warnings_raw = iamgraph_data.get("warnings", [])
        for idx, warn in enumerate(warnings_raw):
            node_ref = warn.get("node_id") or warn.get("target_id") or warn.get("principal_id")
            if node_ref and node_ref not in node_map:
                result.errors.append(
                    StructuredError(
                        code="ERR_DANGLING_WARNING_REFERENCE",
                        location=f"iamgraph.warnings[{idx}]",
                        message=f"Warning references missing node '{node_ref}'.",
                    )
                )

        # Check collection_status vs coverage
        coll_status = snapshot_raw.get("collection_status")
        coverage = snapshot_raw.get("coverage", [])
        if coll_status == "partial":
            all_complete = len(coverage) > 0 and all(
                item.get("status") == "complete" for item in coverage
            )
            if all_complete:
                result.errors.append(
                    StructuredError(
                        code="ERR_INCONSISTENT_COVERAGE",
                        location="iamgraph.snapshot",
                        message="collection_status is 'partial' but all coverage components report 'complete'.",
                    )
                )
        elif coll_status == "complete":
            any_incomplete = any(
                item.get("status") in ("partial", "failed") for item in coverage
            )
            if any_incomplete:
                result.errors.append(
                    StructuredError(
                        code="ERR_INCONSISTENT_COVERAGE",
                        location="iamgraph.snapshot",
                        message="collection_status is 'complete' but some coverage items are incomplete or failed.",
                    )
                )

        # 2. Check SecurityRule schema and semantics
        try:
            rule_schema = self._load_schema("security_rule_v0.1.schema.json")
            jsonschema.validate(instance=rulebook_data, schema=rule_schema)
        except jsonschema.ValidationError as err:
            result.errors.append(
                StructuredError(
                    code="ERR_SCHEMA_VALIDATION",
                    location=f"rulebook.{'.'.join(str(p) for p in err.path)}",
                    message=err.message,
                )
            )

        rule_ids: set[str] = set()
        for idx, r_data in enumerate(rulebook_data):
            rule_id = r_data.get("rule_id")
            if rule_id:
                if rule_id in rule_ids:
                    result.errors.append(
                        StructuredError(
                            code="ERR_DUPLICATE_RULE_ID",
                            location=f"rulebook[{idx}].rule_id",
                            message=f"Duplicate rule_id '{rule_id}' found in rulebook.",
                        )
                    )
                else:
                    rule_ids.add(rule_id)

            sev = r_data.get("severity")
            if sev not in self.VALID_SEVERITIES:
                result.errors.append(
                    StructuredError(
                        code="ERR_UNKNOWN_RULE_SEVERITY",
                        location=f"rulebook[{idx}].severity",
                        message=f"Rule '{rule_id}' has unknown severity '{sev}'.",
                    )
                )

            st = r_data.get("status")
            if st not in self.VALID_STATUSES:
                result.errors.append(
                    StructuredError(
                        code="ERR_UNKNOWN_RULE_STATUS",
                        location=f"rulebook[{idx}].status",
                        message=f"Rule '{rule_id}' has unknown status '{st}'.",
                    )
                )

        # If errors present, return early before adapter conversion
        if not result.is_valid:
            return result

        # Convert using adapters
        internal_graph = GraphAdapter.from_json(iamgraph_data)
        if coll_status == "partial":
            internal_graph.degraded = True
            internal_graph.degraded_reasons.append("IAMGraph collection_status is partial.")

        result.graph = internal_graph

        all_rules = RuleAdapter.from_json_list(rulebook_data)
        for rule in all_rules:
            if rule.status == "ACTIVE":
                result.active_rules.append(rule)
            else:
                result.skipped_rules.append(rule)
                result.warnings.append(
                    f"Skipping rule '{rule.rule_id}' with non-ACTIVE status '{rule.status}'."
                )

        result.rules_active = len(result.active_rules)
        result.rules_skipped = len(result.skipped_rules)

        return result


# Canonical alias for pipeline stages
Stage0Intake = Stage0Loader

__all__ = [
    "StructuredError",
    "Stage0LoadResult",
    "Stage0IntakeResult",
    "Stage0Loader",
    "Stage0Intake",
]
