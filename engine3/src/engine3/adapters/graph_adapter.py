"""GraphAdapter converts raw IAMGraph v0.1 JSON into InternalGraph models."""

from typing import Any

from engine3.contracts.models import (
    GraphEdge,
    InternalGraph,
    PermissionStatement,
    Principal,
    SnapshotMetadata,
    TargetResource,
)


class GraphAdapter:
    """Adapts raw IAMGraph JSON to InternalGraph."""

    SUPPORTED_MAJOR_VERSION = "0"

    @classmethod
    def from_json(cls, raw_data: dict[str, Any]) -> InternalGraph:
        contract_name = raw_data.get("contract_name")
        if contract_name != "IAMGraph":
            raise ValueError(f"Invalid contract_name '{contract_name}', expected 'IAMGraph'")

        version = str(raw_data.get("contract_version", ""))
        major_version = version.split(".")[0] if "." in version else version
        if major_version != cls.SUPPORTED_MAJOR_VERSION:
            raise ValueError(f"Unsupported contract major version '{version}'")

        snap_raw = raw_data.get("snapshot", {})
        snapshot = SnapshotMetadata(
            snapshot_id=snap_raw.get("snapshot_id", ""),
            account_id=snap_raw.get("account_id", ""),
            collected_at=snap_raw.get("collected_at", ""),
            origin=snap_raw.get("origin", ""),
            collection_status=snap_raw.get("collection_status", "complete"),
            collected_resource_types=snap_raw.get("collected_resource_types", []),
            coverage=snap_raw.get("coverage", []),
            extras={k: v for k, v in snap_raw.items() if k not in SnapshotMetadata.model_fields},
        )

        principals: list[Principal] = []
        permissions: list[PermissionStatement] = []
        resources: list[TargetResource] = []

        for node in raw_data.get("nodes", []):
            node_type = node.get("type")
            node_id = str(node.get("id"))
            if node_type in ("User", "Role", "ServicePrincipal"):
                principals.append(
                    Principal(
                        id=node_id,
                        type=node_type,
                        arn=node.get("arn"),
                        name=node.get("name"),
                        permissions_boundary=node.get("permissions_boundary"),
                        trust_policy=node.get("trust_policy"),
                        extras={
                            k: v for k, v in node.items() if k not in Principal.model_fields
                        },
                    )
                )
            elif node_type == "Permission":
                permissions.append(
                    PermissionStatement(
                        id=node_id,
                        type="Permission",
                        effect=node.get("effect", "Allow"),
                        actions=node.get("actions"),
                        not_actions=node.get("not_actions"),
                        resources=node.get("resources"),
                        not_resources=node.get("not_resources"),
                        condition=node.get("condition"),
                        raw_statement=node.get("raw_statement", {}),
                        provenance=node.get("provenance", {}),
                        extras={
                            k: v
                            for k, v in node.items()
                            if k not in PermissionStatement.model_fields
                        },
                    )
                )
            elif node_type == "Resource":
                resources.append(
                    TargetResource(
                        id=node_id,
                        type="Resource",
                        resource_type=node.get("resource_type", ""),
                        arn=node.get("arn", node_id),
                        name=node.get("name"),
                        metadata=node.get("metadata", {}),
                        extras={
                            k: v for k, v in node.items() if k not in TargetResource.model_fields
                        },
                    )
                )

        edges: list[GraphEdge] = []
        for edge in raw_data.get("edges", []):
            edge_id = str(edge.get("id"))
            edges.append(
                GraphEdge(
                    id=edge_id,
                    type=edge.get("type", ""),
                    source=str(edge.get("source", "")),
                    target=str(edge.get("target", "")),
                    via_group=edge.get("via_group"),
                    via=edge.get("via"),
                    has_condition=edge.get("has_condition"),
                    statement_index=edge.get("statement_index"),
                    matched_principal=edge.get("matched_principal"),
                    extras={k: v for k, v in edge.items() if k not in GraphEdge.model_fields},
                )
            )

        # Sort deterministically by opaque ID
        principals.sort(key=lambda p: p.id)
        permissions.sort(key=lambda p: p.id)
        resources.sort(key=lambda r: r.id)
        edges.sort(key=lambda e: e.id)

        degraded = snapshot.collection_status == "partial"
        degraded_reasons = []
        if degraded:
            degraded_reasons.append("Graph snapshot collection_status is 'partial'")

        return InternalGraph(
            snapshot=snapshot,
            principals=principals,
            permissions=permissions,
            resources=resources,
            edges=edges,
            warnings=raw_data.get("warnings", []),
            degraded=degraded,
            degraded_reasons=degraded_reasons,
        )
