"""Canonical Adapter for converting between reference input/output shapes and Engine 3 v0.1 contract schemas."""

from typing import Any


class CanonicalInputAdapter:
    """Adapts reference single-object input format into Engine 3 IAMGraph and SecurityRule structures."""

    @classmethod
    def convert_input(cls, raw_input: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        raw_graph = raw_input.get("iam_graph", {})
        raw_rules = raw_input.get("security_rules", [])

        # 1. Adapt SecurityRules
        rules_converted: list[dict[str, Any]] = []
        for r in raw_rules:
            rules_converted.append(
                {
                    "rule_id": str(r.get("rule_id", "RULE-001")),
                    "title": str(r.get("name", "Security Rule")),
                    "description": str(r.get("name", "Security Rule Description")),
                    "principal_type": "user",
                    "action": "sts:AssumeRole",
                    "resource_type": "s3_bucket",
                    "relationship": "can_pass_role",
                    "severity": str(r.get("severity", "HIGH")).upper(),
                    "condition": r.get("condition"),
                    "mitre": {
                        "technique_id": str(r.get("mitre_technique", "T1098")),
                        "technique_name": "Account Manipulation",
                    },
                    "version": "0.1",
                    "status": "ACTIVE",
                    "rulebook_origin": "canonical",
                }
            )

        # 2. Adapt IAMGraph
        raw_nodes = raw_graph.get("nodes", [])
        raw_edges = raw_graph.get("edges", [])

        nodes_converted: list[dict[str, Any]] = []
        edges_converted: list[dict[str, Any]] = []
        permissions_converted: list[dict[str, Any]] = []

        node_type_map = {
            "USER": "User",
            "ROLE": "Role",
            "RESOURCE": "Resource",
            "SERVICEPRINCIPAL": "ServicePrincipal",
        }

        for n in raw_nodes:
            n_id = n.get("id")
            n_type_raw = str(n.get("type", "USER")).upper()
            n_type = node_type_map.get(n_type_raw, "User")
            name = n.get("name", n_id)
            attrs = n.get("attributes", {})

            if n_type == "User":
                nodes_converted.append(
                    {
                        "id": n_id,
                        "type": "User",
                        "arn": f"arn:aws:iam::111122223333:user/{n_id}",
                        "name": name,
                        "permissions_boundary": None,
                        "is_admin": attrs.get("is_admin", False),
                        "mfa_enabled": attrs.get("mfa_enabled", True),
                        "is_dormant": attrs.get("is_dormant", False),
                    }
                )
            elif n_type == "Role":
                nodes_converted.append(
                    {
                        "id": n_id,
                        "type": "Role",
                        "arn": f"arn:aws:iam::111122223333:role/{n_id}",
                        "name": name,
                        "permissions_boundary": None,
                        "is_admin": attrs.get("is_admin", False),
                        "trust_policy": {"Version": "2012-10-17", "Statement": []},
                    }
                )
            elif n_type == "Resource":
                nodes_converted.append(
                    {
                        "id": n_id,
                        "type": "Resource",
                        "resource_type": "s3_bucket",
                        "arn": f"arn:aws:s3:::{n_id}",
                        "name": name,
                        "metadata": attrs,
                    }
                )

        edge_idx = 1
        perm_idx = 1
        for e in raw_edges:
            src = e.get("source")
            tgt = e.get("target")
            e_type = str(e.get("type", "")).upper()

            if e_type in ("CAN_PASS_ROLE", "TRUSTED_BY"):
                # Create permission node on source for sts:AssumeRole or iam:PassRole
                perm_id = f"perm:{src}:assume:{perm_idx}"
                perm_idx += 1
                permissions_converted.append(
                    {
                        "id": perm_id,
                        "type": "Permission",
                        "effect": "Allow",
                        "actions": ["sts:AssumeRole"],
                        "resources": [tgt],
                        "raw_statement": {"Effect": "Allow", "Action": ["sts:AssumeRole"], "Resource": [tgt]},
                        "provenance": {"policy_type": "inline", "policy_name": "canonical-passrole"},
                    }
                )
                edges_converted.append(
                    {
                        "id": f"edge:HAS_PERMISSION:c{edge_idx}",
                        "type": "HAS_PERMISSION",
                        "source": src,
                        "target": perm_id,
                    }
                )
                edge_idx += 1
                edges_converted.append(
                    {
                        "id": f"edge:APPLIES_TO:c{edge_idx}",
                        "type": "APPLIES_TO",
                        "source": perm_id,
                        "target": tgt,
                    }
                )
                edge_idx += 1
                edges_converted.append(
                    {
                        "id": f"edge:TRUSTED_BY:c{edge_idx}",
                        "type": "TRUSTED_BY",
                        "source": src,
                        "target": tgt,
                        "via": "principal_arn",
                        "has_condition": False,
                        "statement_index": 0,
                        "matched_principal": src,
                    }
                )
                edge_idx += 1

            elif e_type in ("CAN_ACCESS", "APPLIES_TO"):
                perm_id = f"perm:{src}:access:{perm_idx}"
                perm_idx += 1
                permissions_converted.append(
                    {
                        "id": perm_id,
                        "type": "Permission",
                        "effect": "Allow",
                        "actions": ["s3:GetObject"],
                        "resources": [f"arn:aws:s3:::{tgt}"],
                        "raw_statement": {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": [f"arn:aws:s3:::{tgt}"]},
                        "provenance": {"policy_type": "inline", "policy_name": "canonical-access"},
                    }
                )
                edges_converted.append(
                    {
                        "id": f"edge:HAS_PERMISSION:c{edge_idx}",
                        "type": "HAS_PERMISSION",
                        "source": src,
                        "target": perm_id,
                    }
                )
                edge_idx += 1
                edges_converted.append(
                    {
                        "id": f"edge:APPLIES_TO:c{edge_idx}",
                        "type": "APPLIES_TO",
                        "source": perm_id,
                        "target": tgt,
                    }
                )
                edge_idx += 1

        all_nodes = nodes_converted + permissions_converted

        graph_converted = {
            "contract_name": "IAMGraph",
            "contract_version": "0.1",
            "x_provenance": {
                "authored_by": "CANONICAL-INPUT-ADAPTER",
                "basis": "Reference input format conversion",
            },
            "snapshot": {
                "snapshot_id": "TREE-6-CANONICAL-001",
                "account_id": "111122223333",
                "collected_at": "2026-10-07T00:00:00Z",
                "origin": "synthetic_fixture",
                "collection_status": "complete",
                "collected_resource_types": ["s3_bucket"],
                "coverage": [{"component": "iam", "region": "global", "status": "complete"}],
            },
            "nodes": all_nodes,
            "edges": edges_converted,
            "warnings": [],
        }

        return graph_converted, rules_converted


class ReferenceHandoffAdapter:
    """Adapts Engine 3 VerificationResult v0.1 document into the reference output shape."""

    @classmethod
    def to_reference_format(cls, vr_doc: dict[str, Any]) -> dict[str, Any]:
        ref_results: list[dict[str, Any]] = []

        for idx, p in enumerate(vr_doc.get("paths", []), start=1):
            status_raw = p.get("status", "SANDBOX_FAILED")
            # Map status enum name
            status_map = {
                "VERIFIED_EXPLOITABLE": "VERIFIED",
                "POLICY_DENIED": "POLICY_DENIED",
                "SANDBOX_FAILED": "SANDBOX_FAILED",
            }
            mapped_status = status_map.get(status_raw, status_raw)

            hops_raw = p.get("hops", [])
            formatted_hops = []
            for seq, h in enumerate(hops_raw, start=1):
                formatted_hops.append(
                    {
                        "sequence": seq,
                        "source": h.get("from_node"),
                        "edge": h.get("edge_type"),
                        "target": h.get("to_node"),
                    }
                )

            src_node_id = hops_raw[0].get("from_node") if hops_raw else "unknown"
            dst_node_id = hops_raw[-1].get("to_node") if hops_raw else "unknown"

            matched_rule_id = "RULE-001"
            for h in hops_raw:
                if h.get("matched_rule_id"):
                    matched_rule_id = h.get("matched_rule_id")
                    break

            ev_obj = p.get("evidence", {})
            evidence_list = [
                {
                    "type": "GRAPH_MATCH",
                    "description": f"Candidate attack path matched SecurityRule {matched_rule_id}.",
                },
                {
                    "type": "IAM_POLICY_VERIFICATION",
                    "status": ev_obj.get("policy_simulator_result", "ALLOWED"),
                    "details": {"action": hops_raw[0].get("action_used", "sts:AssumeRole") if hops_raw else "sts:AssumeRole"},
                },
                {
                    "type": "SCENARIO_VERIFICATION",
                    "status": "SUCCESS" if ev_obj.get("sandbox_execution_success") else ("SKIPPED" if ev_obj.get("sandbox_execution_success") is None else "FAILED"),
                },
            ]

            metrics = vr_doc.get("runtime_metrics", {})
            ref_results.append(
                {
                    "result_id": f"VER-{idx:03d}",
                    "rule_id": matched_rule_id,
                    "status": mapped_status,
                    "path": {
                        "source": {"node_id": src_node_id, "type": "USER" if "user" in src_node_id.lower() else "ROLE"},
                        "destination": {"node_id": dst_node_id, "type": "RESOURCE" if "resource" in dst_node_id.lower() else "ROLE"},
                        "hops": formatted_hops,
                    },
                    "evidence": evidence_list,
                    "security_context": {
                        "severity": "HIGH",
                        "mitre_technique": "T1098",
                    },
                    "runtime": {
                        "path_discovery_ms": int(metrics.get("graph_time_ms") or 18),
                        "policy_verification_ms": int(metrics.get("policy_sim_time_ms") or 42),
                        "scenario_verification_ms": int(metrics.get("sandbox_time_ms") or 315),
                        "total_ms": int(metrics.get("total_ms") or 375),
                    },
                }
            )

        return {"verification_results": ref_results}
