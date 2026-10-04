"""Stage 2 Attack-Path Discovery Engine."""

import hashlib
from typing import Any

from pydantic import BaseModel, Field

from engine3.contracts.models import InternalGraph
from engine3.stages.s1_match import RuleMatchResult


class PathHop(BaseModel):
    from_node: str
    to_node: str
    action_used: str
    matched_rule_id: str | None = None
    edge_id: str
    edge_type: str
    flags: list[str] = Field(default_factory=list)


class CandidatePath(BaseModel):
    path_id: str
    hops: list[PathHop]
    assumptions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    degraded: bool = False
    target_node: str
    start_node: str


class Stage2DiscoveryResult(BaseModel):
    paths: list[CandidatePath] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class Stage2PathFinder:
    """Stage 2 Attack-Path Discovery Engine."""

    def __init__(self, max_depth: int = 6) -> None:
        self.max_depth = max_depth

    @staticmethod
    def compute_path_id(hops: list[PathHop]) -> str:
        edge_seq = "|".join(f"{h.edge_id}:{h.action_used}" for h in hops)
        return hashlib.sha256(edge_seq.encode("utf-8")).hexdigest()[:16]

    def discover_paths(
        self, graph: InternalGraph, match_results: list[RuleMatchResult]
    ) -> Stage2DiscoveryResult:
        result = Stage2DiscoveryResult()
        result.limitations.append(
            "A missing attack path is never proof of absolute safety."
        )

        if graph.degraded:
            result.warnings.append(
                "Graph collection_status is partial; discovered paths marked degraded."
            )

        # Build adjacency graph
        # 1. TRUSTED_BY edges (Role -> Role, User -> Role)
        # 2. Rule matched edges (Role/User -> Target)
        adj: dict[str, list[dict[str, Any]]] = {}

        for edge in graph.edges:
            if edge.type == "TRUSTED_BY":
                # Check for unresolved cross account warnings
                is_unresolved = False
                for w in graph.warnings:
                    if w.get("edge_id") == edge.id or w.get("code") == "WARN_UNRESOLVED_CROSS_ACCOUNT":
                        is_unresolved = True
                        break
                if is_unresolved:
                    result.warnings.append(
                        f"Skipping edge '{edge.id}' due to unresolved cross-account trust."
                    )
                    continue

                flags = []
                if edge.has_condition:
                    flags.append("condition_unevaluated")
                else:
                    flags.append("trust_structural_only")

                adj.setdefault(edge.source, []).append(
                    {
                        "to_node": edge.target,
                        "action_used": "sts:AssumeRole",
                        "matched_rule_id": None,
                        "edge_id": edge.id,
                        "edge_type": edge.type,
                        "flags": flags,
                    }
                )

        # Add rule matched target hops
        for r_res in match_results:
            if r_res.status != "MATCHED":
                continue
            for m in r_res.matches:
                adj.setdefault(m.principal_id, []).append(
                    {
                        "to_node": m.target_id,
                        "action_used": f"rule_target:{r_res.rule_id}",
                        "matched_rule_id": r_res.rule_id,
                        "edge_id": m.edge_id or "rule_edge",
                        "edge_type": "APPLIES_TO",
                        "flags": m.flags,
                    }
                )

        # Identify start nodes (Users)
        start_nodes = [p.id for p in graph.principals if p.type == "User"]
        target_nodes = {r.id for r in graph.resources}

        discovered: list[CandidatePath] = []

        def dfs(current_node: str, current_hops: list[PathHop], visited: set[str]) -> None:
            if len(current_hops) >= self.max_depth:
                return

            if current_node in target_nodes:
                p_id = self.compute_path_id(current_hops)
                all_assumptions: set[str] = set()
                for h in current_hops:
                    all_assumptions.update(h.flags)

                path_obj = CandidatePath(
                    path_id=p_id,
                    hops=list(current_hops),
                    assumptions=sorted(all_assumptions),
                    limitations=[
                        "SCP/RCP/session policies not evaluated",
                        "Permissions boundaries beyond ARN not checked",
                    ],
                    degraded=graph.degraded,
                    start_node=current_hops[0].from_node,
                    target_node=current_node,
                )
                discovered.append(path_obj)
                return

            for neighbor in adj.get(current_node, []):
                next_node = neighbor["to_node"]
                if next_node in visited:
                    continue

                hop = PathHop(
                    from_node=current_node,
                    to_node=next_node,
                    action_used=neighbor["action_used"],
                    matched_rule_id=neighbor["matched_rule_id"],
                    edge_id=neighbor["edge_id"],
                    edge_type=neighbor["edge_type"],
                    flags=neighbor["flags"],
                )

                visited.add(next_node)
                current_hops.append(hop)
                dfs(next_node, current_hops, visited)
                current_hops.pop()
                visited.remove(next_node)

        for s_node in start_nodes:
            dfs(s_node, [], {s_node})

        # Sort paths deterministically by path_id
        discovered.sort(key=lambda p: p.path_id)
        result.paths = discovered
        return result
