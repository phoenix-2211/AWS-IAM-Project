"""Stage 6 VerificationResult Assembler."""

import time
from typing import Any

from engine3.sandbox.s5_sandbox import SandboxRunResult
from engine3.stages.s0_load import Stage0LoadResult
from engine3.stages.s3_queue import QueuedPath
from engine3.stages.s4_sim import PathSimResult


class Stage6Assembler:
    """Stage 6 VerificationResult Assembler."""

    def assemble(
        self,
        load_res: Stage0LoadResult,
        queue_paths: list[QueuedPath],
        sim_results: list[PathSimResult],
        sandbox_results: list[SandboxRunResult] | None = None,
        rulebook_origin: str = "active",
        metrics_dict: dict[str, float] | None = None,
    ) -> dict[str, Any]:
        if sandbox_results is None:
            sandbox_results = []
        if metrics_dict is None:
            metrics_dict = {}

        sim_map = {s.path_id: s for s in sim_results}
        sb_map = {sb.path_id: sb for sb in sandbox_results}

        final_paths: list[dict[str, Any]] = []
        status_counts: dict[str, int] = {}

        for q_p in queue_paths:
            path_id = q_p.path_id
            sim_res = sim_map.get(path_id)
            sb_res = sb_map.get(path_id)

            # Decision logic for final status (VERIFIED_EXPLOITABLE | POLICY_DENIED | SANDBOX_FAILED)
            if sim_res and sim_res.status == "POLICY_DENIED":
                status = "POLICY_DENIED"
                status_reason = sim_res.status_reason
                verification_scope = "policy_simulated_only"
            elif sb_res and sb_res.status == "VERIFIED_EXPLOITABLE":
                status = "VERIFIED_EXPLOITABLE"
                status_reason = "Exploit successfully verified in CloudGoat sandbox."
                verification_scope = "live_verified"
            elif sb_res and sb_res.sandbox_attempted:
                status = "SANDBOX_FAILED"
                status_reason = sb_res.reason or "Sandbox execution failed."
                verification_scope = "sandbox_attempted"
            else:
                status = "SANDBOX_FAILED"
                status_reason = "Path structurally allowed by local evaluator; unverified against live AWS policy simulator or sandbox."
                verification_scope = "policy_simulated_only"

            status_counts[status] = status_counts.get(status, 0) + 1

            hops_formatted = []
            for h in q_p.path.hops:
                hops_formatted.append(
                    {
                        "from_node": h.from_node,
                        "to_node": h.to_node,
                        "action_used": h.action_used,
                        "matched_rule_id": h.matched_rule_id,
                        "edge_id": h.edge_id,
                        "edge_type": h.edge_type,
                        "flags": h.flags,
                    }
                )

            evidence_obj = {
                "policy_simulator_result": "ALLOWED" if status != "POLICY_DENIED" else "DENIED",
                "policy_simulator_source": sim_res.source if sim_res else "local_evaluator",
                "policy_simulator_details": [h.model_dump() for h in (sim_res.hop_results if sim_res else [])],
                "sandbox_scenario_name": sb_res.sandbox_scenario_name if sb_res else None,
                "sandbox_attempted": sb_res.sandbox_attempted if sb_res else False,
                "sandbox_execution_success": sb_res.sandbox_execution_success if sb_res else None,
                "sandbox_logs": sb_res.sandbox_logs if sb_res else [],
                "sandbox_logs_redacted": True,
                "sandbox_evidence_ref": sb_res.sandbox_evidence_ref if sb_res else None,
            }

            path_limitations = list(q_p.path.limitations)
            if sim_res:
                path_limitations.extend(sim_res.limitations)
            if "local_evaluator, not AWS" not in path_limitations:
                path_limitations.append("local_evaluator, not AWS")

            final_paths.append(
                {
                    "path_id": path_id,
                    "status": status,
                    "status_reason": status_reason,
                    "verification_scope": verification_scope,
                    "hops": hops_formatted,
                    "assumptions": q_p.path.assumptions,
                    "queue_rank": q_p.queue_rank,
                    "queue_reason": q_p.queue_reason,
                    "evidence": evidence_obj,
                    "limitations": list(set(path_limitations)),
                    "runtime_metrics": {
                        "policy_sim_time_ms": metrics_dict.get("policy_sim_time_ms"),
                        "sandbox_time_ms": metrics_dict.get("sandbox_time_ms"),
                    },
                }
            )

        res_doc = {
            "contract_name": "VerificationResult",
            "contract_version": "0.1",
            "run": {
                "run_id": f"run-{int(time.time())}",
                "origin": "engine3_pipeline",
                "started_at": None,
                "finished_at": None,
                "git_sha": None,
                "mode": "offline_fixture",
                "simulator_backend": "local_evaluator",
                "sandbox_mode": "none",
                "enrichment": "off",
            },
            "inputs": {
                "iamgraph_snapshot_id": load_res.graph.snapshot.snapshot_id if load_res.graph else "unknown",
                "iamgraph_content_sha256": load_res.iamgraph_content_sha256,
                "iamgraph_collection_status": load_res.graph.snapshot.collection_status if load_res.graph else "complete",
                "rulebook_sha256": load_res.rulebook_sha256,
                "rulebook_origin": rulebook_origin,
                "rules_active": load_res.rules_active,
                "rules_skipped": load_res.rules_skipped,
            },
            "degraded": load_res.graph.degraded if load_res.graph else False,
            "degraded_reasons": load_res.graph.degraded_reasons if load_res.graph else [],
            "paths": final_paths,
            "runtime_metrics": {
                "graph_time_ms": metrics_dict.get("graph_time_ms"),
                "policy_sim_time_ms": metrics_dict.get("policy_sim_time_ms"),
                "sandbox_time_ms": metrics_dict.get("sandbox_time_ms"),
                "total_ms": metrics_dict.get("total_ms"),
                "load_time_ms": metrics_dict.get("load_time_ms"),
                "policy_sim_backend": "local_evaluator",
                "policy_sim_timing_representative": False,
                "sandbox_breakdown_ms": {
                    "deploy": None,
                    "execute": None,
                    "destroy": None,
                },
            },
            "stats": {
                "paths_total": len(final_paths),
                "by_status": status_counts,
            },
            "warnings": [w for w in load_res.warnings],
        }

        return res_doc
