"""Stage 8 Output Package & Metrics Assembler."""

import json
import time
from pathlib import Path
from typing import Any

from engine3.s0_intake import Stage0LoadResult
from engine3.s3_prioritization import QueuedPath
from engine3.s4_policy_verification import PathSimResult
from engine3.s5_sandbox import SandboxRunResult
from engine3.s6_evidence import Stage6EvidenceAggregator
from engine3.s7_decision import Stage7DecisionEngine


class Stage8OutputAssembler:
    """Stage 8 VerificationResult Assembler & Metric Packager."""

    def __init__(self) -> None:
        self.evidence_aggregator = Stage6EvidenceAggregator()
        self.decision_engine = Stage7DecisionEngine()

    def assemble(
        self,
        load_res: Stage0LoadResult,
        queue_paths: list[QueuedPath],
        sim_results: list[PathSimResult],
        sandbox_results: list[SandboxRunResult] | None = None,
        rulebook_origin: str = "active",
        metrics_dict: dict[str, float] | None = None,
        output_file: Path | str | None = "runs/final_verification_results.json",
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

            evidence = self.evidence_aggregator.collect_path_evidence(q_p, sim_res, sb_res)
            decision = self.decision_engine.evaluate_decision(sim_res, sb_res, evidence)

            status = decision.status
            confidence_tier = decision.confidence_tier
            status_reason = decision.status_reason
            verification_scope = decision.verification_scope

            status_counts[status] = status_counts.get(status, 0) + 1

            evidence_dict = {
                "policy_simulator_result": evidence.policy_simulator_result,
                "policy_simulator_source": evidence.policy_simulator_source,
                "policy_simulator_details": evidence.policy_simulator_details,
                "sandbox_scenario_name": evidence.sandbox_scenario_name,
                "sandbox_attempted": evidence.sandbox_attempted,
                "sandbox_execution_success": evidence.sandbox_execution_success,
                "sandbox_logs": evidence.sandbox_logs,
                "sandbox_logs_redacted": evidence.sandbox_logs_redacted,
                "sandbox_evidence_ref": evidence.sandbox_evidence_ref,
            }

            path_sandbox_time = 0.0
            if sb_res and sb_res.runtime_metrics:
                path_sandbox_time = sb_res.runtime_metrics.get("sandbox_time_ms") or 0.0

            path_policy_time = 0.0
            if sim_res and hasattr(sim_res, "eval_duration_ms"):
                path_policy_time = sim_res.eval_duration_ms
            elif metrics_dict.get("policy_sim_time_ms"):
                path_policy_time = metrics_dict["policy_sim_time_ms"] / max(len(queue_paths), 1)

            final_paths.append(
                {
                    "path_id": path_id,
                    "status": status,
                    "status_reason": status_reason,
                    "verification_scope": verification_scope,
                    "hops": evidence.hops_formatted,
                    "assumptions": q_p.path.assumptions,
                    "queue_rank": q_p.queue_rank,
                    "queue_reason": q_p.queue_reason,
                    "evidence": evidence_dict,
                    "limitations": evidence.limitations,
                    "runtime_metrics": {
                        "policy_sim_time_ms": round(path_policy_time, 2),
                        "sandbox_time_ms": round(path_sandbox_time, 2),
                    },
                }
            )

        # Aggregate sandbox phase stopwatch breakdown
        sandbox_breakdown = {
            "deploy": None,
            "execute": None,
            "destroy": None,
        }
        ran_breakdowns = [
            sb.runtime_metrics.get("sandbox_breakdown_ms")
            for sb in sandbox_results
            if sb.sandbox_attempted and sb.runtime_metrics and sb.runtime_metrics.get("sandbox_breakdown_ms")
        ]
        if ran_breakdowns:
            sandbox_breakdown = {
                "deploy": round(sum(b.get("deploy", 0.0) or 0.0 for b in ran_breakdowns), 2),
                "execute": round(sum(b.get("execute", 0.0) or 0.0 for b in ran_breakdowns), 2),
                "destroy": round(sum(b.get("destroy", 0.0) or 0.0 for b in ran_breakdowns), 2),
            }

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
                "sandbox_mode": "MOCKED",
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
                "sandbox_breakdown_ms": sandbox_breakdown,
            },
            "stats": {
                "paths_total": len(final_paths),
                "by_status": status_counts,
            },
            "warnings": [w for w in load_res.warnings],
        }

        if output_file:
            out_p = Path(output_file)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(res_doc, f, indent=2)

        return res_doc


# Backward compatibility aliases
Stage8Output = Stage8OutputAssembler
Stage6Assembler = Stage8OutputAssembler
