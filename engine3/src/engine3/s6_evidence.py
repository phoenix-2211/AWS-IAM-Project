"""Stage 6 Evidence Aggregator."""

from typing import Any
from pydantic import BaseModel, Field

from engine3.s0_intake import Stage0LoadResult
from engine3.s3_prioritization import QueuedPath
from engine3.s4_policy_verification import PathSimResult
from engine3.s5_sandbox import SandboxRunResult


class PathEvidence(BaseModel):
    path_id: str
    policy_simulator_result: str
    policy_simulator_source: str
    simulator_mode: str = "MOCKED"
    policy_simulator_details: list[dict[str, Any]] = Field(default_factory=list)
    denying_hop_details: dict[str, Any] | None = None
    sandbox_scenario_name: str | None = None
    sandbox_attempted: bool = False
    sandbox_execution_success: bool | None = None
    sandbox_failure_reason: str | None = None
    sandbox_logs: list[str] = Field(default_factory=list)
    sandbox_logs_redacted: bool = True
    sandbox_evidence_ref: str | None = None
    sandbox_mode: str = "MOCKED"
    hops_formatted: list[dict[str, Any]] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class Stage6EvidenceAggregator:
    """Assembles graph + policy + sandbox evidence (makes no exploitability decision)."""

    def collect_path_evidence(
        self,
        queued_path: QueuedPath,
        sim_res: PathSimResult | None,
        sb_res: SandboxRunResult | None,
    ) -> PathEvidence:
        hops_formatted = []
        for h in queued_path.path.hops:
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

        sim_details = []
        if sim_res and sim_res.hop_results:
            for h_res in sim_res.hop_results:
                sim_details.append(
                    {
                        "hop_index": h_res.hop_index,
                        "decision": h_res.decision,
                        "eval_decision": h_res.eval_decision,
                        "missing_context": h_res.missing_context or [],
                        "note": h_res.note or "",
                        "raw_ref": h_res.raw_ref,
                    }
                )

        denying_hop_details = None
        if sim_res and sim_res.status == "POLICY_DENIED":
            denying_hop_details = {
                "denying_hop_index": sim_res.denying_hop_index,
                "denying_hop_from": sim_res.denying_hop_from,
                "denying_hop_to": sim_res.denying_hop_to,
                "denying_action": sim_res.denying_action,
                "denying_reason_type": sim_res.denying_reason_type,
            }

        path_limitations = list(queued_path.path.limitations)
        if sim_res:
            path_limitations.extend(sim_res.limitations)
        if "local_evaluator, not AWS" not in path_limitations:
            path_limitations.append("local_evaluator, not AWS")

        sim_result_str = "ALLOWED"
        if sim_res and sim_res.status == "POLICY_DENIED":
            sim_result_str = "DENIED"

        return PathEvidence(
            path_id=queued_path.path_id,
            policy_simulator_result=sim_result_str,
            policy_simulator_source=sim_res.source if sim_res else "local_evaluator",
            simulator_mode="MOCKED",
            policy_simulator_details=sim_details,
            denying_hop_details=denying_hop_details,
            sandbox_scenario_name=sb_res.sandbox_scenario_name if sb_res else None,
            sandbox_attempted=sb_res.sandbox_attempted if sb_res else False,
            sandbox_execution_success=sb_res.sandbox_execution_success if sb_res else None,
            sandbox_failure_reason=(sb_res.reason if sb_res and not sb_res.sandbox_execution_success else None),
            sandbox_logs=sb_res.sandbox_logs if sb_res else [],
            sandbox_logs_redacted=True,
            sandbox_evidence_ref=sb_res.sandbox_evidence_ref if sb_res else None,
            sandbox_mode="MOCKED",
            hops_formatted=hops_formatted,
            limitations=list(set(path_limitations)),
        )


# Alias for canonical pipeline stage naming
Stage6Evidence = Stage6EvidenceAggregator
