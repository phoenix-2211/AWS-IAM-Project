"""Stage 4 Policy Simulator Backend & Evaluator."""

import json
import os
from pathlib import Path

from pydantic import BaseModel, Field

from engine3.stages.s3_queue import QueuedPath


class HopSimResult(BaseModel):
    hop_index: int
    decision: str  # ALLOWED, DENIED, UNKNOWN
    eval_decision: str  # allowed, explicitDeny, implicitDeny
    missing_context: list[str] = Field(default_factory=list)
    note: str = ""
    raw_ref: str | None = None


class PathSimResult(BaseModel):
    path_id: str
    status: str  # POLICY_ALLOWED, POLICY_DENIED
    status_reason: str
    hop_results: list[HopSimResult] = Field(default_factory=list)
    source: str = "local_evaluator"
    limitations: list[str] = Field(default_factory=list)


class Stage4SimResult(BaseModel):
    results: list[PathSimResult] = Field(default_factory=list)
    policy_sim_backend: str = "local_evaluator"
    policy_sim_timing_representative: bool = False
    policy_sim_time_ms: float | None = None


class LocalPolicySimulator:
    """Offline Local Policy Simulator implementation."""

    def __init__(self, fixtures_dir: Path | None = None) -> None:
        if fixtures_dir is None:
            fixtures_dir = Path(__file__).parents[3] / "fixtures" / "simulator"
        self.fixtures_dir = fixtures_dir

    def evaluate_path(self, queued_path: QueuedPath) -> PathSimResult:
        hops = queued_path.path.hops
        hop_results: list[HopSimResult] = []
        path_denied = False
        denying_hop_idx = -1

        for idx, hop in enumerate(hops):
            # Trust hops checked structurally
            if hop.edge_type == "TRUSTED_BY":
                hop_results.append(
                    HopSimResult(
                        hop_index=idx,
                        decision="ALLOWED",
                        eval_decision="allowed",
                        note="Trust checked structurally, simulator does not evaluate trust policies",
                    )
                )
                continue

            # Load offline evaluator response if available
            resp_file = self.fixtures_dir / f"hop_{idx}.json"
            if resp_file.exists():
                with open(resp_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                eval_dec = data.get("EvalDecision", "allowed")
                missing = data.get("MissingContextKeys", [])
            else:
                # Default local evaluator response
                eval_dec = "allowed"
                missing = []

            if eval_dec == "allowed":
                hop_results.append(
                    HopSimResult(
                        hop_index=idx,
                        decision="ALLOWED",
                        eval_decision=eval_dec,
                        missing_context=missing,
                        raw_ref=str(resp_file) if resp_file.exists() else None,
                    )
                )
            else:
                path_denied = True
                denying_hop_idx = idx
                hop_results.append(
                    HopSimResult(
                        hop_index=idx,
                        decision="DENIED",
                        eval_decision=eval_dec,
                        missing_context=missing,
                        raw_ref=str(resp_file) if resp_file.exists() else None,
                    )
                )

        if path_denied:
            return PathSimResult(
                path_id=queued_path.path_id,
                status="POLICY_DENIED",
                status_reason=f"Hop {denying_hop_idx} denied by simulator",
                hop_results=hop_results,
                source="local_evaluator",
                limitations=["local_evaluator, not AWS"],
            )

        return PathSimResult(
            path_id=queued_path.path_id,
            status="POLICY_ALLOWED",
            status_reason="Simulator allowed every hop; trust structurally satisfied; no sandbox run.",
            hop_results=hop_results,
            source="local_evaluator",
            limitations=[
                "local_evaluator, not AWS",
                "Offline local evaluation, not independent verification",
                "SCP/RCP/Resource policies not evaluated",
            ],
        )


class LivePolicySimulator:
    """Live Policy Simulator wrapper requiring safety gate approval."""

    def evaluate_path(self, queued_path: QueuedPath, gate_token: str | None = None, aws_profile: str | None = None) -> PathSimResult:
        if gate_token != "APPROVE-LIVE-SIM":
            raise PermissionError("Refusing live AWS simulator call without APPROVE-LIVE-SIM gate token")
        if not aws_profile and not os.environ.get("AWS_PROFILE"):
            raise ValueError("Refusing live AWS simulator call without valid named AWS profile")

        # Boto3 client invocation placeholder for when gate is provided
        raise NotImplementedError("Live AWS API simulator call requires active AWS credentials environment")
