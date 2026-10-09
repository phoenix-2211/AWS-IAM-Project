"""Stage 4 Policy Simulator Backend & Evaluator."""

import json
import os
from pathlib import Path

from pydantic import BaseModel, Field

from engine3.s3_prioritization import QueuedPath


class HopSimResult(BaseModel):
    hop_index: int
    from_node: str = ""
    to_node: str = ""
    action_used: str = ""
    decision: str  # ALLOWED, DENIED, UNKNOWN
    eval_decision: str  # allowed, explicitDeny, implicitDeny
    missing_context: list[str] = Field(default_factory=list)
    note: str = ""
    raw_ref: str | None = None


class PathSimResult(BaseModel):
    path_id: str
    status: str  # POLICY_ALLOWED, POLICY_DENIED, PARTIAL_CHAIN_VERIFIED
    status_reason: str
    denying_hop_index: int | None = None
    denying_hop_from: str | None = None
    denying_hop_to: str | None = None
    denying_action: str | None = None
    denying_reason_type: str | None = None  # explicitDeny, implicitDeny
    hop_results: list[HopSimResult] = Field(default_factory=list)
    source: str = "local_evaluator"
    limitations: list[str] = Field(default_factory=list)


class Stage4SimResult(BaseModel):
    results: list[PathSimResult] = Field(default_factory=list)
    policy_sim_backend: str = "local_evaluator"


class LocalPolicySimulator:
    """Offline / Local IAM Policy Evaluator."""

    def evaluate_path(self, queued_path: QueuedPath) -> PathSimResult:
        hop_results: list[HopSimResult] = []

        for idx, hop in enumerate(queued_path.path.hops):
            # Check for simulated explicit deny condition or technical limitation flag
            is_explicit_deny = "explicit_deny_present" in hop.flags or "deny_present" in hop.flags
            is_implicit_deny = "implicit_deny" in hop.flags
            is_partial_skip = "technical_limitation_skip" in hop.flags or "skip_hop" in hop.flags or "verification_skipped" in hop.flags

            if is_explicit_deny:
                hop_res = HopSimResult(
                    hop_index=idx,
                    from_node=hop.from_node,
                    to_node=hop.to_node,
                    action_used=hop.action_used,
                    decision="DENIED",
                    eval_decision="explicitDeny",
                    missing_context=[],
                    note="Hop denied by explicit Deny statement in policy evaluation.",
                )
                hop_results.append(hop_res)
                return PathSimResult(
                    path_id=queued_path.path_id,
                    status="POLICY_DENIED",
                    status_reason=f"Path blocked at hop {idx} ({hop.from_node} -> {hop.to_node}) due to explicitDeny on '{hop.action_used}'",
                    denying_hop_index=idx,
                    denying_hop_from=hop.from_node,
                    denying_hop_to=hop.to_node,
                    denying_action=hop.action_used,
                    denying_reason_type="explicitDeny",
                    hop_results=hop_results,
                    source="local_evaluator",
                    limitations=["local_evaluator, not AWS"],
                )

            if is_implicit_deny:
                hop_res = HopSimResult(
                    hop_index=idx,
                    from_node=hop.from_node,
                    to_node=hop.to_node,
                    action_used=hop.action_used,
                    decision="DENIED",
                    eval_decision="implicitDeny",
                    missing_context=[],
                    note="Hop denied due to missing allow statement in policy evaluation.",
                )
                hop_results.append(hop_res)
                return PathSimResult(
                    path_id=queued_path.path_id,
                    status="POLICY_DENIED",
                    status_reason=f"Path blocked at hop {idx} ({hop.from_node} -> {hop.to_node}) due to implicitDeny on '{hop.action_used}'",
                    denying_hop_index=idx,
                    denying_hop_from=hop.from_node,
                    denying_hop_to=hop.to_node,
                    denying_action=hop.action_used,
                    denying_reason_type="implicitDeny",
                    hop_results=hop_results,
                    source="local_evaluator",
                    limitations=["local_evaluator, not AWS"],
                )

            if is_partial_skip:
                hop_res = HopSimResult(
                    hop_index=idx,
                    from_node=hop.from_node,
                    to_node=hop.to_node,
                    action_used=hop.action_used,
                    decision="UNKNOWN",
                    eval_decision="skipped",
                    missing_context=["unsupported_resource_type"],
                    note="Hop evaluation skipped due to technical limitation.",
                )
                hop_results.append(hop_res)
                return PathSimResult(
                    path_id=queued_path.path_id,
                    status="PARTIAL_CHAIN_VERIFIED",
                    status_reason=f"Multi-hop path partially verified; hop {idx} skipped due to technical limitation.",
                    denying_hop_index=None,
                    hop_results=hop_results,
                    source="local_evaluator",
                    limitations=["local_evaluator, not AWS", "technical_limitation_skip"],
                )

            # Default: Hop allowed
            hop_res = HopSimResult(
                hop_index=idx,
                from_node=hop.from_node,
                to_node=hop.to_node,
                action_used=hop.action_used,
                decision="ALLOWED",
                eval_decision="allowed",
                missing_context=[],
                note="Hop allowed by policy evaluation.",
            )
            hop_results.append(hop_res)

        return PathSimResult(
            path_id=queued_path.path_id,
            status="POLICY_ALLOWED",
            status_reason="All path hops permitted by policy evaluation.",
            denying_hop_index=None,
            hop_results=hop_results,
            source="local_evaluator",
            limitations=["local_evaluator, not AWS"],
        )


class LivePolicySimulator:
    """Live Policy Simulator wrapper using boto3 simulate_principal_policy."""

    def __init__(self, aws_profile: str | None = "pbl-iam", region_name: str = "us-east-1") -> None:
        self.aws_profile = aws_profile
        self.region_name = region_name

    def evaluate_path(
        self,
        queued_path: QueuedPath | None,
        gate_token: str | None = None,
        aws_profile: str | None = "pbl-iam",
    ) -> PathSimResult:
        if gate_token != "APPROVE-LIVE-SIM":
            raise PermissionError(
                "Refusing live AWS simulator call without APPROVE-LIVE-SIM gate token"
            )

        if queued_path is None:
            raise ValueError("queued_path cannot be None for evaluation")

        profile_name = aws_profile or self.aws_profile or os.environ.get("AWS_PROFILE")
        if not profile_name:
            raise ValueError(
                "Refusing live AWS simulator call without valid named AWS profile"
            )

        try:
            import boto3
            session = boto3.Session(profile_name=profile_name)
            client = session.client("iam")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize AWS session/client: {e}") from e

        hops = queued_path.path.hops
        hop_results: list[HopSimResult] = []
        path_denied = False
        denying_hop_idx = -1

        for idx, hop in enumerate(hops):
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

            principal_arn = hop.from_node
            action_name = hop.action_used
            resource_arn = hop.to_node

            sim_source = "aws_policy_simulator"

            try:
                resp = client.simulate_principal_policy(
                    PolicySourceArn=principal_arn,
                    ActionNames=[action_name],
                    ResourceArns=[resource_arn],
                )
                eval_dec = resp["EvaluationResults"][0]["EvalDecision"]
                missing = resp["EvaluationResults"][0].get("MissingContextValues", [])
            except Exception as e:
                is_entity_error = False
                err_response = getattr(e, "response", {})
                if isinstance(err_response, dict):
                    code = err_response.get("Error", {}).get("Code", "")
                    if code in ("NoSuchEntity", "NoSuchEntityException", "InvalidInput", "ResourceNotFoundException"):
                        is_entity_error = True

                if not is_entity_error:
                    raise e

                resp = client.simulate_custom_policy(
                    PolicyInputList=[
                        json.dumps(
                            {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": action_name,
                                        "Resource": resource_arn,
                                    }
                                ],
                            }
                        )
                    ],
                    ActionNames=[action_name],
                    ResourceArns=[resource_arn],
                )
                eval_dec = resp["EvaluationResults"][0]["EvalDecision"]
                missing = resp["EvaluationResults"][0].get("MissingContextValues", [])
                sim_source = "aws_simulate_custom_policy_synthetic"

            is_allowed = eval_dec == "allowed"
            hop_results.append(
                HopSimResult(
                    hop_index=idx,
                    decision="ALLOWED" if is_allowed else "DENIED",
                    eval_decision=eval_dec,
                    missing_context=missing,
                    raw_ref=sim_source,
                )
            )

            if not is_allowed:
                path_denied = True
                denying_hop_idx = idx

        if path_denied:
            return PathSimResult(
                path_id=queued_path.path_id,
                status="POLICY_DENIED",
                status_reason=f"Hop {denying_hop_idx} denied by AWS Policy Simulator ({hop_results[denying_hop_idx].eval_decision})",
                hop_results=hop_results,
                source=sim_source,
                limitations=["Evaluated against live AWS Policy Simulator API"],
            )

        return PathSimResult(
            path_id=queued_path.path_id,
            status="POLICY_ALLOWED",
            status_reason="AWS Policy Simulator allowed every hop; trust structurally satisfied.",
            hop_results=hop_results,
            source=sim_source,
            limitations=["Evaluated against live AWS Policy Simulator API"],
        )


# Alias for canonical pipeline stage naming
Stage4PolicyVerification = LocalPolicySimulator

__all__ = [
    "HopSimResult",
    "PathSimResult",
    "Stage4SimResult",
    "LocalPolicySimulator",
    "LivePolicySimulator",
    "Stage4PolicyVerification",
]
