"""Stage 7 Verification Decision Engine."""

from pydantic import BaseModel
from engine3.s4_policy_verification import PathSimResult
from engine3.s5_sandbox import SandboxRunResult
from engine3.s6_evidence import PathEvidence


class VerificationDecision(BaseModel):
    status: str
    confidence_tier: str
    status_reason: str
    verification_scope: str


class Stage7DecisionEngine:
    """Evaluates evidence to determine the final 5-status verification decision."""

    def evaluate_decision(
        self,
        sim_res: PathSimResult | None = None,
        sb_res: SandboxRunResult | None = None,
        evidence: PathEvidence | None = None,
    ) -> VerificationDecision:
        # Extract simulation status
        sim_status = sim_res.status if sim_res else None
        if not sim_status and evidence:
            sim_status = "POLICY_DENIED" if evidence.policy_simulator_result == "DENIED" else "POLICY_ALLOWED"

        # Extract sandbox fields
        sb_scenario = sb_res.sandbox_scenario_name if sb_res else (evidence.sandbox_scenario_name if evidence else None)
        sb_attempted = sb_res.sandbox_attempted if sb_res else (evidence.sandbox_attempted if evidence else False)
        sb_success = sb_res.sandbox_execution_success if sb_res else (evidence.sandbox_execution_success if evidence else None)
        sb_status = sb_res.status if sb_res else None

        # 1. POLICY_DENIED
        if sim_status == "POLICY_DENIED":
            reason = sim_res.status_reason if sim_res else "Path blocked by explicit or implicit policy denial."
            return VerificationDecision(
                status="POLICY_DENIED",
                confidence_tier="POLICY_DENIED",
                status_reason=reason,
                verification_scope="policy_simulated_only",
            )

        # 2. PARTIAL_CHAIN_VERIFIED
        if sim_status == "PARTIAL_CHAIN_VERIFIED":
            return VerificationDecision(
                status="PARTIAL_CHAIN_VERIFIED",
                confidence_tier="PARTIAL_CHAIN_VERIFIED",
                status_reason="Multi-hop path partially verified; one or more hops skipped due to technical limitation.",
                verification_scope="policy_simulated_only",
            )

        # 3. POLICY_VERIFIED_NO_SANDBOX (all policy hops allowed, but no sandbox scenario/module mapped)
        if sim_status == "POLICY_ALLOWED" and (sb_scenario is None or not sb_scenario):
            return VerificationDecision(
                status="POLICY_VERIFIED_NO_SANDBOX",
                confidence_tier="POLICY_VERIFIED_NO_SANDBOX",
                status_reason="All policy hops allowed by simulator, but no matching CloudGoat/Pathrunner sandbox scenario is available for live execution.",
                verification_scope="policy_simulated_only",
            )

        # 4. VERIFIED_EXPLOITABLE (all policy hops allowed, scenario mapped, execution succeeded)
        if (sb_status == "VERIFIED_EXPLOITABLE" or sb_success is True) and sb_scenario is not None:
            return VerificationDecision(
                status="VERIFIED_EXPLOITABLE",
                confidence_tier="FULL_CHAIN_VERIFIED",
                status_reason="Every hop policy-checked and exploit successfully verified in sandbox.",
                verification_scope="live_verified",
            )

        # 5. SANDBOX_FAILED (all policy hops allowed, scenario attempted, but execution failed)
        if sb_attempted:
            reason = (sb_res.reason if sb_res else None) or (evidence.sandbox_failure_reason if evidence else None) or "Sandbox execution attempted but failed."
            return VerificationDecision(
                status="SANDBOX_FAILED",
                confidence_tier="SANDBOX_EXECUTION_FAILED",
                status_reason=reason,
                verification_scope="sandbox_attempted",
            )

        # Default fallback
        return VerificationDecision(
            status="SANDBOX_FAILED",
            confidence_tier="SANDBOX_EXECUTION_FAILED",
            status_reason="Path unverified against live policy simulator or sandbox.",
            verification_scope="policy_simulated_only",
        )


# Alias for canonical pipeline stage naming
Stage7Decision = Stage7DecisionEngine
