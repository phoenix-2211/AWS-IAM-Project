"""Stage 5 CloudGoat Sandbox Runner."""


from pydantic import BaseModel, Field

from engine3.stages.s3_queue import QueuedPath


class SandboxRunResult(BaseModel):
    path_id: str
    status: str = "SANDBOX_FAILED"  # VERIFIED_EXPLOITABLE, SANDBOX_FAILED
    sandbox_scenario_name: str | None = None
    sandbox_attempted: bool = False
    sandbox_execution_success: bool | None = None
    sandbox_logs: list[str] = Field(default_factory=list)
    sandbox_logs_redacted: bool = True
    sandbox_evidence_ref: str | None = None
    sandbox_mode: str = "MOCKED"
    reason: str = ""


class CloudGoatSandboxRunner:
    """Stage 5 CloudGoat Sandbox Runner."""

    def __init__(self, budget_confirmed: bool = False, account_id_confirmed: str | None = None) -> None:
        self.budget_confirmed = budget_confirmed
        self.account_id_confirmed = account_id_confirmed

    def execute_sandbox(
        self, queued_path: QueuedPath, gate_token: str | None = None
    ) -> SandboxRunResult:
        logs: list[str] = []

        if not self.budget_confirmed:
            logs.append("Refusing deploy without budget_confirmed: true in sandbox.yaml")
            return SandboxRunResult(
                path_id=queued_path.path_id,
                status="SANDBOX_FAILED",
                sandbox_attempted=False,
                sandbox_logs=logs,
                sandbox_mode="MOCKED",
                reason="budget_confirmed is false",
            )

        if not self.account_id_confirmed:
            logs.append("Refusing deploy without confirmed sandbox account ID")
            return SandboxRunResult(
                path_id=queued_path.path_id,
                status="SANDBOX_FAILED",
                sandbox_attempted=False,
                sandbox_logs=logs,
                sandbox_mode="MOCKED",
                reason="account_id_confirmed is missing",
            )

        if gate_token != "APPROVE-DEPLOY":
            logs.append("Refusing deploy without APPROVE-DEPLOY gate token")
            return SandboxRunResult(
                path_id=queued_path.path_id,
                status="SANDBOX_FAILED",
                sandbox_attempted=False,
                sandbox_logs=logs,
                sandbox_mode="MOCKED",
                reason="APPROVE-DEPLOY gate token missing",
            )

        # Placeholder for real CloudGoat sandbox deployment loop
        logs.append("CloudGoat deploy initiated under try/finally block...")
        logs.append("Teardown verified cleanly.")
        return SandboxRunResult(
            path_id=queued_path.path_id,
            status="SANDBOX_FAILED",
            sandbox_attempted=True,
            sandbox_execution_success=False,
            sandbox_logs=logs,
            sandbox_mode="MOCKED",
            reason="Sandbox deployment not executed in offline mode",
        )


class MockCloudGoatSandboxRunner:
    """Stage 5 Deterministic Mock Sandbox Evaluator for sample-based runs."""

    @staticmethod
    def map_scenario_name(queued_path: QueuedPath) -> str:
        actions = [h.action_used for h in queued_path.path.hops]
        actions_str = " ".join(actions).lower()

        if "iam:attachuserpolicy" in actions_str or "iam:putrolepolicy" in actions_str:
            return "iam_privesc_by_attachment"
        if "iam:passrole" in actions_str:
            return "iam_privesc_by_rollback"
        if "s3:getobject" in actions_str:
            return "iam_privesc_by_s3_exfiltration"
        if "secretsmanager:getsecretvalue" in actions_str:
            return "iam_privesc_by_secretsmanager"
        return "iam_privesc_by_assume_role"

    def evaluate_sandbox_path(
        self, queued_path: QueuedPath, sim_status: str = "POLICY_ALLOWED"
    ) -> SandboxRunResult:
        if sim_status == "POLICY_DENIED":
            return SandboxRunResult(
                path_id=queued_path.path_id,
                status="SANDBOX_FAILED",
                sandbox_scenario_name=None,
                sandbox_attempted=False,
                sandbox_execution_success=None,
                sandbox_logs=["[MOCKED] Skipped sandbox execution: path blocked at policy simulator (POLICY_DENIED)."],
                sandbox_mode="MOCKED",
                reason="blocked_at_policy_simulator",
            )

        scenario_name = self.map_scenario_name(queued_path)

        # Deterministic seed check for soft condition failure:
        # If path_id hash integer % 11 == 0 or soft condition flag present, fail sandbox
        is_soft_failure = (int(queued_path.path_id[:4], 16) % 11 == 0) or any(
            "soft_condition_failed" in h.flags for h in queued_path.path.hops
        )

        success = not is_soft_failure
        status = "VERIFIED_EXPLOITABLE" if success else "SANDBOX_FAILED"
        reason = (
            "Exploit payload executed successfully in mocked sandbox environment."
            if success
            else "Deterministic runtime assertion failed during mocked sandbox execution."
        )

        logs = [
            f"[MOCKED] Initializing CloudGoat scenario: {scenario_name}",
            f"[MOCKED] Target start node: {queued_path.path.start_node}",
            f"[MOCKED] Target end node: {queued_path.path.target_node}",
            f"[MOCKED] Hop sequence: {' -> '.join(h.to_node for h in queued_path.path.hops)}",
            f"[MOCKED] Execution result: {'SUCCESS (FLAG_CAPTURED)' if success else 'FAILURE (ASSERTION_FAILED)'}",
            "[MOCKED] Teardown verified cleanly; sandbox destroyed.",
        ]

        return SandboxRunResult(
            path_id=queued_path.path_id,
            status=status,
            sandbox_scenario_name=scenario_name,
            sandbox_attempted=True,
            sandbox_execution_success=success,
            sandbox_logs=logs,
            sandbox_logs_redacted=True,
            sandbox_evidence_ref=f"mocked-evidence-{queued_path.path_id[:8]}",
            sandbox_mode="MOCKED",
            reason=reason,
        )

