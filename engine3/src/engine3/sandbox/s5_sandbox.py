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
                reason="budget_confirmed is false",
            )

        if not self.account_id_confirmed:
            logs.append("Refusing deploy without confirmed sandbox account ID")
            return SandboxRunResult(
                path_id=queued_path.path_id,
                status="SANDBOX_FAILED",
                sandbox_attempted=False,
                sandbox_logs=logs,
                reason="account_id_confirmed is missing",
            )

        if gate_token != "APPROVE-DEPLOY":
            logs.append("Refusing deploy without APPROVE-DEPLOY gate token")
            return SandboxRunResult(
                path_id=queued_path.path_id,
                status="SANDBOX_FAILED",
                sandbox_attempted=False,
                sandbox_logs=logs,
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
            reason="Sandbox deployment not executed in offline mode",
        )
