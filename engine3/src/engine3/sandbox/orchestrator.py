"""Branch-Walking Orchestrator for Attack-Path Sandbox Execution.

Executes a branch's hop sequence in order, resolving actions to pathfinding.cloud module IDs,
driving Pathrunner modules, verifying post-hop identity transitions, and stopping on any failure.
"""

from typing import Any, ClassVar
from pydantic import BaseModel, Field

from engine3.sandbox.terraform_generator import BranchJSON, BranchHop


class HopResult(BaseModel):
    from_node: str
    to_node: str
    action_used: str
    matched_rule_id: str | None = None
    result: str  # success, policy_denied, sandbox_failed, goal_reached


class OrchestratorRunResult(BaseModel):
    branch_id: str
    status: str  # VERIFIED_EXPLOITABLE, POLICY_DENIED, SANDBOX_FAILED
    hops: list[HopResult] = Field(default_factory=list)
    final_identity: str
    logs: list[str] = Field(default_factory=list)
    reason: str = ""
    verification_source: str = "MOCK"  # "REAL" or "MOCK"


from engine3.sandbox.module_resolver import PathrunnerModuleResolver
from engine3.sandbox.pathrunner_client import PathrunnerClient, MockPathrunnerClient, ModuleResult


class BranchOrchestrator:
    """Walks an attack-path branch's hops, executing modules and verifying identity switches."""

    def __init__(
        self,
        client: PathrunnerClient | None = None,
        resolver: PathrunnerModuleResolver | None = None,
    ) -> None:
        if resolver is None:
            resolver = PathrunnerModuleResolver()
        if client is None:
            client = MockPathrunnerClient()
        self.resolver = resolver
        self.client = client

    def resolve_module_id(self, action: str | list[str], matched_rule_id: str | None = None) -> str | None:
        """Resolves module ID using dynamic rulebook index with primary rule_id lookup."""
        return self.resolver.resolve_hop(matched_rule_id=matched_rule_id, action=action)

    def execute_branch(
        self, branch: BranchJSON, initial_credentials: dict[str, str] | None = None
    ) -> OrchestratorRunResult:
        logs: list[str] = []
        hop_results: list[HopResult] = []

        if not branch.hops:
            return OrchestratorRunResult(
                branch_id=branch.branch_id,
                status="SANDBOX_FAILED",
                hops=[],
                final_identity="unknown",
                logs=["Branch contains no hops to execute."],
                reason="empty_branch",
                verification_source="MOCK" if isinstance(self.client, MockPathrunnerClient) else "REAL",
            )

        current_identity = branch.hops[0].source
        current_creds: dict[str, str] | None = initial_credentials
        client_verification_source = "MOCK" if isinstance(self.client, MockPathrunnerClient) else "REAL"

        logs.append(f"Starting branch {branch.branch_id} execution with initial identity: {current_identity}")

        total_hops = len(branch.hops)
        for idx, hop in enumerate(branch.hops):
            is_goal_hop = (idx == total_hops - 1) and (
                "getobject" in str(hop.action).lower() or "read" in branch.goal.lower()
            )
            action_str = "+".join(hop.actions_list) if isinstance(hop.action, list) else hop.action

            logs.append(f"--- Hop {idx+1}/{total_hops}: {hop.source} -> {hop.target} (Action: {action_str}) ---")

            # 1. Post-hop Identity Verification
            if current_identity != hop.source:
                mismatch_msg = (
                    f"Identity mismatch at hop {idx+1}: expected source '{hop.source}', "
                    f"but current identity is '{current_identity}'"
                )
                logs.append(f"[FAIL] {mismatch_msg}")
                hop_results.append(
                    HopResult(
                        from_node=hop.source,
                        to_node=hop.target,
                        action_used=action_str,
                        matched_rule_id=None,
                        result="sandbox_failed",
                    )
                )
                return OrchestratorRunResult(
                    branch_id=branch.branch_id,
                    status="SANDBOX_FAILED",
                    hops=hop_results,
                    final_identity=current_identity,
                    logs=logs,
                    reason=mismatch_msg,
                    verification_source=client_verification_source,
                )

            # 2. Module Resolution (direct primary/secondary rulebook index)
            module_id = self.resolve_module_id(hop.action) if not is_goal_hop else None
            logs.append(f"Resolved module ID for action '{action_str}': {module_id or '(goal direct call)'}")

            # 3. Pathrunner Client Execution
            options = {
                "target": hop.target,
                "principal": current_identity,
                "action": action_str,
            }

            mod_res: ModuleResult = self.client.run_module(
                module_id=module_id or "generic-target-action",
                options=options,
                credentials=current_creds,
            )

            client_verification_source = mod_res.verification_source
            if mod_res.stdout:
                logs.append(mod_res.stdout)
            if mod_res.stderr:
                logs.append(f"[STDERR] {mod_res.stderr}")

            # 4. Handle Failure Cases
            if not mod_res.success:
                is_policy_denial = (
                    mod_res.exit_code == 2
                    or "denied" in mod_res.stderr.lower()
                    or "denied" in mod_res.stdout.lower()
                )
                res_status = "POLICY_DENIED" if is_policy_denial else "SANDBOX_FAILED"
                hop_result_type = "policy_denied" if is_policy_denial else "sandbox_failed"
                failure_reason = (
                    f"Hop {idx+1} policy denial during execution"
                    if is_policy_denial
                    else f"Pathrunner module execution failed at hop {idx+1} (exit code {mod_res.exit_code})"
                )

                logs.append(f"[{res_status}] {failure_reason}")
                hop_results.append(
                    HopResult(
                        from_node=hop.source,
                        to_node=hop.target,
                        action_used=action_str,
                        matched_rule_id=module_id,
                        result=hop_result_type,
                    )
                )
                return OrchestratorRunResult(
                    branch_id=branch.branch_id,
                    status=res_status,
                    hops=hop_results,
                    final_identity=current_identity,
                    logs=logs,
                    reason=failure_reason,
                    verification_source=client_verification_source,
                )

            # 5. Handle Success & Credential Transition
            # Credentials come ONLY from ModuleResult.captured_credentials; if a module doesn't yield any on intermediate hop, the chain stops.
            if not is_goal_hop and idx < total_hops - 1:
                if not mod_res.captured_credentials:
                    fail_msg = (
                        f"Hop {idx+1} ({module_id}) succeeded but yielded no captured credentials to assume target '{hop.target}'. Chain halted."
                    )
                    logs.append(f"[FAIL] {fail_msg}")
                    hop_results.append(
                        HopResult(
                            from_node=hop.source,
                            to_node=hop.target,
                            action_used=action_str,
                            matched_rule_id=module_id,
                            result="sandbox_failed",
                        )
                    )
                    return OrchestratorRunResult(
                        branch_id=branch.branch_id,
                        status="SANDBOX_FAILED",
                        hops=hop_results,
                        final_identity=current_identity,
                        logs=logs,
                        reason=fail_msg,
                        verification_source=client_verification_source,
                    )
                current_creds = mod_res.captured_credentials

            res_type = "goal_reached" if is_goal_hop else "success"
            hop_results.append(
                HopResult(
                    from_node=hop.source,
                    to_node=hop.target,
                    action_used=action_str,
                    matched_rule_id=module_id,
                    result=res_type,
                )
            )

            logs.append(
                f"[SUCCESS] Hop {idx+1} succeeded. Switched identity from '{current_identity}' -> '{hop.target}'"
            )
            current_identity = hop.target

        logs.append(f"Branch {branch.branch_id} executed successfully to goal.")
        return OrchestratorRunResult(
            branch_id=branch.branch_id,
            status="VERIFIED_EXPLOITABLE",
            hops=hop_results,
            final_identity=current_identity,
            logs=logs,
            reason="All hops verified and goal reached successfully",
            verification_source=client_verification_source,
        )
