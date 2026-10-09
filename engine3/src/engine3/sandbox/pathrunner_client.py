"""Pathrunner Client implementations for Stage 5 Sandbox Execution.

Provides abstract PathrunnerClient, SubprocessPathrunnerClient (real subprocess execution),
and MockPathrunnerClient (explicitly tagged mock for unit testing).
"""

import json
import os
import subprocess
import time
from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel, Field


class ModuleResult(BaseModel):
    """Result of a single Pathrunner module execution."""

    success: bool
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    captured_credentials: dict[str, str] | None = None
    duration_ms: float = 0.0
    verification_source: str = "REAL"  # "REAL" or "MOCK"


class PathrunnerClient(ABC):
    """Abstract interface for Pathrunner module execution."""

    @abstractmethod
    def run_module(
        self,
        module_id: str,
        options: dict[str, Any],
        credentials: dict[str, str] | None = None,
    ) -> ModuleResult:
        """Runs a Pathrunner module with supplied options and credentials."""
        pass


class SubprocessPathrunnerClient(PathrunnerClient):
    """Real Pathrunner client executing module subprocesses with scrubbed environment and timeout."""

    ALLOWED_ACCOUNTS: list[str] = ["111122223333", "sandbox-dev-account"]

    def __init__(
        self,
        executable_path: str = "pathrunner",
        timeout_seconds: int = 30,
        budget_confirmed: bool = False,
        account_id_confirmed: str | None = None,
        gate_token: str | None = None,
    ) -> None:
        self.executable_path = executable_path
        self.timeout_seconds = timeout_seconds
        self.budget_confirmed = budget_confirmed
        self.account_id_confirmed = account_id_confirmed
        self.gate_token = gate_token

    def build_argv(self, module_id: str, options: dict[str, Any]) -> list[str]:
        """Constructs safe argv argument list without shell expansion."""
        argv = [self.executable_path, "run", "--module", module_id]
        for key, val in sorted(options.items()):
            argv.extend([f"--{key.lower()}", str(val)])
        return argv

    def run_module(
        self,
        module_id: str,
        options: dict[str, Any],
        credentials: dict[str, str] | None = None,
    ) -> ModuleResult:
        # Strict Safety Gates Enforced BEFORE any subprocess execution
        if not self.budget_confirmed:
            raise PermissionError("SubprocessPathrunnerClient: budget_confirmed must be True")

        if not self.account_id_confirmed:
            raise PermissionError("SubprocessPathrunnerClient: account_id_confirmed missing")

        if self.account_id_confirmed not in self.ALLOWED_ACCOUNTS:
            raise PermissionError(
                f"SubprocessPathrunnerClient: account '{self.account_id_confirmed}' is not in ALLOWED_ACCOUNTS"
            )

        if self.gate_token != "APPROVE-DEPLOY":
            raise PermissionError("SubprocessPathrunnerClient: APPROVE-DEPLOY gate token missing")

        t0 = time.time()
        argv = self.build_argv(module_id, options)

        # Scrub environment: only pass safe system paths and explicitly provided AWS credentials
        clean_env: dict[str, str] = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "TEMP": os.environ.get("TEMP", ""),
        }
        if credentials:
            if "access_key_id" in credentials:
                clean_env["AWS_ACCESS_KEY_ID"] = credentials["access_key_id"]
            if "secret_access_key" in credentials:
                clean_env["AWS_SECRET_ACCESS_KEY"] = credentials["secret_access_key"]
            if "session_token" in credentials:
                clean_env["AWS_SESSION_TOKEN"] = credentials["session_token"]
            if "region" in credentials:
                clean_env["AWS_DEFAULT_REGION"] = credentials["region"]

        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
                env=clean_env,
            )
            duration = (time.time() - t0) * 1000.0

            captured_creds: dict[str, str] | None = None
            if proc.stdout and "CAPTURED_CREDENTIALS_JSON:" in proc.stdout:
                try:
                    payload = proc.stdout.split("CAPTURED_CREDENTIALS_JSON:")[1].strip().split("\n")[0]
                    captured_creds = json.loads(payload)
                except Exception:
                    captured_creds = None

            return ModuleResult(
                success=(proc.returncode == 0),
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                captured_credentials=captured_creds,
                duration_ms=duration,
                verification_source="REAL",
            )

        except subprocess.TimeoutExpired as te:
            return ModuleResult(
                success=False,
                exit_code=-1,
                stdout=te.stdout or "",
                stderr=f"Pathrunner module '{module_id}' timed out after {self.timeout_seconds}s",
                captured_credentials=None,
                duration_ms=(time.time() - t0) * 1000.0,
                verification_source="REAL",
            )
        except Exception as e:
            return ModuleResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                captured_credentials=None,
                duration_ms=(time.time() - t0) * 1000.0,
                verification_source="REAL",
            )


class MockPathrunnerClient(PathrunnerClient):
    """Deterministic Mock Pathrunner client used ONLY for unit testing and offline verification."""

    def __init__(self, failure_modules: set[str] | None = None) -> None:
        self.failure_modules = failure_modules or set()

    def run_module(
        self,
        module_id: str,
        options: dict[str, Any],
        credentials: dict[str, str] | None = None,
    ) -> ModuleResult:
        t0 = time.time()
        target = options.get("target", "target-entity")

        if module_id in self.failure_modules:
            return ModuleResult(
                success=False,
                exit_code=1,
                stdout=f"[MOCK] Pathrunner module {module_id} simulated execution failure on target {target}",
                stderr="[MOCK] Runtime simulation failure",
                captured_credentials=None,
                duration_ms=(time.time() - t0) * 1000.0,
                verification_source="MOCK",
            )

        # Simulate captured credentials for credential-yielding techniques
        captured_creds: dict[str, str] | None = None
        if any(module_id.startswith(pfx) for pfx in ("iam-", "sts-", "ec2-", "lambda-", "glue-")):
            captured_creds = {
                "access_key_id": f"ASIA_MOCK_{target.replace(':', '_').replace('/', '_').upper()}",
                "secret_access_key": f"mock_secret_for_{target.lower()}",
                "session_token": f"mock_session_token_{module_id}",
            }

        stdout_log = (
            f"[MOCK] Pathrunner `use {module_id}`\n"
            f"[MOCK] Pathrunner `set TARGET {target}`\n"
            f"[MOCK] Pathrunner `exploit` -> SUCCESS"
        )

        return ModuleResult(
            success=True,
            exit_code=0,
            stdout=stdout_log,
            stderr="",
            captured_credentials=captured_creds,
            duration_ms=(time.time() - t0) * 1000.0,
            verification_source="MOCK",
        )


__all__ = [
    "ModuleResult",
    "PathrunnerClient",
    "SubprocessPathrunnerClient",
    "MockPathrunnerClient",
]
