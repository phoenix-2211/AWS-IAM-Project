"""Stage 8 End-to-End Pipeline Runner."""

import json
import sys
import time
from pathlib import Path
from typing import Any

from engine3.s0_intake import Stage0Loader
from engine3.s1_rule_matching import Stage1Matcher
from engine3.s2_path_discovery import Stage2PathFinder
from engine3.s3_prioritization import Stage3Prioritizer
from engine3.s4_policy_verification import LocalPolicySimulator
from engine3.s5_sandbox import MockCloudGoatSandboxRunner
from engine3.s8_output import Stage8OutputAssembler


class PipelineRunner:
    """Runs Stage 0 to Stage 8 end to end."""

    def run(self, graph_path: Path, rulebook_path: Path, out_dir: Path) -> dict[str, Any]:
        t0 = time.time()
        out_dir.mkdir(parents=True, exist_ok=True)

        with open(graph_path, "rb") as f:
            graph_bytes = f.read()
            graph_data = json.loads(graph_bytes.decode("utf-8"))

        with open(rulebook_path, "rb") as f:
            rulebook_bytes = f.read()
            rulebook_data = json.loads(rulebook_bytes.decode("utf-8"))

        # S0: Intake / Load
        t_s0_start = time.time()
        loader = Stage0Loader()
        load_res = loader.load_and_validate(
            graph_data, rulebook_data
        )
        if not load_res.is_valid:
            print("Pipeline failed at Stage 0 intake validation:", load_res.errors, file=sys.stderr)
            raise ValueError(f"Stage 0 validation failed with {len(load_res.errors)} errors.")
        t_s0_end = time.time()

        # S1: Rule Matching
        matcher = Stage1Matcher()
        match_results = matcher.match_rules(load_res.graph, load_res.active_rules, rulebook_origin="active")

        # S2: Path Discovery
        t_graph_start = time.time()
        finder = Stage2PathFinder(max_depth=6)
        disc_res = finder.discover_paths(load_res.graph, match_results)
        t_graph_end = time.time()

        # S3: Queue / Prioritization
        prioritizer = Stage3Prioritizer()
        queue_res = prioritizer.prioritize_paths(disc_res.paths, load_res.active_rules)

        # S4: Policy Verification (Offline / Local Evaluator)
        t_s4_start = time.time()
        sim = LocalPolicySimulator()
        sim_results = [sim.evaluate_path(q_p) for q_p in queue_res.queue]
        t_s4_end = time.time()

        # S5: Sandbox Verification (Mock)
        t_s5_start = time.time()
        sandbox_evaluator = MockCloudGoatSandboxRunner()
        sandbox_results = [
            sandbox_evaluator.evaluate_sandbox_path(q_p, sim_status=s_r.status)
            for q_p, s_r in zip(queue_res.queue, sim_results)
        ]
        t_s5_end = time.time()

        # S8: Assemble VerificationResult Output
        assembler = Stage8OutputAssembler()
        metrics = {
            "load_time_ms": (t_s0_end - t_s0_start) * 1000,
            "graph_time_ms": (t_graph_end - t_graph_start) * 1000,
            "policy_sim_time_ms": (t_s4_end - t_s4_start) * 1000,
            "sandbox_time_ms": (t_s5_end - t_s5_start) * 1000,
            "total_ms": (time.time() - t0) * 1000,
        }
        vr_doc = assembler.assemble(
            load_res=load_res,
            queue_paths=queue_res.queue,
            sim_results=sim_results,
            sandbox_results=sandbox_results,
            rulebook_origin="active",
            metrics_dict=metrics,
        )

        # Write artifacts
        with open(out_dir / "VerificationResult.json", "w", encoding="utf-8") as f:
            json.dump(vr_doc, f, indent=2)

        with open(out_dir / "queue.json", "w", encoding="utf-8") as f:
            json.dump(queue_res.model_dump(), f, indent=2)

        manifest = {
            "run_id": vr_doc["run"]["run_id"],
            "artifacts": ["VerificationResult.json", "queue.json"],
            "status": "COMPLETE",
        }
        with open(out_dir / "run_manifest.json", "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return vr_doc
