"""Stage 7 & CLI End-to-End Pipeline Runner."""

import json
import sys
import time
from pathlib import Path
from typing import Any

from engine3.emit.s6_emit import Stage6Assembler
from engine3.stages.s0_load import Stage0Loader
from engine3.stages.s1_match import Stage1Matcher
from engine3.stages.s2_path import Stage2PathFinder
from engine3.stages.s3_queue import Stage3Prioritizer
from engine3.stages.s4_sim import LocalPolicySimulator


class PipelineRunner:
    """Runs Stage 0 to Stage 6 end to end."""

    def run(self, graph_path: Path, rulebook_path: Path, out_dir: Path) -> dict[str, Any]:
        t0 = time.time()
        out_dir.mkdir(parents=True, exist_ok=True)

        with open(graph_path, "rb") as f:
            graph_bytes = f.read()
            graph_data = json.loads(graph_bytes.decode("utf-8"))

        with open(rulebook_path, "rb") as f:
            rulebook_bytes = f.read()
            rulebook_data = json.loads(rulebook_bytes.decode("utf-8"))

        # S0: Load
        t_s0_start = time.time()
        loader = Stage0Loader()
        load_res = loader.load_and_validate(
            graph_data, rulebook_data, iamgraph_raw_bytes=graph_bytes, rulebook_raw_bytes=rulebook_bytes
        )
        if not load_res.is_valid:
            print("Pipeline failed at Stage 0 loader validation:", load_res.errors, file=sys.stderr)
            raise ValueError(f"Stage 0 validation failed with {len(load_res.errors)} errors.")
        t_s0_end = time.time()

        # S1: Match
        matcher = Stage1Matcher()
        match_results = matcher.match_rules(load_res.graph, load_res.active_rules)

        # S2: Path Discovery
        t_graph_start = time.time()
        finder = Stage2PathFinder(max_depth=6)
        disc_res = finder.discover_paths(load_res.graph, match_results)
        t_graph_end = time.time()

        # S3: Queue
        prioritizer = Stage3Prioritizer()
        queue_res = prioritizer.prioritize_paths(disc_res.paths, load_res.active_rules)

        # S4: Policy Simulator (Offline / Local Evaluator)
        t_s4_start = time.time()
        sim = LocalPolicySimulator()
        sim_results = [sim.evaluate_path(q_p) for q_p in queue_res.queue]
        t_s4_end = time.time()

        # S6: Assemble VerificationResult
        assembler = Stage6Assembler()
        metrics = {
            "load_time_ms": (t_s0_end - t_s0_start) * 1000,
            "graph_time_ms": (t_graph_end - t_graph_start) * 1000,
            "policy_sim_time_ms": (t_s4_end - t_s4_start) * 1000,
            "sandbox_time_ms": 0.0,
            "total_ms": (time.time() - t0) * 1000,
        }
        vr_doc = assembler.assemble(
            load_res=load_res,
            queue_paths=queue_res.queue,
            sim_results=sim_results,
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
