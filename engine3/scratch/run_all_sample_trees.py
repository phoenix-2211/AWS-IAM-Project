"""Runner script for processing all 5 sample trees S1->S4 and generating prioritized_queue.json."""

import json
from pathlib import Path
from typing import Any

from engine3.adapters.graph_adapter import GraphAdapter
from engine3.adapters.rule_adapter import RuleAdapter
from engine3.emit.s6_emit import Stage6Assembler
from engine3.stages.s0_load import Stage0Loader
from engine3.stages.s1_match import Stage1Matcher
from engine3.stages.s2_path import Stage2PathFinder
from engine3.stages.s3_queue import Stage3Prioritizer, QueuedPath
from engine3.stages.s4_sim import LocalPolicySimulator


def main():
    base_dir = Path(__file__).parents[1]
    fixtures_dir = base_dir / "docs" / "contracts" / "fixtures"
    rulebook_path = base_dir / "rulebook" / "active_rulebook.json"
    runs_dir = base_dir / "runs"
    output_dir = base_dir / "output"

    runs_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(rulebook_path, "rb") as f:
        rulebook_bytes = f.read()
        rulebook_data = json.loads(rulebook_bytes.decode("utf-8"))

    tree_files = [
        "tree_1_benign.json",
        "tree_2_low.json",
        "tree_3_medium.json",
        "tree_4_high.json",
        "tree_5_critical.json",
    ]

    all_queued_paths: list[QueuedPath] = []
    tree_summary_report: dict[str, Any] = {}

    loader = Stage0Loader()
    matcher = Stage1Matcher()
    finder = Stage2PathFinder(max_depth=6)
    prioritizer = Stage3Prioritizer()
    sim = LocalPolicySimulator()
    assembler = Stage6Assembler()

    for tree_file in tree_files:
        tree_name = Path(tree_file).stem
        tree_path = fixtures_dir / tree_file

        with open(tree_path, "rb") as f:
            graph_bytes = f.read()
            graph_data = json.loads(graph_bytes.decode("utf-8"))

        load_res = loader.load_and_validate(graph_data, rulebook_data)
        match_results = matcher.match_rules(load_res.graph, load_res.active_rules)
        rule_matches_count = sum(len(r.matches) for r in match_results)

        disc_res = finder.discover_paths(load_res.graph, match_results)
        paths_count = len(disc_res.paths)

        queue_res = prioritizer.prioritize_paths(disc_res.paths, load_res.active_rules, source_tree=tree_name)
        all_queued_paths.extend(queue_res.queue)

        sim_results = [sim.evaluate_path(q_p) for q_p in queue_res.queue]

        vr_doc = assembler.assemble(
            load_res=load_res,
            queue_paths=queue_res.queue,
            sim_results=sim_results,
            rulebook_origin="active",
        )

        # Write per-tree VR JSON under runs/<tree_name>/
        tree_out_dir = runs_dir / tree_name
        tree_out_dir.mkdir(parents=True, exist_ok=True)
        with open(tree_out_dir / "VerificationResult.json", "w", encoding="utf-8") as f:
            json.dump(vr_doc, f, indent=2)

        # For tree_5_critical, also write main output/ VerificationResult.json & queue.json
        if tree_file == "tree_5_critical.json":
            with open(output_dir / "VerificationResult.json", "w", encoding="utf-8") as f:
                json.dump(vr_doc, f, indent=2)
            with open(output_dir / "queue.json", "w", encoding="utf-8") as f:
                json.dump(queue_res.model_dump(), f, indent=2)

        top_path_id = queue_res.queue[0].path_id if queue_res.queue else None
        top_verdict = sim_results[0].status if sim_results else "NO_PATHS"

        tree_summary_report[tree_name] = {
            "tree_file": tree_file,
            "rule_matches": rule_matches_count,
            "attack_paths": paths_count,
            "top_path_id": top_path_id,
            "top_path_verdict": top_verdict,
        }

    # Sort all candidate paths globally for prioritized_queue.json
    all_candidate_paths = [q.path for q in all_queued_paths]
    # Fetch active rules for priority calculation
    active_rules = RuleAdapter.from_json_list(rulebook_data)
    global_queue_res = prioritizer.prioritize_paths(all_candidate_paths, active_rules)

    # Attach correct source_tree and severity to each globally queued path
    path_tree_map = {q.path_id: q.source_tree for q in all_queued_paths}
    global_queue_export = []
    for q_item in global_queue_res.queue:
        q_dict = q_item.model_dump()
        q_dict["source_tree"] = path_tree_map.get(q_item.path_id, "unknown")
        global_queue_export.append(q_dict)

    with open(runs_dir / "prioritized_queue.json", "w", encoding="utf-8") as f:
        json.dump({"global_queue": global_queue_export, "total_paths": len(global_queue_export)}, f, indent=2)

    with open(runs_dir / "summary_report.json", "w", encoding="utf-8") as f:
        json.dump(tree_summary_report, f, indent=2)

    print("Pipeline run completed successfully for all 5 trees.")
    print(json.dumps(tree_summary_report, indent=2))


if __name__ == "__main__":
    main()
