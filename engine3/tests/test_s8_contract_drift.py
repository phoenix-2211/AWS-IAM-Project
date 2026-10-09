"""Regression test validating Stage 8 VerificationResult output structure against engine4_handoff_example.json."""

import json
from pathlib import Path
import pytest
from engine3.stages.runner import PipelineRunner


def test_s8_output_structure_matches_engine4_handoff_example(tmp_path):
    """Recursively validates S8 output structure against engine4_handoff_example.json to prevent schema drift."""
    graph_path = Path("docs/contracts/iamgraph_fixture.json")
    rulebook_path = Path("rulebook/active_rulebook.json")
    example_path = Path("docs/engine4_handoff_example.json")

    assert example_path.exists(), "docs/engine4_handoff_example.json must exist"
    with open(example_path, "r", encoding="utf-8") as f:
        example_doc = json.load(f)

    runner = PipelineRunner()
    vr_doc = runner.run(graph_path, rulebook_path, tmp_path)

    # 1. Top-Level Keys
    assert set(vr_doc.keys()) == set(example_doc.keys()), (
        f"Root keys mismatch: extra={set(vr_doc.keys()) - set(example_doc.keys())}, "
        f"missing={set(example_doc.keys()) - set(vr_doc.keys())}"
    )

    # 2. Run Section Keys
    assert set(vr_doc["run"].keys()) == set(example_doc["run"].keys())

    # 3. Inputs Section Keys
    assert set(vr_doc["inputs"].keys()) == set(example_doc["inputs"].keys())

    # 4. Path Object Structure
    assert len(vr_doc["paths"]) > 0
    assert len(example_doc["paths"]) > 0

    expected_path_keys = set(example_doc["paths"][0].keys())
    for path_obj in vr_doc["paths"]:
        assert set(path_obj.keys()) == expected_path_keys, (
            f"Path object keys mismatch: extra={set(path_obj.keys()) - expected_path_keys}, "
            f"missing={expected_path_keys - set(path_obj.keys())}"
        )

        # 5. Hop Object Structure (no 'result' on hops)
        assert "result" not in path_obj["hops"][0]
        expected_hop_keys = set(example_doc["paths"][0]["hops"][0].keys())
        for hop in path_obj["hops"]:
            assert set(hop.keys()) == expected_hop_keys

        # 6. Evidence Structure
        expected_evidence_keys = set(example_doc["paths"][0]["evidence"].keys())
        assert set(path_obj["evidence"].keys()) == expected_evidence_keys

        # 7. Policy Simulator Details Structure
        if path_obj["evidence"]["policy_simulator_details"]:
            expected_sim_detail_keys = set(example_doc["paths"][0]["evidence"]["policy_simulator_details"][0].keys())
            for sim_d in path_obj["evidence"]["policy_simulator_details"]:
                assert set(sim_d.keys()) == expected_sim_detail_keys

        # 8. Per-Path Runtime Metrics Structure
        expected_path_metrics_keys = set(example_doc["paths"][0]["runtime_metrics"].keys())
        assert set(path_obj["runtime_metrics"].keys()) == expected_path_metrics_keys

    # 9. Top-Level Runtime Metrics Structure
    expected_root_metrics_keys = set(example_doc["runtime_metrics"].keys())
    assert set(vr_doc["runtime_metrics"].keys()) == expected_root_metrics_keys

    # 10. Top-Level Stats Structure
    expected_stats_keys = set(example_doc["stats"].keys())
    assert set(vr_doc["stats"].keys()) == expected_stats_keys
