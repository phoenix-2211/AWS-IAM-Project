"""Tests for Stage 6 and Stage 7 End-to-End Pipeline Execution."""

import json
from pathlib import Path

import jsonschema
import pytest

from engine3.stages.runner import PipelineRunner


def test_end_to_end_pipeline_execution(tmp_path):
    graph_path = Path("docs/contracts/iamgraph_fixture.json")
    rulebook_path = Path("rulebook/active_rulebook.json")

    runner = PipelineRunner()
    vr_doc = runner.run(graph_path, rulebook_path, tmp_path)

    # 1. Check generated artifact files exist
    assert (tmp_path / "VerificationResult.json").exists()
    assert (tmp_path / "queue.json").exists()
    assert (tmp_path / "run_manifest.json").exists()

    # 2. Validate VerificationResult against JSON schema
    schema_path = Path("schemas/verification_result_v0.1.schema.json")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    jsonschema.validate(instance=vr_doc, schema=schema)

    # 3. Assert properties
    assert vr_doc["contract_name"] == "VerificationResult"
    assert vr_doc["contract_version"] == "0.1"
    assert vr_doc["stats"]["paths_total"] >= 2
    assert "SANDBOX_FAILED" in vr_doc["stats"]["by_status"]
    assert vr_doc["paths"][0]["verification_scope"] == "policy_simulated_only"


def test_schema_rejects_non_enum_status():
    schema_path = Path("schemas/verification_result_v0.1.schema.json")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    invalid_doc = {
        "contract_name": "VerificationResult",
        "contract_version": "0.1",
        "run": {
            "run_id": "run-test",
            "origin": "test",
            "mode": "offline",
            "simulator_backend": "local_evaluator",
            "sandbox_mode": "none",
            "enrichment": "off",
        },
        "inputs": {
            "iamgraph_snapshot_id": "snap-1",
            "iamgraph_content_sha256": "abc",
            "iamgraph_collection_status": "complete",
            "rulebook_sha256": "def",
            "rulebook_origin": "test",
            "rules_active": 1,
            "rules_skipped": 0,
        },
        "degraded": False,
        "degraded_reasons": [],
        "paths": [
            {
                "path_id": "path-1",
                "status": "INVALID_NON_ENUM_STATUS",
                "status_reason": "invalid status test",
                "hops": [],
                "assumptions": [],
                "queue_rank": 1,
                "queue_reason": "test",
                "evidence": {},
                "limitations": [],
            }
        ],
        "stats": {"paths_total": 1, "by_status": {"INVALID_NON_ENUM_STATUS": 1}},
    }

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=invalid_doc, schema=schema)


def test_end_to_end_all_sample_trees(tmp_path):
    fixtures_dir = Path("docs/contracts/fixtures")
    rulebook_path = Path("rulebook/active_rulebook.json")
    schema_path = Path("schemas/verification_result_v0.1.schema.json")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    runner = PipelineRunner()
    tree_files = [
        "tree_1_benign.json",
        "tree_2_low.json",
        "tree_3_medium.json",
        "tree_4_high.json",
        "tree_5_critical.json",
    ]

    for tree_file in tree_files:
        tree_path = fixtures_dir / tree_file
        tree_out_dir = tmp_path / Path(tree_file).stem
        vr_doc = runner.run(tree_path, rulebook_path, tree_out_dir)

        # Validate schema compliance
        jsonschema.validate(instance=vr_doc, schema=schema)
        assert vr_doc["contract_name"] == "VerificationResult"

    # Specific tree assertions
    vr_tree_1 = runner.run(fixtures_dir / "tree_1_benign.json", rulebook_path, tmp_path / "t1")
    assert vr_tree_1["stats"]["paths_total"] == 0

    vr_tree_5 = runner.run(fixtures_dir / "tree_5_critical.json", rulebook_path, tmp_path / "t5")
    assert vr_tree_5["stats"]["paths_total"] > 1


def test_final_verification_results_handoff_deliverable():
    final_vr_path = Path("runs/final_verification_results.json")
    schema_path = Path("schemas/verification_result_v0.1.schema.json")

    assert final_vr_path.exists(), "runs/final_verification_results.json deliverable file must exist"

    with open(final_vr_path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # Validate against Engine 4 VerificationResult v0.1 schema
    jsonschema.validate(instance=doc, schema=schema)

    assert doc["contract_name"] == "VerificationResult"
    assert doc["contract_version"] == "0.1"
    assert doc["run"]["sandbox_mode"] == "MOCKED"
    assert doc["run"]["simulator_mode"] == "MOCKED"

    # Assert path evidence contains MOCKED tags throughout
    for path_obj in doc["paths"]:
        ev = path_obj["evidence"]
        assert ev["simulator_mode"] == "MOCKED"
        assert ev["sandbox_mode"] == "MOCKED"


