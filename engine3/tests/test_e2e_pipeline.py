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
