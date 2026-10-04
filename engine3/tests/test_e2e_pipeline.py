"""Tests for Stage 6 and Stage 7 End-to-End Pipeline Execution."""

import json
from pathlib import Path

import jsonschema

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
    assert "POLICY_ALLOWED_UNCONFIRMED" in vr_doc["stats"]["by_status"]
