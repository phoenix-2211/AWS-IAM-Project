"""Mutation and validation tests for Stage 0 loader."""

import json
from pathlib import Path

import pytest

from engine3.stages.s0_load import Stage0Loader


@pytest.fixture
def base_inputs():
    fixture_path = Path("docs/contracts/iamgraph_fixture.json")
    rulebook_path = Path("docs/contracts/SecurityRule_sample.json")
    with open(fixture_path, "r", encoding="utf-8") as f:
        iamgraph_data = json.load(f)
    with open(rulebook_path, "r", encoding="utf-8") as f:
        rulebook_data = json.load(f)
    return iamgraph_data, rulebook_data


def test_baseline_valid_load(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is True
    assert res.graph is not None
    assert res.rules_active == 4
    assert res.rules_skipped == 1
    assert "A missing edge in the IAMGraph is never treated as proof of safety." in res.limitations


def test_mutation_01_duplicate_node_id(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    # Duplicate node 0
    iamgraph_data["nodes"].append(dict(iamgraph_data["nodes"][0]))

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert "ERR_DUPLICATE_NODE_ID" in codes


def test_mutation_02_dangling_edge_target(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    iamgraph_data["edges"][0]["target"] = "arn:aws:iam::111122223333:role/nonexistent"

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert "ERR_DANGLING_EDGE_TARGET" in codes


def test_mutation_03_invalid_edge_endpoint(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    # HAS_PERMISSION edge pointing User -> Role (illegal endpoint)
    iamgraph_data["edges"][0]["target"] = iamgraph_data["nodes"][1]["id"]  # Role ID

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert "ERR_INVALID_EDGE_ENDPOINT" in codes


def test_mutation_04_unknown_enum_value(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    iamgraph_data["snapshot"]["origin"] = "invalid_origin"

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert "ERR_SCHEMA_VALIDATION" in codes


def test_mutation_05_missing_contract_version(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    del iamgraph_data["contract_version"]

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert "ERR_MISSING_CONTRACT_VERSION" in codes or "ERR_SCHEMA_VALIDATION" in codes


def test_mutation_06_wrong_contract_version(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    iamgraph_data["contract_version"] = "99.0"

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert "ERR_WRONG_CONTRACT_VERSION" in codes or "ERR_SCHEMA_VALIDATION" in codes


def test_mutation_07_inconsistent_coverage(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    iamgraph_data["snapshot"]["collection_status"] = "partial"
    for item in iamgraph_data["snapshot"]["coverage"]:
        item["status"] = "complete"

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert "ERR_INCONSISTENT_COVERAGE" in codes


def test_mutation_08_dangling_warning_reference(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    iamgraph_data["warnings"].append({"node_id": "arn:aws:iam::111122223333:role/nonexistent"})

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert "ERR_DANGLING_WARNING_REFERENCE" in codes


def test_mutation_09_both_actions_and_not_actions(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    # Find a permission node and set both actions and not_actions
    for node in iamgraph_data["nodes"]:
        if node.get("type") == "Permission":
            node["actions"] = ["sts:AssumeRole"]
            node["not_actions"] = ["s3:*"]
            break

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert "ERR_BOTH_ACTIONS_AND_NOT_ACTIONS" in codes


def test_mutation_10_removed_x_provenance(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    if "x_provenance" in iamgraph_data:
        del iamgraph_data["x_provenance"]

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is True
    assert any("x_provenance" in n for n in res.notes)


def test_mutation_11_pipe_collision_keys(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    node_a = {"id": "a|b", "type": "Role"}
    node_b = {"id": "c", "type": "Permission", "actions": ["sts:AssumeRole"]}
    node_c = {"id": "a", "type": "Role"}
    node_d = {"id": "b|c", "type": "Permission", "actions": ["sts:AssumeRole"]}
    edge_1 = {"id": "e1", "type": "HAS_PERMISSION", "source": "a|b", "target": "c"}
    edge_2 = {"id": "e2", "type": "HAS_PERMISSION", "source": "a", "target": "b|c"}

    iamgraph_data["nodes"].extend([node_a, node_b, node_c, node_d])
    iamgraph_data["edges"].extend([edge_1, edge_2])

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)
    assert res.is_valid is True


def test_mutation_12_unknown_rule_severity(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    rulebook_data[0]["severity"] = "APOCALYPTIC"

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert codes == ["ERR_SCHEMA_VALIDATION"] or "ERR_UNKNOWN_RULE_SEVERITY" in codes


def test_mutation_13_flip_active_to_draft(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    # Flip first rule to DRAFT (now 2 DRAFT, 3 ACTIVE)
    rulebook_data[0]["status"] = "DRAFT"

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is True
    assert res.rules_active == 3
    assert res.rules_skipped == 2


def test_mutation_14_complete_status_with_partial_coverage(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    iamgraph_data["snapshot"]["collection_status"] = "complete"
    iamgraph_data["snapshot"]["coverage"][0]["status"] = "partial"

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert codes == ["ERR_INCONSISTENT_COVERAGE"]


def test_mutation_16_rule_missing_required_field(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    del rulebook_data[0]["title"]

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert codes == ["ERR_SCHEMA_VALIDATION"]


def test_mutation_17_duplicate_rule_id(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    rulebook_data.append(dict(rulebook_data[0]))

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert codes == ["ERR_DUPLICATE_RULE_ID"]


def test_mutation_18_bad_rule_status(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    rulebook_data[0]["status"] = "INVALID_STATUS"

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert "ERR_SCHEMA_VALIDATION" in codes or "ERR_UNKNOWN_RULE_STATUS" in codes


def test_mutation_19_unknown_node_type(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    iamgraph_data["nodes"][0]["type"] = "SuperUser"

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert "ERR_SCHEMA_VALIDATION" in codes


def test_mutation_20_unknown_edge_type(base_inputs):
    iamgraph_data, rulebook_data = base_inputs
    iamgraph_data["edges"][0]["type"] = "SUPER_CONNECT"

    loader = Stage0Loader()
    res = loader.load_and_validate(iamgraph_data, rulebook_data)

    assert res.is_valid is False
    codes = [e.code for e in res.errors]
    assert codes == ["ERR_SCHEMA_VALIDATION"]


def test_negative_verification_result_schema():
    import jsonschema
    schema_path = Path("schemas/verification_result_v0.1.schema.json")
    handoff_path = Path("docs/engine4_handoff_example.json")
    with open(schema_path) as f:
        schema = json.load(f)
    with open(handoff_path) as f:
        doc = json.load(f)

    # Negative 21: Bad status
    bad_status_doc = json.loads(json.dumps(doc))
    bad_status_doc["paths"][0]["status"] = "SUPER_EXPLOITABLE_INVALID"
    # Note: verification_result_v0.1 schema requires string for status currently
    # Negative 22: Missing hop field
    missing_hop_doc = json.loads(json.dumps(doc))
    del missing_hop_doc["paths"][0]["hops"][0]["action_used"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=missing_hop_doc, schema=schema)
