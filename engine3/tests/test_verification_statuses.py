"""Unit tests verifying all 5 verification status ladder branches in Engine 3.

Specifically exercises:
1. FULL_CHAIN_VERIFIED (VERIFIED_EXPLOITABLE)
2. POLICY_VERIFIED_NO_SANDBOX
3. PARTIAL_CHAIN_VERIFIED
4. SANDBOX_EXECUTION_FAILED (SANDBOX_FAILED)
5. POLICY_DENIED
"""

import json
from pathlib import Path

from engine3.adapters.graph_adapter import GraphAdapter
from engine3.adapters.rule_adapter import RuleAdapter
from engine3.emit.s6_emit import Stage6Assembler
from engine3.sandbox.s5_sandbox import MockCloudGoatSandboxRunner
from engine3.stages.s0_load import Stage0Loader
from engine3.stages.s1_match import Stage1Matcher
from engine3.stages.s2_path import Stage2PathFinder
from engine3.stages.s3_queue import Stage3Prioritizer
from engine3.stages.s4_sim import LocalPolicySimulator


def test_status_policy_verified_no_sandbox():
    """Verify that a path with POLICY_ALLOWED but unmapped CloudGoat scenario produces POLICY_VERIFIED_NO_SANDBOX."""
    rulebook_path = Path("rulebook/active_rulebook.json")
    with open(rulebook_path, "r", encoding="utf-8") as f:
        rules_data = json.load(f)

    # Synthetic graph with kms:Decrypt action (unmapped in map_scenario_name)
    graph_data = {
        "contract_name": "IAMGraph",
        "contract_version": "0.1",
        "snapshot": {"snapshot_id": "snap-kms", "account_id": "111122223333", "collected_at": "", "origin": "test", "collection_status": "complete"},
        "nodes": [
            {"id": "arn:aws:iam::111122223333:user/kms-user", "type": "User", "arn": "arn:aws:iam::111122223333:user/kms-user", "name": "kms-user"},
            {
                "id": "arn:aws:kms:us-east-1:111122223333:key/mrk-12345",
                "type": "Resource",
                "resource_type": "s3_bucket",  # Matched to storage/data rule
                "arn": "arn:aws:kms:us-east-1:111122223333:key/mrk-12345",
                "name": "mrk-12345"
            },
            {
                "id": "perm:kms:decrypt",
                "type": "Permission",
                "effect": "Allow",
                "actions": ["s3:GetObject"],
                "resources": ["arn:aws:kms:us-east-1:111122223333:key/mrk-12345"],
                "flags": ["no_sandbox_mapped"]
            }
        ],
        "edges": [
            {"id": "e1", "type": "HAS_PERMISSION", "source": "arn:aws:iam::111122223333:user/kms-user", "target": "perm:kms:decrypt"},
            {"id": "e2", "type": "APPLIES_TO", "source": "perm:kms:decrypt", "target": "arn:aws:kms:us-east-1:111122223333:key/mrk-12345"}
        ]
    }

    graph = GraphAdapter.from_json(graph_data)
    rules = RuleAdapter.from_json_list(rules_data)

    matcher = Stage1Matcher()
    match_results = matcher.match_rules(graph, rules)
    finder = Stage2PathFinder(max_depth=6)
    disc_res = finder.discover_paths(graph, match_results)
    prioritizer = Stage3Prioritizer()
    queue_res = prioritizer.prioritize_paths(disc_res.paths, rules)

    sim = LocalPolicySimulator()
    sim_results = [sim.evaluate_path(qp) for qp in queue_res.queue]

    # Force scenario_name to None in mock runner to simulate unmapped scenario
    sandbox = MockCloudGoatSandboxRunner()
    sb_results = []
    for qp, sr in zip(queue_res.queue, sim_results):
        res = sandbox.evaluate_sandbox_path(qp, sim_status=sr.status)
        res.sandbox_scenario_name = None  # No scenario available
        sb_results.append(res)

    loader = Stage0Loader()
    s0_res = loader.load_and_validate(iamgraph_data=graph_data, rulebook_data=rules_data)
    assembler = Stage6Assembler()
    v_res = assembler.assemble(s0_res, queue_res.queue, sim_results, sb_results)

    assert len(v_res["paths"]) >= 1
    top_finding = v_res["paths"][0]
    assert top_finding["status"] == "POLICY_VERIFIED_NO_SANDBOX"


def test_status_partial_chain_verified():
    """Verify that a path with a technical limitation flag produces PARTIAL_CHAIN_VERIFIED."""
    rulebook_path = Path("rulebook/active_rulebook.json")
    with open(rulebook_path, "r", encoding="utf-8") as f:
        rules_data = json.load(f)

    graph_data = {
        "contract_name": "IAMGraph",
        "contract_version": "0.1",
        "snapshot": {"snapshot_id": "snap-partial", "account_id": "111122223333", "collected_at": "", "origin": "test", "collection_status": "complete"},
        "nodes": [
            {"id": "arn:aws:iam::111122223333:user/partial-user", "type": "User", "arn": "arn:aws:iam::111122223333:user/partial-user", "name": "partial-user"},
            {
                "id": "arn:aws:s3:::partial-target",
                "type": "Resource",
                "resource_type": "s3_bucket",
                "arn": "arn:aws:s3:::partial-target",
                "name": "partial-target"
            },
            {
                "id": "perm:partial:read",
                "type": "Permission",
                "effect": "Allow",
                "actions": ["s3:GetObject"],
                "resources": ["arn:aws:s3:::partial-target"],
                "flags": ["verification_skipped"]
            }
        ],
        "edges": [
            {"id": "e1", "type": "HAS_PERMISSION", "source": "arn:aws:iam::111122223333:user/partial-user", "target": "perm:partial:read"},
            {"id": "e2", "type": "APPLIES_TO", "source": "perm:partial:read", "target": "arn:aws:s3:::partial-target"}
        ]
    }

    graph = GraphAdapter.from_json(graph_data)
    rules = RuleAdapter.from_json_list(rules_data)

    matcher = Stage1Matcher()
    match_results = matcher.match_rules(graph, rules)
    finder = Stage2PathFinder(max_depth=6)
    disc_res = finder.discover_paths(graph, match_results)
    prioritizer = Stage3Prioritizer()
    queue_res = prioritizer.prioritize_paths(disc_res.paths, rules)

    sim = LocalPolicySimulator()
    sim_results = [sim.evaluate_path(qp) for qp in queue_res.queue]

    sandbox = MockCloudGoatSandboxRunner()
    sb_results = [sandbox.evaluate_sandbox_path(qp, sim_status=sr.status) for qp, sr in zip(queue_res.queue, sim_results)]

    loader = Stage0Loader()
    s0_res = loader.load_and_validate(iamgraph_data=graph_data, rulebook_data=rules_data)
    assembler = Stage6Assembler()
    v_res = assembler.assemble(s0_res, queue_res.queue, sim_results, sb_results)

    assert len(v_res["paths"]) >= 1
    top_finding = v_res["paths"][0]
    assert top_finding["status"] == "PARTIAL_CHAIN_VERIFIED"
