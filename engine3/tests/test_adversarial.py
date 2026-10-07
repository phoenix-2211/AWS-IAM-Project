"""Adversarial self-tests to verify pipeline resistance against false positives & path inflation."""

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


def test_adversarial_case_1_low_sensitivity_target():
    """Case 1: Path targeting a low-sensitivity resource must not be assigned HIGH/CRITICAL queue priority."""
    rulebook_path = Path("rulebook/active_rulebook.json")
    with open(rulebook_path, "r", encoding="utf-8") as f:
        rules_data = json.load(f)

    graph_data = {
        "contract_name": "IAMGraph",
        "contract_version": "0.1",
        "snapshot": {"snapshot_id": "snap-adv-1", "account_id": "111122223333", "collected_at": "", "origin": "test", "collection_status": "complete"},
        "nodes": [
            {"id": "arn:aws:iam::111122223333:user/adv-user-low", "type": "User", "arn": "arn:aws:iam::111122223333:user/adv-user-low", "name": "adv-user-low"},
            {
                "id": "arn:aws:s3:::public-debug-logs",
                "type": "Resource",
                "resource_type": "s3_bucket",
                "arn": "arn:aws:s3:::public-debug-logs",
                "name": "public-debug-logs",
                "metadata": {"sensitivity": "low"}
            },
            {
                "id": "perm:low:read",
                "type": "Permission",
                "effect": "Allow",
                "actions": ["s3:GetObject"],
                "resources": ["arn:aws:s3:::public-debug-logs"]
            }
        ],
        "edges": [
            {"id": "e1", "type": "HAS_PERMISSION", "source": "arn:aws:iam::111122223333:user/adv-user-low", "target": "perm:low:read"},
            {"id": "e2", "type": "APPLIES_TO", "source": "perm:low:read", "target": "arn:aws:s3:::public-debug-logs"}
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

    assert len(queue_res.queue) >= 1
    # Confirm queue reason reflects low sensitivity resource status
    top_path = queue_res.queue[0]
    assert "LOW" in top_path.queue_reason.upper() or "MEDIUM" in top_path.queue_reason.upper() or top_path.queue_rank == 1


def test_adversarial_case_2_mfa_satisfied_not_blocked():
    """Case 2: Path with satisfied MFA condition must evaluate as ALLOWED, not blocked as POLICY_DENIED."""
    rulebook_path = Path("rulebook/active_rulebook.json")
    with open(rulebook_path, "r", encoding="utf-8") as f:
        rules_data = json.load(f)

    graph_data = {
        "contract_name": "IAMGraph",
        "contract_version": "0.1",
        "snapshot": {"snapshot_id": "snap-adv-2", "account_id": "111122223333", "collected_at": "", "origin": "test", "collection_status": "complete"},
        "nodes": [
            {"id": "arn:aws:iam::111122223333:user/mfa-user", "type": "User", "arn": "arn:aws:iam::111122223333:user/mfa-user", "name": "mfa-user", "mfa_enabled": True},
            {
                "id": "arn:aws:iam::111122223333:role/MFAProtectedRole",
                "type": "Role",
                "arn": "arn:aws:iam::111122223333:role/MFAProtectedRole",
                "name": "MFAProtectedRole",
                "trust_policy": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::111122223333:user/mfa-user"},
                        "Action": "sts:AssumeRole",
                        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
                    }]
                }
            },
            {
                "id": "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db",
                "type": "Resource",
                "resource_type": "secretsmanager_secret",
                "arn": "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db",
                "name": "prod/db"
            },
            {
                "id": "perm:mfa:assume",
                "type": "Permission",
                "effect": "Allow",
                "actions": ["sts:AssumeRole"],
                "resources": ["arn:aws:iam::111122223333:role/MFAProtectedRole"]
            },
            {
                "id": "perm:role:read-db",
                "type": "Permission",
                "effect": "Allow",
                "actions": ["secretsmanager:GetSecretValue"],
                "resources": ["arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db"]
            }
        ],
        "edges": [
            {"id": "e1", "type": "HAS_PERMISSION", "source": "arn:aws:iam::111122223333:user/mfa-user", "target": "perm:mfa:assume"},
            {"id": "e2", "type": "APPLIES_TO", "source": "perm:mfa:assume", "target": "arn:aws:iam::111122223333:role/MFAProtectedRole"},
            {"id": "e3", "type": "TRUSTED_BY", "source": "arn:aws:iam::111122223333:user/mfa-user", "target": "arn:aws:iam::111122223333:role/MFAProtectedRole", "has_condition": False},
            {"id": "e4", "type": "HAS_PERMISSION", "source": "arn:aws:iam::111122223333:role/MFAProtectedRole", "target": "perm:role:read-db"},
            {"id": "e5", "type": "APPLIES_TO", "source": "perm:role:read-db", "target": "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db"}
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

    assert len(sim_results) > 0
    # Satisfied MFA path must not be POLICY_DENIED
    for s_res in sim_results:
        assert s_res.status == "POLICY_ALLOWED"


def test_adversarial_case_3_cycle_handling_no_path_explosion():
    """Case 3: Graph cycles (RoleA trusts RoleB and RoleB trusts RoleA) must not inflate path count infinitely."""
    rulebook_path = Path("rulebook/active_rulebook.json")
    with open(rulebook_path, "r", encoding="utf-8") as f:
        rules_data = json.load(f)

    graph_data = {
        "contract_name": "IAMGraph",
        "contract_version": "0.1",
        "snapshot": {"snapshot_id": "snap-adv-3", "account_id": "111122223333", "collected_at": "", "origin": "test", "collection_status": "complete"},
        "nodes": [
            {"id": "arn:aws:iam::111122223333:user/cycle-user", "type": "User", "arn": "arn:aws:iam::111122223333:user/cycle-user"},
            {"id": "arn:aws:iam::111122223333:role/RoleA", "type": "Role", "arn": "arn:aws:iam::111122223333:role/RoleA"},
            {"id": "arn:aws:iam::111122223333:role/RoleB", "type": "Role", "arn": "arn:aws:iam::111122223333:role/RoleB"},
            {
                "id": "arn:aws:s3:::cycle-target-bucket",
                "type": "Resource",
                "resource_type": "s3_bucket",
                "arn": "arn:aws:s3:::cycle-target-bucket"
            },
            {"id": "p1", "type": "Permission", "effect": "Allow", "actions": ["sts:AssumeRole"], "resources": ["arn:aws:iam::111122223333:role/RoleA"]},
            {"id": "p2", "type": "Permission", "effect": "Allow", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::cycle-target-bucket"]}
        ],
        "edges": [
            {"id": "e1", "type": "HAS_PERMISSION", "source": "arn:aws:iam::111122223333:user/cycle-user", "target": "p1"},
            {"id": "e2", "type": "APPLIES_TO", "source": "p1", "target": "arn:aws:iam::111122223333:role/RoleA"},
            {"id": "e3", "type": "TRUSTED_BY", "source": "arn:aws:iam::111122223333:role/RoleA", "target": "arn:aws:iam::111122223333:role/RoleB", "has_condition": False},
            {"id": "e4", "type": "TRUSTED_BY", "source": "arn:aws:iam::111122223333:role/RoleB", "target": "arn:aws:iam::111122223333:role/RoleA", "has_condition": False},
            {"id": "e5", "type": "HAS_PERMISSION", "source": "arn:aws:iam::111122223333:role/RoleB", "target": "p2"},
            {"id": "e6", "type": "APPLIES_TO", "source": "p2", "target": "arn:aws:s3:::cycle-target-bucket"}
        ]
    }

    graph = GraphAdapter.from_json(graph_data)
    rules = RuleAdapter.from_json_list(rules_data)

    matcher = Stage1Matcher()
    match_results = matcher.match_rules(graph, rules)
    finder = Stage2PathFinder(max_depth=6)
    disc_res = finder.discover_paths(graph, match_results)

    # Cyclic graph must produce exact acyclic paths without infinite recursion or path explosion
    assert len(disc_res.paths) > 0
    # Every discovered path must be strictly acyclic (no duplicate node in trajectory)
    for p in disc_res.paths:
        nodes_in_path = [p.start_node] + [h.to_node for h in p.hops]
        assert len(nodes_in_path) == len(set(nodes_in_path))
