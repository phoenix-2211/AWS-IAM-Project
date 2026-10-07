"""Runs Engine 3 S0-S8 pipeline against tree_7_industry_scale.json and computes detection rate metrics against the 31 IAM Vulnerable benchmark paths."""

import json
import time
from pathlib import Path

import jsonschema

from engine3.emit.s6_emit import Stage6Assembler
from engine3.sandbox.s5_sandbox import MockCloudGoatSandboxRunner
from engine3.stages.s0_load import Stage0Loader
from engine3.stages.s1_match import Stage1Matcher
from engine3.stages.s2_path import Stage2PathFinder
from engine3.stages.s3_queue import Stage3Prioritizer
from engine3.stages.s4_sim import LocalPolicySimulator

BASE_DIR = Path(__file__).parent.parent
FIXTURE_PATH = BASE_DIR / "docs" / "contracts" / "fixtures" / "tree_7_industry_scale.json"
RULEBOOK_PATH = BASE_DIR / "rulebook" / "active_rulebook.json"
SCHEMA_PATH = BASE_DIR / "schemas" / "verification_result_v0.1.schema.json"

# All 31 documented IAM Vulnerable privilege escalation benchmark path identifiers
IAM_VULNERABLE_PATHS = [
    "privesc1-CreateNewPolicyVersion",
    "privesc2-SetExistingDefaultPolicyVersion",
    "privesc3-CreateEC2WithExistingIP",
    "privesc4-CreateAccessKey",
    "privesc5-CreateLoginProfile",
    "privesc6-UpdateLoginProfile",
    "privesc7-AttachUserPolicy",
    "privesc8-AttachGroupPolicy",
    "privesc9-AttachRolePolicy",
    "privesc10-PutUserPolicy",
    "privesc11-PutGroupPolicy",
    "privesc12-PutRolePolicy",
    "privesc13-AddUserToGroup",
    "privesc14-UpdatingAssumeRolePolicy",
    "privesc15-PassExistingRoleToNewLambdaThenInvoke",
    "privesc16-PassRoleToNewLambdaThenTriggerWithNewDynamo",
    "privesc17-EditExistingLambdaFunctionWithRole",
    "privesc18-PassExistingRoleToNewGlueDevEndpoint",
    "privesc19-UpdateExistingGlueDevEndpoint",
    "privesc20-PassExistingRoleToCloudFormation",
    "privesc21-PassExistingRoleToNewDataPipeline",
    "privesc-AssumeRole",
    "privesc-cloudFormationUpdateStack",
    "privesc-codeBuildCreateProjectPassRole",
    "privesc-ec2InstanceConnect",
    "privesc-sageMakerCreateNotebookPassRole",
    "privesc-sageMakerCreatePresignedNotebookURL",
    "privesc-sageMakerCreateProcessingJob",
    "privesc-sageMakerCreateTrainingJob",
    "privesc-ssmSendCommand",
    "privesc-ssmStartSession",
]


def run_benchmark():
    t0 = time.perf_counter()

    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        graph_data = json.load(f)
    with open(RULEBOOK_PATH, "r", encoding="utf-8") as f:
        rulebook_data = json.load(f)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # S0 Load & Validate
    loader = Stage0Loader()
    s0_res = loader.load_and_validate(iamgraph_data=graph_data, rulebook_data=rulebook_data)
    assert s0_res.is_valid, f"Stage 0 validation failed: {s0_res.errors}"
    t_s0 = time.perf_counter()

    # S1 Match Rules
    matcher = Stage1Matcher()
    match_results = matcher.match_rules(s0_res.graph, s0_res.active_rules)
    t_s1 = time.perf_counter()

    # S2 Discover Paths
    finder = Stage2PathFinder(max_depth=6)
    disc_res = finder.discover_paths(s0_res.graph, match_results)
    t_s2 = time.perf_counter()

    # S3 Prioritize Queue
    prioritizer = Stage3Prioritizer()
    queue_res = prioritizer.prioritize_paths(disc_res.paths, s0_res.active_rules)
    t_s3 = time.perf_counter()

    # S4 Policy Simulator
    sim = LocalPolicySimulator()
    sim_results = [sim.evaluate_path(qp) for qp in queue_res.queue]
    t_s4 = time.perf_counter()

    # S5 Sandbox Evaluator
    sandbox = MockCloudGoatSandboxRunner()
    sandbox_results = [sandbox.evaluate_sandbox_path(qp, sim_status=sr.status) for qp, sr in zip(queue_res.queue, sim_results)]
    t_s5 = time.perf_counter()

    # S6 VerificationResult Assembler
    assembler = Stage6Assembler()
    v_res = assembler.assemble(s0_res, queue_res.queue, sim_results, sandbox_results)
    t_s6 = time.perf_counter()

    # Validate against JSON schema
    jsonschema.validate(instance=v_res, schema=schema)

    total_time = (t_s6 - t0) * 1000

    # Analyze detection rate across the 31 IAM Vulnerable paths
    caught_paths = set()
    caught_details = {}

    for path_obj in v_res["paths"]:
        # Extract all node strings in path trajectory
        nodes_in_path = []
        for h in path_obj["hops"]:
            nodes_in_path.append(h["from_node"])
            nodes_in_path.append(h["to_node"])

        path_text = " ".join(nodes_in_path).lower()

        for benchmark_path in IAM_VULNERABLE_PATHS:
            p_prefix = benchmark_path.split("-")[0].lower()  # e.g., privesc1, privesc15
            p_full = benchmark_path.lower()

            # Match if path nodes contain either full name or specific prefix identifier
            if p_full in path_text or (len(p_prefix) > 4 and p_prefix in path_text):
                rule_ids = [h.get("matched_rule_id") for h in path_obj["hops"] if h.get("matched_rule_id")]
                caught_paths.add(benchmark_path)
                caught_details.setdefault(benchmark_path, []).extend(rule_ids)

    # Check tool-testing compound paths (fn1-*)
    fn1_paths = [p for p in v_res["paths"] if any("fn1" in h["from_node"].lower() or "fn1" in h["to_node"].lower() for h in p["hops"])]
    fn1_caught = len(fn1_paths) > 0

    missed_paths = sorted(list(set(IAM_VULNERABLE_PATHS) - caught_paths))
    caught_paths_sorted = sorted(list(caught_paths))

    print("\n=======================================================")
    print("  ENGINE 3 IAM VULNERABLE BENCHMARK RESULTS")
    print("=======================================================")
    print(f"Fixture: tree_7_industry_scale.json")
    print(f"Nodes: {len(graph_data['nodes'])} | Edges: {len(graph_data['edges'])}")
    print(f"Rules Evaluated: {len(s0_res.active_rules)}")
    print(f"Discovered Attack Paths: {len(v_res['paths'])}")
    print(f"Schema Validation: PASSED")
    print(f"\nDETECTION METRICS:")
    print(f"Benchmark Paths Caught: {len(caught_paths_sorted)} / 31 ({len(caught_paths_sorted)/31 * 100:.1f}%)")
    print(f"Benchmark Paths Missed: {len(missed_paths)} / 31")
    print(f"Compound Risk (fn1-*) Discovered: {'YES (' + str(len(fn1_paths)) + ' paths)' if fn1_caught else 'NO (Expected Schema Limitation)'}")
    print(f"\nPERFORMANCE TIMINGS:")
    print(f"S0 Load & Validate: {(t_s0 - t0)*1000:.2f} ms")
    print(f"S1 Match Rules:     {(t_s1 - t_s0)*1000:.2f} ms")
    print(f"S2 Path Discovery:  {(t_s2 - t_s1)*1000:.2f} ms")
    print(f"S3 Prioritize Queue:{(t_s3 - t_s2)*1000:.2f} ms")
    print(f"S4 Policy Simulator:{(t_s4 - t_s3)*1000:.2f} ms")
    print(f"S5 Sandbox Run:     {(t_s5 - t_s4)*1000:.2f} ms")
    print(f"S6 Assembly:        {(t_s6 - t_s5)*1000:.2f} ms")
    print(f"Total Pipeline Run: {total_time:.2f} ms")
    print("=======================================================\n")

    return {
        "caught_count": len(caught_paths_sorted),
        "missed_count": len(missed_paths),
        "caught_paths": caught_paths_sorted,
        "missed_paths": missed_paths,
        "fn1_caught": fn1_caught,
        "total_paths": len(v_res["paths"]),
        "total_time_ms": total_time,
        "caught_details": caught_details
    }


if __name__ == "__main__":
    run_benchmark()
