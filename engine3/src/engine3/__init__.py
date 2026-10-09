"""Engine 3: Attack + Verify IAM Attack Paths."""

__version__ = "0.1.0"

from engine3.s0_intake import Stage0Intake, Stage0Loader, Stage0LoadResult
from engine3.s1_rule_matching import MatchEvidence, RuleMatchResult, Stage1Matcher, Stage1RuleMatcher
from engine3.s2_path_discovery import CandidatePath, PathHop, Stage2DiscoveryResult, Stage2PathDiscovery, Stage2PathFinder
from engine3.s3_prioritization import QueuedPath, Stage3Prioritization, Stage3Prioritizer, Stage3QueueResult
from engine3.s4_policy_verification import HopSimResult, LivePolicySimulator, LocalPolicySimulator, PathSimResult, Stage4PolicyVerification, Stage4SimResult
from engine3.s5_sandbox import CloudGoatSandboxRunner, MockCloudGoatSandboxRunner, SandboxRunResult, Stage5Sandbox
from engine3.s6_evidence import PathEvidence, Stage6Evidence, Stage6EvidenceAggregator
from engine3.s7_decision import Stage7Decision, Stage7DecisionEngine, VerificationDecision
from engine3.s8_output import Stage6Assembler, Stage8Output, Stage8OutputAssembler

__all__ = [
    "__version__",
    "Stage0Loader",
    "Stage0Intake",
    "Stage0LoadResult",
    "Stage1Matcher",
    "Stage1RuleMatcher",
    "RuleMatchResult",
    "MatchEvidence",
    "Stage2PathFinder",
    "Stage2PathDiscovery",
    "CandidatePath",
    "PathHop",
    "Stage2DiscoveryResult",
    "Stage3Prioritizer",
    "Stage3Prioritization",
    "QueuedPath",
    "Stage3QueueResult",
    "LocalPolicySimulator",
    "LivePolicySimulator",
    "Stage4PolicyVerification",
    "PathSimResult",
    "HopSimResult",
    "Stage4SimResult",
    "CloudGoatSandboxRunner",
    "MockCloudGoatSandboxRunner",
    "SandboxRunResult",
    "Stage5Sandbox",
    "Stage6EvidenceAggregator",
    "Stage6Evidence",
    "PathEvidence",
    "Stage7DecisionEngine",
    "Stage7Decision",
    "VerificationDecision",
    "Stage8OutputAssembler",
    "Stage8Output",
    "Stage6Assembler",
]
