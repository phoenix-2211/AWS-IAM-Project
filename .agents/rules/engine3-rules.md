ENGINE 3 — ALWAYS-ON RULES

HONESTY
1. Never edit an expected value in a test to make it pass. If a test fails, either the code or the oracle is wrong. If you believe the oracle is wrong, stop, write audit/oracle_change_requests/<n>.md explaining why from the contract or AWS documentation, and wait for human approval.
2. Oracles come before code. Hand-derive expected outputs, with written reasoning, and commit them before writing the implementation.
3. Empty logs are a failure. Every pipeline stage writes structured evidence to runs/<run_id>/<stage>/. A stage with no artifacts is reported FAILED.
4. Report failures first. Every report starts with FAIL / INCONCLUSIVE / SKIPPED counts, then passes. Never open with "all done".
5. Never mark a phase complete or create a git tag until the phase audit has produced audit/phase_N_report.json with per-check evidence paths.
6. Distinguish proven from assumed. A simulator "allowed" is not a confirmed exploit.
7. If a contract field, enum value, or AWS behaviour is unspecified, stop and ask. Never invent vocabulary or semantics.
8. Verify AWS, CloudGoat, Terraform, and Policy Simulator behaviour from current official documentation at the time of use. Record the URL and retrieval date next to anything you encode. Do not rely on memory.

SAFETY
9. No secrets in the repo, docs, logs, fixtures, or chat output. Credentials come from the environment or an AWS profile only. Scan before every commit.
10. Never call AWS, run a Policy Simulator Live call, or deploy/destroy anything without the matching human gate token below.
11. CloudGoat and other vulnerable labs run only in a dedicated sandbox account whose account ID the human has confirmed in this session.
12. Always tear down what you deploy, and verify the teardown.

GATES (the human must type the exact token; "continue", "ok", "go ahead" do NOT count)
- APPROVE-VOCAB        before locking rule/graph vocabulary adapters
- APPROVE-LIVE-SIM     before the first Live Policy Simulator call
- APPROVE-DEPLOY       before any CloudGoat/Terraform deploy (after account ID confirmation)
- APPROVE-DESTROY      before any destroy that is not the automatic cleanup

SCOPE
13. Engine 3 owns: rule matching, attack-path discovery, verification queue, Policy Simulator checks, CloudGoat verification, VerificationResult emission.
14. Engine 3 does NOT own: AWS collection or graph construction (Engine 2), rule generation or approval (Engine 1), risk scoring/centrality/GNN, explanations, MITRE mapping, dashboards, human review UI (Engine 4).
15. An IAMGraph edge is never proof of authorization. A missing edge is never proof of absence.
16. Treat IDs as opaque strings. Never split an ID on "|".
17. Old code in legacy/ is never imported and never cited as evidence that anything works.
