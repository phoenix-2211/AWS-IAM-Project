# Open Questions for Team Owners

## 1. Engine 1 Owner Questions
- **Single vs Multi-action**: Does SecurityRule specify a single string `action` or a list of `required_actions` (with AND semantics)?
- **Status field**: Is `status = ACTIVE` the single status field, or is there a separate `approval_status = APPROVED`?
- **Value Sets**: Are the proposed value sets in `vocab_proposal.md` for `relationship`, `principal_type`, `resource_type`, `severity` acceptable?

## 2. Engine 2 Owner Questions
- **Resource Scope**: Will non-Secrets-Manager resources (e.g. Lambda, S3, EC2) be collected in future major versions?
- **Statement Data**: Will normalized statement-level data stay alongside any future collapsed edges (`CAN_PASS_ROLE` / `CAN_ACCESS`)?
- **Shared Matcher**: Who generates `APPLIES_TO` edges, or do both Engine 2 and Engine 3 use a shared matcher algorithm?
- **ID Encoding**: What is the resolved ID encoding scheme replacing the pipe-separated (`|`) format?

## 3. Engine 4 Owner Questions
- **Status Enum & Scope**: Does Engine 4 accept the extended status enum (including `VERIFIED_IN_SANDBOX`)?
- **Metrics Scope**: Per-path vs run-level `runtime_metrics` format?
- **Delivery Mechanism**: File-based outbox handoff vs REST API endpoint vs message queue?
