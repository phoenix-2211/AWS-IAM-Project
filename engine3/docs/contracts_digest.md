# Contracts Digest & Provenance Record

## 1. Provenance Registry
- **`IAMGraph_v0.1.md`**: Engine 2's contract text, unmodified. It is a DRAFT pending review. Where the fixture and this document disagree, the document wins and differences are reported.
- **`iamgraph_fixture.json`**: ENGINE3-SIDE DRAFT rebuilt from section 8 of that contract (13 nodes, 21 edges: 7 `HAS_PERMISSION`, 5 `TRUSTED_BY`, 9 `APPLIES_TO`). It is NOT Engine 2's own fixture file. Node/edge ID formats are placeholders, not Engine 2's scheme. Top-level `x_provenance` field is preserved in `extras`.
- **`SecurityRule_sample.json`**: ENGINE3-SIDE DRAFT with 5 rules, all labelled `TEST_ONLY`. Values for `relationship`, `resource_type`, and `condition` are PLACEHOLDERS because Engine 1 has not specified value sets; marked `PROPOSED`, not `DERIVED`. `mitre` is `null` on purpose. Rule `TEST-IAM-005` has status `DRAFT` (tests loader skipping) and `TEST-IAM-004` targets Lambda (tests `NOT_REPRESENTABLE` handling).
- **`engine4_handoff_example.json`**: Engine 3 draft of `VerificationResult` for Engine 4, synthetic, pending Engine 4's agreement.

---

## 2. IAMGraph Contract v0.1
* **Source Files**: [`engine3/docs/contracts/IAMGraph_v0.1.md`](file:///D:/Project%20IAM/engine3/docs/contracts/IAMGraph_v0.1.md) and [`engine3/docs/contracts/iamgraph_fixture.json`](file:///D:/Project%20IAM/engine3/docs/contracts/iamgraph_fixture.json)
* **Contract Name**: `"IAMGraph"` (cite: `iamgraph_fixture.json` `$.contract_name`, L2)
* **Contract Version**: `"0.1"` (cite: `iamgraph_fixture.json` `$.contract_version`, L3)

### Observed Enum Values & Types (Traceable):
* `snapshot.origin`: `"synthetic_fixture"` (cite: `iamgraph_fixture.json` `$.snapshot.origin`, L14), `"aws_collection"` (cite: `IAMGraph_v0.1.md` Section 2, L32)
* `snapshot.collection_status`: `"complete"` (cite: `iamgraph_fixture.json` `$.snapshot.collection_status`, L15), `"partial"` (cite: `IAMGraph_v0.1.md` Section 2, L33)
* `node.type`:
  * `"User"` (cite: `iamgraph_fixture.json` `$.nodes[0].type`, L37)
  * `"Role"` (cite: `iamgraph_fixture.json` `$.nodes[1].type`, L44)
  * `"Resource"` (cite: `iamgraph_fixture.json` `$.nodes[4].type`, L127)
  * `"ServicePrincipal"` (cite: `iamgraph_fixture.json` `$.nodes[5].type`, L137)
  * `"Permission"` (cite: `iamgraph_fixture.json` `$.nodes[6].type`, L143)
* `edge.type`:
  * `"HAS_PERMISSION"` (cite: `iamgraph_fixture.json` `$.edges[0].type`, L370)
  * `"TRUSTED_BY"` (cite: `iamgraph_fixture.json` `$.edges[7].type`, L419)
  * `"APPLIES_TO"` (cite: `iamgraph_fixture.json` `$.edges[12].type`, L469)
* `edge.via` (for `TRUSTED_BY` edges):
  * `"principal_arn"` (cite: `iamgraph_fixture.json` `$.edges[7].via`, L422)
  * `"service"` (cite: `iamgraph_fixture.json` `$.edges[9].via`, L442)
  * `"account"` (cite: `IAMGraph_v0.1.md` Section 4.2, L117)
  * `"wildcard"` (cite: `IAMGraph_v0.1.md` Section 4.2, L117)

---

## 3. SecurityRule / ApprovedRule Contract
* **Source File**: [`engine3/docs/contracts/SecurityRule_sample.json`](file:///D:/Project%20IAM/engine3/docs/contracts/SecurityRule_sample.json)

### Observed Enum Values & Types (Traceable):
* `rule_id`: `"TEST-IAM-001"` (cite: `SecurityRule_sample.json` `$[0].rule_id`, L3)
* `principal_type`: `"role"` (cite: `SecurityRule_sample.json` `$[0].principal_type`, L7)
* `action`: `"iam:PassRole"` (cite: `SecurityRule_sample.json` `$[0].action`, L8)
* `resource_type`: `"iam_role"` (cite: `SecurityRule_sample.json` `$[0].resource_type`, L9)
* `relationship`: `"can_pass_role"` (cite: `SecurityRule_sample.json` `$[0].relationship`, L10)
* `severity`: `"HIGH"` (cite: `SecurityRule_sample.json` `$[0].severity`, L11)
* `status`: `"ACTIVE"` (cite: `SecurityRule_sample.json` `$[0].status`, L22), `"DRAFT"` (cite: `SecurityRule_sample.json` `$[4].status`, L114)
* `version`: `"0.1"` (cite: `SecurityRule_sample.json` `$[0].version`, L21)

---

## 4. Ambiguities & Contradictions Flagged
1. **Contract Diagram vs Canonical Architecture**: Engine 1 contract diagram labels the rule consumer as "Engine 2", whereas the canonical architecture routes rules directly to Engine 3. *Flagged per Step 0.2 instructions (don't fix).*
2. **ID Collision Warning**: IAMGraph v0.1 Section 6 flags that pipe-separated ID schemes (`|`) collide when IAM paths contain `|`. All Engine 3 node and edge IDs must be treated as opaque strings.
3. **Single vs Multi-action**: Contract sample specifies `action` as a single string (`"iam:PassRole"`). Rules requiring multiple simultaneous actions must be flagged as `NEEDS_MULTI_ACTION` and held in the backlog until Engine 1 answers.
