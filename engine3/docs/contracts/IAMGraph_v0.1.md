# Engine 2 → Engine 3: IAMGraph Contract v0.1

**Status:** Draft — Pending Review and Agreement  
**Purpose:** Define the data Engine 2 provides to Engine 3 for IAM rule matching, attack-path discovery, and verification.

## 1. Overview

Engine 2 collects AWS IAM information, normalizes policies, resolves trust relationships, builds the IAM graph, and exports it as a JSON snapshot.

Engine 3 consumes this snapshot to identify candidate attack paths and perform further checks using the AWS IAM Policy Simulator and CloudGoat.

The graph represents potential relationships. The existence of an edge does not, by itself, prove that an action is authorized or exploitable.

## 2. Proposed JSON Structure

The proposed top-level structure contains:

- `contract_name`: `"IAMGraph"`
- `contract_version`: `"0.1"`
- `snapshot`: Snapshot metadata and collection status
- `nodes`: IAM entities and policy statements
- `edges`: Relationships between entities
- `warnings`: Unsupported or unresolved cases

### Snapshot metadata

The snapshot contains:

- `snapshot_id`
- `account_id`
- `collected_at`
- `origin`: `aws_collection` or `synthetic_fixture`
- `collection_status`: `complete` or `partial`
- `collected_resource_types`
- `coverage`

Each coverage entry identifies the component, region, status, and relevant details.

If essential IAM authorization data cannot be collected, Engine 2 should not export a misleadingly complete graph. If a regional resource listing fails, the snapshot should indicate partial coverage.

## 3. Proposed Node Types

### 3.1 User

Represents an IAM user.

- ID: User ARN
- Includes the permissions-boundary ARN, which may be null.

### 3.2 Role

Represents an IAM role.

- ID: Role ARN
- Includes the decoded trust policy.
- Includes the permissions-boundary ARN, which may be null.

### 3.3 Permission

Represents one statement from an identity-based policy.

It includes:

- `effect`
- `actions` or `not_actions`
- `resources` or `not_resources`
- `condition`
- `raw_statement`
- `provenance`

Provenance records the policy type, name, ARN where applicable, version ID, owner ARN, and statement index.

The proposed design shares nodes for statements from managed policies. Inline-policy statements are owner-specific.

Both Allow and Deny statements must be preserved.

### 3.4 Resource

The initial proposed resource scope is AWS Secrets Manager secrets.

- Resource type: `secretsmanager:secret`
- ID: Resource ARN
- Contains resource metadata only, not secret values.

Additional resource types can be added later.

### 3.5 ServicePrincipal

Represents an AWS service principal.

- ID format: `svc:<name>`

## 4. Proposed Edge Types

### 4.1 HAS_PERMISSION

Connects a User or Role to a Permission node.

The edge represents an identity-policy attachment or an effective association derived from group membership.

Proposed fields include `via_group`, which is null for direct associations and identifies the group when permissions are flattened to a user.

Deny statements are included; the edge itself does not mean that the permission is allowed.

### 4.2 TRUSTED_BY

Connects a trusted principal to a Role.

The proposed direction is:

`Principal → TRUSTED_BY → Role`

The edge is derived from an Allow statement in the role's trust policy whose action covers `sts:AssumeRole`.

Proposed fields include:

- `via`: `principal_arn`, `account`, `wildcard`, or `service`
- `has_condition`
- `statement_index`
- `matched_principal`, where applicable

The draft proposes resolving account and wildcard principals into individual User and Role edges within the snapshot. Unresolved cross-account principals produce a warning rather than an ordinary resolved edge.

**Important:** This edge represents a structural trust relationship, not proof that role assumption will succeed. Conditions, identity policies, explicit Deny statements, and other AWS controls can affect the outcome. The exact edge semantics and fan-out behavior require agreement with you.

### 4.3 APPLIES_TO

Connects a Permission node to a Role or Resource when the statement's resource pattern syntactically matches the target ARN.

The proposed behavior is:

- Allow and Deny statements can both produce edges.
- Conditions are not evaluated when creating these edges.
- `NotResource` and policy variables do not produce ordinary matching edges in the current draft.
- Unsupported cases should be represented through warnings.
- Users are not currently included as targets.
- Wildcard matching is a structural approximation, not an authorization decision.

Whether i should generate these edges, you should calculate matches itself, or both should use a shared matcher remains open for review.

## 5. Policy Representation and Limitations

The current proposal preserves raw statements and provenance so that downstream analysis can inspect the original policy data.

The draft does not fully model or evaluate all AWS authorization mechanisms.

Known limitations include:

- `NotAction` and `NotResource`
- Policy variables
- Trust-policy `NotPrincipal` and Deny statements
- Unresolved cross-account and federated principals
- Permissions boundaries beyond recording their ARN
- Service control policies (SCPs)
- Resource control policies (RCPs)
- Session policies
- Resource-based policies
- Resource types outside the initial collection scope

Unsupported or unresolved cases should produce warnings where applicable.

A missing edge must not automatically be interpreted as proof that no relationship or attack path exists.

## 6. IDs and Versioning

The draft proposes deterministic IDs for nodes and edges.

- User, Role, and Resource nodes use their ARNs.
- ServicePrincipal nodes use `svc:<name>`.
- Permission IDs incorporate the policy identity, version where applicable, and statement index.
- Edge IDs incorporate their type, endpoints, and relevant qualifiers.
- Snapshot IDs incorporate the account and collection timestamp, with a suffix if needed to avoid collisions.

**Review finding:** The proposed pipe-separated ID scheme has a potential collision because `|` is permitted in IAM paths. The encoding must be corrected or replaced before implementation.

The proposed versioning policy is:

- Minor revisions for additive optional fields.
- Major revisions for changes to required fields, node or edge types, enums, semantics, or ID formats.

The precise version-field placement and parsing policy remain to be agreed.

## 7. Validation Requirements

The proposed validator should check:

1. Contract name and version.
2. Unique node and edge IDs.
3. Valid edge endpoints and type combinations.
4. ARN and account consistency.
5. Permission-field invariants.
6. Consistency between normalized policy fields and raw statements.
7. Correct derivation of trust and resource-matching edges.
8. Orphan Permission nodes and other invalid relationships.
9. Warning references.
10. Consistency between coverage and collection status.
11. Deterministic ordering where required.

The synthetic fixture has been checked using a scratchpad validator, including mutation tests. However, a formal project-level validator and JSON Schema still need to be established. The reported checks should not be treated as proof that every AWS semantic detail is correct.

## 8. Synthetic Fixture

The proposed fixture contains 13 nodes and 21 edges:

- 7 `HAS_PERMISSION`
- 5 `TRUSTED_BY`
- 9 `APPLIES_TO`

It illustrates a developer, IAM roles, a production secret, role trust relationships, permissions, a group-derived Deny, conditional PassRole, and an unresolved cross-account trust case.

The fixture is intended to demonstrate candidate relationships, not prove exploitability.

The review identified additional cases that should be tested:

- A managed policy shared by two principals
- Conditional trust
- Wildcard trust
- `NotAction`
- Partial collection coverage
- A non-null permissions boundary
- An ARN containing `|` in its path

## 9. Engine 2 and Engine 3 Responsibilities

**Engine 2 owns:**

- Read-only AWS collection
- Policy normalization and provenance
- Trust-policy parsing and principal resolution
- Graph construction
- Coverage and warning tracking
- Graph validation and export

**Engine 3 owns:**

- IAM rule matching
- Candidate attack-path discovery
- Interpretation of graph relationships
- AWS IAM Policy Simulator checks
- CloudGoat sandbox verification
- Verification-result generation

Neither `HAS_PERMISSION`, `TRUSTED_BY`, nor `APPLIES_TO` should be interpreted as proof of authorization on its own.

## 10. Decisions Requiring Agreement

Before the contract is frozen, the Engine 2 and Engine 3 owners need to agree on:

1. Version-field placement and compatibility rules.
2. Node and edge names and semantics.
3. `TRUSTED_BY` direction, `via` values, and traversal rules.
4. Account-level and wildcard trust handling.
5. Whether and how `APPLIES_TO` edges are generated.
6. Wildcard behavior and the treatment of Deny statements.
7. The final deterministic ID scheme.
8. The treatment of unsupported policy constructs.
9. Partial-coverage and degraded-analysis signaling.
10. Validation requirements and fixture coverage.

## 11. Proposed Implementation Approach

Work that can begin without finalizing the JSON schema includes read-only collection, policy normalization, provenance capture, trust-policy parsing, coverage tracking, and synthetic test preparation.

The serializer, final ID scheme, contract schema, and edge-generation behavior should be finalized after the outstanding decisions are agreed.

## 12. Current Status

**IAMGraph v0.1 remains a proposal pending review.**

The next step is for you to review the contract, identify any fields or semantics that do not fit Engine 3's requirements, and agree on the outstanding decisions.

Once we both agree, the contract and fixtures can be updated and the interface frozen before implementation depends on it.
