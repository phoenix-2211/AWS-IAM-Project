# Vocabulary Proposal (Gate: APPROVE-VOCAB)

This proposal defines the value sets for Engine 1 SecurityRule fields and Engine 2 IAMGraph node/edge fields.

## 1. Value Sets

### `principal_type`
- `role`: **DERIVED** (cite: `SecurityRule_sample.json` `$[0].principal_type`)
- `user`: **PROPOSED** (needs Engine 1 confirmation; derived from IAMGraph `User` node type)
- `service`: **PROPOSED** (needs Engine 1 confirmation; derived from IAMGraph `ServicePrincipal` node type)

### `resource_type`
- `iam_role`: **DERIVED** (cite: `SecurityRule_sample.json` `$[0].resource_type`)
- `secretsmanager_secret`: **PROPOSED** (needs Engine 1 confirmation; derived from IAMGraph `secretsmanager:secret`)

### `relationship`
- `CAN_PASS_ROLE`: **DERIVED** (cite: `SecurityRule_sample.json` `$[0].relationship`)
- `CAN_ASSUME_ROLE`: **PROPOSED** (needs Engine 1 confirmation; derived from `sts:AssumeRole` action)
- `CAN_READ_SECRET`: **PROPOSED** (needs Engine 1 confirmation; derived from `secretsmanager:GetSecretValue` action)

### `severity`
- `HIGH`: **DERIVED** (cite: `SecurityRule_sample.json` `$[0].severity`)
- `CRITICAL`: **PROPOSED** (needs Engine 1 confirmation)
- `MEDIUM`: **PROPOSED** (needs Engine 1 confirmation)
- `LOW`: **PROPOSED** (needs Engine 1 confirmation)

### `status`
- `ACTIVE`: **DERIVED** (cite: `SecurityRule_sample.json` `$[0].status`)
- `DISABLED`: **PROPOSED** (needs Engine 1 confirmation)
- `DRAFT`: **PROPOSED** (needs Engine 1 confirmation)

### `condition`
- `null` / empty: **DERIVED** (cite: `SecurityRule_sample.json` `$[0].condition`)
- Object mapping: **PROPOSED** (IAM Condition block format)
