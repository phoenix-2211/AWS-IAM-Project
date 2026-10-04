---
name: aws-iam-semantics
description: Load when reasoning about IAM policy evaluation, trust policies, wildcard matching, NotAction/NotResource, permissions boundaries, sts:AssumeRole or iam:PassRole semantics.
---

# AWS IAM Semantics

## Verified facts
(none yet)

## Unverified / to confirm
- [ ] Policy evaluation order and explicit-Deny precedence
- [ ] How Action/Resource wildcards match; how NotAction and NotResource match
- [ ] Policy variables and what they do to matching
- [ ] When a same-account role trust policy that names a principal ARN does or does not ALSO require an identity-side sts:AssumeRole Allow, compared with account-root trust
- [ ] Effect of a permissions boundary on allowed actions
- [ ] iam:PassRole condition keys (for example iam:PassedToService) and what they restrict
- [ ] Effect of SCPs, RCPs and session policies, and whether they matter for our analysis

## Procedure
1. Before encoding any IAM rule into code, find the official AWS documentation page for it.
2. Add the fact, the URL and the retrieval date to docs/aws_semantics.md and to "Verified facts" in this file.
3. Write the test that proves the rule BEFORE the code (see always-on rules 1 and 2).
4. If documentation is unclear or contradictory, stop and ask the human; mark the behaviour INCONCLUSIVE in outputs.

## Never do
- Encode a semantic rule without a cited source.
- Treat a wildcard match as an authorization decision.
- Treat a missing edge or a missing statement as proof that access is impossible.
