# Cost Guardrails (`cost_guardrails.md`)

## AWS Sandbox Safety Policy
1. **IAM and Policy Simulator Calls**: $0 cost.
2. **Billing Alarm / Budget Recommendation**: Ensure AWS Budget alarm is set for $5.00 USD threshold in the target account.
3. **Region Pinning**: All deployments MUST pin region to `us-east-1`.
4. **Mandatory Teardown**: Every deployment MUST execute destroy immediately in a `try/finally` block.
