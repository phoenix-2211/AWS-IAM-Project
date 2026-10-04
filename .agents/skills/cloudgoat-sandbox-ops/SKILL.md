---
name: cloudgoat-sandbox-ops
description: Load when installing, configuring, deploying, running or destroying CloudGoat or any Terraform-based vulnerable lab.
---

# CloudGoat Sandbox Ops

## Verified facts
(none yet)

## Unverified / to confirm
- [ ] Current CloudGoat install method and prerequisites (from the current official README)
- [ ] The `config` step and the IP whitelist step
- [ ] Current create / list / destroy commands
- [ ] The list of available scenarios and what each one contains
- [ ] Terraform and AWS CLI install steps on Windows

## Procedure
1. Run `aws sts get-caller-identity`, show the human the account ID, and wait for the human to confirm in writing that it is the dedicated sandbox account.
2. Confirm a billing alarm exists and the CloudGoat IP whitelist is set to the human's IP only.
3. Show each command to the human before running it.
4. Wait for the exact token APPROVE-DEPLOY.
5. Deploy and run inside try/finally.
6. Always destroy in the finally block.
7. Verify the teardown from state (CloudGoat or Terraform state shows nothing left) and record the proof.
8. Save timestamped evidence of every executed step under runs/<run_id>/05_sandbox/.

## Never do
- Deploy without the token.
- Execute any step that is not on the scenario's reviewed, written step list.
- Touch any resource outside the lab.
- Leave anything deployed without telling the human exactly what remains and how to remove it.
- Use credentials from anywhere except the environment or an AWS profile.
