---
name: evidence-redaction
description: Use whenever raw tool output, logs or sandbox output may enter a file, a result, or a chat message.
---

# Evidence Redaction

## Rules
- Redact AWS access key IDs (AKIA/ASIA prefixes), secret access keys, session tokens, any Secrets Manager returned value, Authorization headers, and anything resembling a private key.
- Cap 200 lines per path.
- Raw logs stay under runs/<id>/ (gitignored) and are referenced by sandbox_evidence_ref.
- Every redactor change needs a test that PLANTS dummy secrets in fake output and fails if any survives.
- A final scan runs over the whole output before it is written (a hit blocks delivery and names the JSON path, never the value).
- Never paste credentials into chat.
- Account IDs are not secrets but are not needed in examples.

## Verified facts
(none yet)

## Unverified / to confirm
- [ ] Full list of credential formats worth detecting
- [ ] False-positive rate on 40-character strings
