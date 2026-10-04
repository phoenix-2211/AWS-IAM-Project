# Engine 3 (Attack + Verify)

Engine 3 consumes IAM graph snapshots (`IAMGraph v0.1`) and security rules (`SecurityRule[]`), matches rules, discovers attack paths, ranks them, verifies them, and emits a `VerificationResult v0.1`.
