---
name: run-artifacts-and-resume
description: Use at the start and end of every stage and whenever resuming after a chat reset.
---

# Run Artifacts and Resume

## Rules
- Run layout: runs/<run_id>/{00_input,01_matches,02_paths,03_queue,04_simulator,05_sandbox,06_result} plus run_manifest.json and run.log.
- All artifacts hashed.
- engine3/PROGRESS.md is updated after every step with: stage, step, status, evidence path, open questions, next action.
- A new chat resumes by reading PROGRESS.md and the last STAGE REPORT, re-running the last stage's RECHECK commands before trusting any "complete" tag.
- Tags are engine3-sN-complete only after all RECHECKs pass with pasted evidence; engine3-sN-incomplete otherwise.
- One file at a time.

## Verified facts
(none yet)

## Unverified / to confirm
(none yet)
