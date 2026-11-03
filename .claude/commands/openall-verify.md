---
description: Phase verify - compare the new build with the original and list gaps
---
1. Run `python3 scripts/phase.py set verify`.
2. Remind the user that the original must only run in a sandbox/VM and get confirmation.
3. Delegate to the `verifier` subagent.
4. Show the user the overall score and top gaps from `workspace/reports/verify-<N>.md`.
5. Run `python3 scripts/phase.py set idle`. Update PROGRESS.md (round number).
   If the score is not good enough and rounds < 5, suggest `/openall-spec` again with the gap list; otherwise stop and summarise.
   When the result is good enough, suggest `/openall-package`. When finishing, remind the user of DISCLAIMER.md and to give the clone its own name and assets.
