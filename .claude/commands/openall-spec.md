---
description: Phase analyze - the Analyst studies input/ and writes the spec
---
1. Read `workspace/PROGRESS.md` and `workspace/INTAKE.md`. Stop if there is no legal basis recorded.
2. Run `python3 scripts/phase.py set analyze`.
3. Delegate to the `analyst` subagent. Give it: target scope (whole app or the modules listed in PROGRESS.md),
   the gap list from the last `workspace/reports/verify-*.md` if any, and open questions from `workspace/spec/QUESTIONS.md`.
   Large apps: one module group per round.
4. When done, check `workspace/spec/SPEC.md` yourself: no code, no original identifiers, labels present.
   Send it back to the analyst if not.
5. Update PROGRESS.md and tell the user the next step is `/openall-build`.
