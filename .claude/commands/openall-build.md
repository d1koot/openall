---
description: Phase build - the Builder writes brand-new code from the spec only
---
1. Read `workspace/PROGRESS.md`. Stop if `workspace/spec/SPEC.md` does not exist.
2. Run `python3 scripts/phase.py set build`. From now on do NOT read `input/` yourself.
3. Delegate to the `builder` subagent with the modules to build or fix this round.
4. Run `python3 scripts/originality_check.py`. If it reports copied fragments, send the Builder back to rewrite them.
5. Update PROGRESS.md. Tell the user how to run the build and that the next step is `/openall-verify`.
