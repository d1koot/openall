---
description: Package the finished build into a clean ZIP with a build script and an honest coverage note
---
1. Run `python3 scripts/phase.py set idle`.
2. Make sure `workspace/COVERAGE.md` is up to date (from `templates/COVERAGE.md`): every feature is `built`, `stub`,
   `missing-input` or `out-of-scope`.
3. Make sure `workspace/build/` has `build.bat` (Windows) and `build.sh` (macOS/Linux) that compile/run the project
   from scratch, and a short `README.md` for the clone. Ask the `builder` subagent to add them if missing
   (it must still not read `input/`).
4. Run `python3 scripts/originality_check.py`; fix findings first.
5. Run `python3 scripts/package.py`. It creates `workspace/dist/<name>.zip` containing the build, COVERAGE.md and DISCLAIMER.md.
6. Tell the user in a few lines: where the ZIP is, how to build it (`build.bat`), and what is stubbed or missing and why.
   Remind them of DISCLAIMER.md and to keep the clone's own name and assets.
