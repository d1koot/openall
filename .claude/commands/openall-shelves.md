---
description: STUDY mode for compiled Windows x64 programs - facts on shelves, meaning pages, checked book (no Ghidra needed)
argument-hint: <optional: file name in input/>
---
Target: $ARGUMENTS (if empty, use the .exe/.dll in `input/`; if there are several, ask once which one).

This is the shelves workflow of `docs/FORMAT.md`: scripts produce the FACTS (shelves 0-2), the `shelf-writer` writes
MEANING (shelf 3) function by function from task packets, a checker proves every claim is grounded, then the book
is rendered. Work in the user's language. Rules 1, 2, 4, 5, 6 of `CLAUDE.md` apply.

1. Read `CLAUDE.md`, `DISCLAIMER.md`, `workspace/PROGRESS.md` (continue from it if it exists).
2. Legal basis: once per project (skip if `workspace/INTAKE.md` exists), same one-line confirmation as `/openall-study`.
   Refuse if the aim is piracy, data theft, impersonation or defeating protection.
3. `python3 scripts/phase.py set study`, then `python3 scripts/doctor.py`. If `capstone` or `pefile` is absent, run
   `pip install capstone pefile` (tell the user in one sentence first). If the network blocks it (pypi.org 403, offline),
   use the copies shipped in the project: `pip install --no-index --find-links vendor capstone pefile`.
   Only Windows PE **x64** is supported; if the
   file is something else (32-bit, .NET, ELF, APK, source), say so in one sentence and use `/openall-study` instead.
4. **Resume check first.** If `workspace/shelves/<name>/shelf3/` already contains pages, do NOT rebuild shelves 0-2
   (it could change classification under the existing pages): run `shelf3.py stubs` and `shelf3.py status`, then go
   straight to step 6. A user can resume in a new session by unzipping a saved `<name>_progress.zip` (see step 6c)
   into the project folder.
   Otherwise build the facts: `python3 scripts/build_shelves.py input/<file> --out workspace/shelves/<name>`.
   Read the first lines it prints:
   - `reference set: <file> (N hashes)` is good: runtime/compiler code will be recognised.
   - `reference set: none for this toolchain` means almost everything will look unknown. Tell the user in two sentences:
     the reference set is made from small programs of their own compiled with the SAME compiler (see
     `tests/shelf_demo_cpp/README.md`, `setup_windows.bat`), learned with
     `python3 scripts/build_shelves.py --learn ref1.exe ref2.exe`. Continue anyway, but say coverage will be weaker.
   Report in 3 sentences: toolchain, how many functions, how many look like the program's own (`unknown`) versus
   runtime/library, whether C++ vtables were found (`T:` records with `class_hint`).
5. `python3 scripts/shelf3.py stubs --shelves workspace/shelves/<name>` (one-line pages for runtime/library).
6. Loop until `python3 scripts/shelf3.py next --batch 8 --shelves <dir>` says all done. A packet holds up to 8
   small independent functions (fewer, or just one, when they are large), callees first; this keeps the number of
   rounds low. Do not read `input/` yourself and do not add facts that are not in the packet.
   a. Give the packet to the `shelf-writer` subagent. In claude.ai chat there are no subagents: write the pages
      yourself, following `.claude/agents/shelf-writer.md`. One page file per function in the packet.
   b. After each packet run `python3 scripts/shelf3.py check --shelves <dir>` once. On failure fix the exact lines
      it reports. Never loosen the checker and never edit shelf 0-2 files by hand.
   c. Every ~3 packets append one line to `workspace/PROGRESS.md` (`python3 scripts/shelf3.py status ...`).
      If the folder `/mnt/user-data/outputs` exists (claude.ai chat, usage limits can stop a long run), also zip
      `workspace/shelves/<name>` to `/mnt/user-data/outputs/<name>_progress.zip` every ~4 packets, and tell the user
      once: this file lets them continue later (unzip into the project, run the command again).
   Large functions (hundreds of instructions) are allowed; expect `confidence: low|medium`. Trivial functions
   (a few instructions) get a two-line page.
7. Write `<dir>/shelf3/OVERVIEW.md` yourself: 4-8 bullets, each `- claim [O|I|D|G] refs: ids`, saying what the
   program is and does. Class names from `T:` records (`class_hint`) may be used as `[I]`. Then `check`, then
   `python3 scripts/shelf3.py book --shelves <dir>`.
8. Finish in 8-10 lines: where the book is (`<dir>/book/`), how many functions have pages, what stays unknown and
   why, confidence overall, and the honest limits (toolchain without reference set, template/STL code that cannot
   be told from the program's own, indirect calls, nothing was executed). Suggest `/openall-ask <question>` next.
   Remind once of `DISCLAIMER.md`. The book is private: do not publish it.
