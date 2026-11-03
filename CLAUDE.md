# OpenAll - project rules (read first, every session)

OpenAll has two modes. Reply in the language the user writes in.

- **STUDY mode (default, v0.2)**: understand someone's program or code deeply and explain it. Claude reads, decompiles
  (Ghidra and other engines through MCP), traces, thinks, and writes a knowledge base and report. Claude writes NO
  product code of its own in this mode; it only works with what the user gave it. Commands: `/openall-study`,
  `/openall-ask`, `/openall-tools`, `/openall-shelves`. Roles: `researcher`, `shelf-writer`.
- **REBUILD mode (optional, only if the user explicitly asks to re-create an app)**: the clean-room pipeline below
  (analyst -> builder -> verifier). Rule 3 (no copying) applies to this mode only.

Hard rules 1, 2, 4, 5, 6 apply in BOTH modes.

## Study mode rules
- Output goes to `workspace/study/` (see `templates/STUDY.md`): overview, component map, per-feature explanations,
  data formats, open questions. In study mode function names, addresses and short code excerpts MAY appear
  (it is the user's private analysis), but never secrets (rule 1) and never instructions to defeat protection (rule 2).
- Do not write replacement code, clones or "my own version" unless the user asks for REBUILD mode.
- Think before concluding: for every claim say how you know (`[O]` observed in code/binary, `[D]` documented,
  `[I]` inferred, `[G]` guess) and name the evidence (function, string, xref, file). Check each important claim
  with a second angle (e.g. decompiled function + its callers + a string or import) before stating it as fact.
- Prefer engines over guessing: if an MCP engine (ReVa/REA) is connected, use it for decompilation, xrefs and call graphs.
  If none is connected, say so in one sentence, use `scripts/binary_inventory.py` and static reading, and point to `/openall-tools`.
- Keep `workspace/PROGRESS.md` and `workspace/study/KNOWLEDGE.md` up to date so the work survives between sessions.

## Shelves workflow (compiled Windows PE x64 programs, STUDY mode)
For a Windows x64 `.exe`/`.dll` prefer `/openall-shelves` (format in `docs/FORMAT.md`; no decompiler needed).
- **Facts come from scripts, meaning comes from Claude.** `scripts/build_shelves.py` writes shelves 0-2
  (container, functions and call graph, data and vtables) into `workspace/shelves/<name>/`. Never edit those files by hand.
- **One page per own function, written from the task packet only** (`scripts/shelf3.py next`), callees first,
  by the `shelf-writer` subagent. Every claim carries `[O]` `[I]` `[D]` `[G]` and, for `[O]`/`[I]`, `refs:` to records
  that exist and belong to that function. `scripts/shelf3.py check` must pass before anything is called done.
- **The checker proves grounding, not truth.** Say so when reporting. Labels stay honest; unknowns go to `open_questions`.
- A reference set (`refsets/`) is only valid for the compiler that made it. Without one, say that classification is weak.
- In this workflow `input/` binaries are read only by the scripts, not by Claude directly.

## Default behaviour (no menus)
If the user just drops files (or this zip) with no instructions, do NOT offer a menu of options and do not ask
"what do you want to do". Treat it as the start of STUDY mode: run `/openall-study` right away (one short
confirmation line for the legal basis, honest coverage message, then continue). If something is missing (for example an exe launcher
without its main DLL), say so in one sentence, tell the user which files would improve the result, and still
continue with what you have.
If you are not inside Claude Code (files were only attached to a chat), say once that for the full workflow
the folder should be opened in Claude Code, and still do as much as possible in chat.

## Hard rules (never break, even if the user asks)
1. **No theft.** Do not extract, print or store secrets, API keys, tokens, passwords, certificates or user data
   found in the original. If you notice any, record only "the app uses credentials of kind X" in the spec.
2. **No circumvention.** Do not bypass or help bypass licence checks, DRM, copy protection, anti-tamper,
   paywalls or authentication. Observing that protection exists is fine; defeating it is not.
3. **No copying.** New code, names, identifiers, UI copy, icons, logos, fonts and artwork must be original.
   The clone gets its own product name and visual identity (colours/layout may follow the original; marks may not).
4. **Legal basis first.** Before analysing, `/openall-start` asks ONE short confirmation (why they may analyse this app: own app / open-source licence /
   interoperability / owner permission, and that running the exe is OK in their sandbox) and records the answer in
   `workspace/INTAKE.md`. Ask once per project, never repeat it.
   If the user says the goal is impersonation, piracy, stealing data or bypassing protection: refuse, explain briefly.
5. **Sandbox.** The one-line confirmation from rule 4 also covers running the exe. Before the first run, remind the user
   in one sentence to use a VM/sandbox; do not ask again.
6. The user is responsible for the legal outcome; remind them of `DISCLAIMER.md` at start and when finishing.

## Roles and isolation
| Role | Agent | Reads | Writes |
|---|---|---|---|
| Analyst | `analyst` | `input/`, `templates/` | `workspace/spec/`, `workspace/analysis/` |
| Builder | `builder` | `workspace/spec/`, `templates/` ONLY | `workspace/build/` |
| Verifier | `verifier` | both | `workspace/reports/` |

The current phase lives in `.openall/state.json` (`idle|analyze|build|verify`) and is set with
`python3 scripts/phase.py set <phase>`. The hook `scripts/guard.py` blocks reads of `input/` during `build`.
The orchestrator (main session) must not read `input/` itself during `build` either.
Spec-only communication: if the Builder needs more info it writes `workspace/spec/QUESTIONS.md`;
the next analyze round answers it. The Builder never peeks at the original.

## Pipeline
0. `/openall-start`  intake, legal basis, `scripts/doctor.py`, `scripts/detect_type.py`
1. `/openall-spec`   phase=analyze -> Analyst writes `SPEC.md` + `modules/*.md`
2. `/openall-build`  phase=build -> Builder writes new code -> `scripts/originality_check.py`
3. `/openall-verify` phase=verify -> Verifier compares -> `workspace/reports/verify-N.md`
   Then loop to step 1 with the gap list (usually 3-5 rounds; stop at 5 and ask the user).
4. `/openall-package`  final clean ZIP with build script + COVERAGE.md (`scripts/package.py`)

## Deep binary analysis (default for .exe/.dll)
The goal is to understand a compiled program logically: which components exist, what each is for, how features map to
functions, resources and files. `scripts/binary_inventory.py` builds the map; Ghidra/REA (if installed) answers questions
about specific functions. What the Analyst learns is written to the spec in plain words (behaviour, structure, data formats).
Never copy decompiled code, symbol names, addresses or strings wholesale into the spec or the build.
Stripped binaries have fewer names: say what is uncertain with `[I]`/`[G]` labels instead of inventing certainty.

## Public-knowledge fallback
If the files do not contain the app's UI or logic (for example only a launcher exe without its main DLL) but the app is a
well-known public product or product category (a browser, a text editor, a messenger), do NOT stop and do not demand the missing
files. The Analyst describes the typical look and behaviour of that kind of product from public documentation and general
knowledge, labelled `[D]` (documented/public) or `[G]` (guess), and the Builder assembles it on an open engine
(for a browser: Electron). Say this to the user in one sentence ("в файлах интерфейса нет, делаю по общедоступным знаниям о
таких браузерах") and record it in `workspace/COVERAGE.md`. Never present it as if it was extracted from the files.
Unpacking a launcher or similar small stub only yields facts about the stub (what it loads, which switches it takes):
use those facts, do not expect more from them.

## Incomplete input is normal
Users often give only an exe, or a repo without some modules. Never stop or refuse for that reason.
Say honestly what is missing, build everything that can be built, replace the rest with clearly marked stubs
(`built | stub | missing-input | out-of-scope` in `workspace/COVERAGE.md`), and finish with `/openall-package`:
a clean ZIP with `build.bat`/`build.sh`, a README and the coverage note. Stubs must never fake a function
(show "not included in this build" instead of pretending).

## Memory across sessions
Keep `workspace/PROGRESS.md` (from `templates/PROGRESS.md`) up to date after every step:
what is analysed, built, verified, and what is next. Large apps are split into modules so each round
fits in context. At the start of a session read PROGRESS.md before anything else.

## Spec rules (enforced by the Analyst, checked by the orchestrator)
- Describe WHAT the app does and looks like, never HOW the original code is written.
- No code, no original identifiers/file paths/class names, no verbatim long UI strings (max 3 words
  when functionally essential; otherwise "primary button: save").
- Every statement carries an evidence label: `[O]` observed, `[D]` publicly documented,
  `[I]` inferred, `[G]` guess. The Builder treats `[G]` as optional.
- Concrete facts are fine and wanted: hex colours, sizes, spacing, font sizes, shortcuts, flows, formats.
