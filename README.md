# OpenAll

**Study a compiled Windows program with Claude: facts on shelves first, meaning second, nothing unchecked.**

> Status: **v0.3.0, release candidate / prototype.** The shelves workflow below was tested on four small programs we
> wrote ourselves. Read "What was tested" and "Known limits" before you rely on it. Read [DISCLAIMER.md](DISCLAIMER.md)
> before use: study only programs you own, have permission for, or may lawfully study.

## What it does

For a Windows x64 `.exe`/`.dll` the workflow separates **facts** from **interpretation**:

1. **Shelves 0-2 (facts, by scripts):** `scripts/build_shelves.py` lists the functions, the call graph, strings,
   imports, data, vtables (with class names when the file has type info), exception handlers and `switch` tables.
   No model is involved, nothing is guessed. Compiler and library code is recognised through *reference sets*
   (hashes of small programs you built with the same compiler), so mostly the program's own code is left.
2. **Shelf 3 (meaning, by Claude):** one short page per own function, written bottom-up from a task packet. Every
   claim carries a label (`[O]` observed, `[I]` inferred, `[D]` documented, `[G]` guess) and cites records.
3. **Checker:** `scripts/shelf3.py check` fails a page whose claim has no label, cites a record that does not exist
   or is not connected to that function, skips a callee, or looks like it contains a secret.
4. **Book:** `scripts/shelf3.py book` renders a private, readable book (overview, functions, library list, open
   questions) and refuses to run while the check fails.

The checker proves that claims are **grounded**, not that they are **true**. It also cannot tell that a page is
*complete*; completeness comes from facts on the shelves (unresolved jumps, handlers, tables are counted there).

## Quick start

1. Windows: unzip the project, double-click `setup_windows.bat` (checks Python and a 64-bit `g++`, offers to install
   them with winget and asks first, builds three tiny reference programs and learns them for your compiler).
   Other systems: `pip install capstone pefile`, and build `tests/shelf_demo_cpp/ref_*.cpp` with your compiler, then
   `python3 scripts/build_shelves.py --learn ref_empty.exe ref_stl.exe ref_numeric.exe`.
2. Put the program you want to study (a 64-bit Windows `.exe`/`.dll`, built by the same compiler) into `input/`.
3. Open the folder in Claude Code (or upload the zip to a Claude chat that can run code) and run `/openall-shelves`.
   Answer the legal-basis question. The book appears in `workspace/shelves/<name>/book/`.
4. No network for `pip`? `pip install --no-index --find-links vendor capstone pefile`.
5. Out of usage limits halfway? The command saves `<name>_progress.zip` in chats; unzip it into the project and run the
   command again, it continues.

Check the setup any time: `python3 scripts/doctor.py`. Run the tests: `python3 tests/run_tests.py`.

## What was tested

Four programs written by us (a word counter in C; a shape/vtable program, an expression calculator and a bytecode
machine in C++), built with MinGW-w64 GCC 13 (msvcrt) and GCC 16.2 (UCRT, WinLibs), stripped of symbols.

| Test | Result |
|---|---|
| C word counter, 165 functions | exactly the 2 own functions left as "own"; pages matched the source |
| Blind run: expression calculator (source never seen by the model) | 9 pages + overview, every claim matched the source |
| Blind run: bytecode machine (source never seen by the model) | 23 pages + overview; every claim matched; the predicted program output and CRC were exact |
| Unit tests (`tests/`) | 13 tests: checker rules, ordering, recursion, builder smoke tests |

Grading was done by comparing with the source code by the project's own assistant, not by an independent reviewer.
Details, numbers and every bug found on the way: [docs/FORMAT.md](docs/FORMAT.md) (sections 8.1-8.9).

## Known limits

- **Windows PE x64 only.** No 32-bit, .NET, ELF, Mach-O, Android.
- **Only GCC (MinGW-w64) builds were tested.** MSVC and clang are untested. Jump-table handling in the MSVC style is
  written but never ran on real MSVC output; MSVC exception tables and MSVC type information (RTTI) are not read.
- **Reference sets are per compiler and per analyser version.** Without a set for your compiler most library code
  looks like the program's own and a run gets long and expensive. The builder says when a set is missing or stale.
- **C++ template code** (STL) that the compiler instantiated in the program cannot be told from the program's own code.
- **Static analysis only.** Nothing is executed. Packed or obfuscated files are described, not unpacked.
- **Indirect calls and jumps** that are not plain `switch` tables stay unresolved and are only counted.
- **Results depend on the model** that writes the pages; tested with one strong model. Names of functions are the
  model's descriptions, not recovered symbols; class names come from type info only when the file has it.
- **Cost.** A small program (20-30 own functions) is on the order of tens of thousands of tokens; library code that
  is not recognised multiplies it. Batched task packets keep the number of rounds low.
- The guard hook (`scripts/guard.py`) is best-effort, not a security boundary.

## Other modes (kept from v0.2, not tested in this release)

- **STUDY with engines:** `/openall-tools`, `/openall-study`, `/openall-ask` (Ghidra / REA / ReVa through MCP).
  See [docs/TOOLS.md](docs/TOOLS.md).
- **REBUILD (experimental):** a clean-room pipeline with three separated roles (Analyst sees the original and writes a
  behavioural spec; Builder sees only the spec and writes new code under its own name and identity; Verifier compares).
  It is untested in this release and does not promise a legally safe or faithful copy.
  Commands: `/openall-start`, `/openall-spec`, `/openall-build`, `/openall-verify`, `/openall-package`.

## Safety and responsibility

Study only your own programs, open-source programs under their licences, programs whose owner allows it, or what the
law of your country allows for interoperability and learning. Run unknown executables only in a sandbox. Never publish
secrets you may find. The generated book is for private use. The authors are not responsible for what people do with
it; see [DISCLAIMER.md](DISCLAIMER.md).

## Layout

`CLAUDE.md` rules for Claude · `.claude/` commands and roles · `scripts/` tools · `docs/FORMAT.md` format and
measurements · `refsets/` reference hashes · `vendor/` offline Python packages · `tests/` tests and demos ·
`templates/` document templates · `input/` your program (never committed) · `workspace/` results (never committed).

## Licence

MIT, see [LICENSE](LICENSE). Third-party packages: [THIRD_PARTY.md](THIRD_PARTY.md).
