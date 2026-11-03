# Changelog

## 0.3.0 (release candidate)
Added
- Shelves workflow for compiled Windows x64 programs: `scripts/build_shelves.py` (facts), `scripts/shelf3.py`
  (task packets, checker, book), command `/openall-shelves`, role `shelf-writer`. Format and measurements:
  `docs/FORMAT.md`.
- Reference sets per compiler fingerprint (`refsets/`, hashes only) and `--learn`; sets are tied to the analyser version.
- C++ support in the builder: vtables with class names (Itanium ABI), exception landing pads, `switch` jump tables,
  recursion cycles, decoded data values, interior-label handling.
- `setup_windows.bat` (checks Python and g++, offers to install them with winget, learns the reference programs).
- Offline copies of capstone and pefile (`vendor/`), `THIRD_PARTY.md`, `.gitignore`.
- Tests: `python3 tests/run_tests.py` (checker rules, ordering, builder smoke tests; no compiler needed).

Tested
- Four own small programs (C and C++), GCC 13 (msvcrt) and GCC 16.2 (UCRT, WinLibs). Two blind runs, graded
  against the source: see "What was tested" in the README. Not tested: MSVC, clang, 32-bit, .NET, packed files.

Changed
- README rewritten with an honest status and limits. The older rebuild mode is kept but marked untested.

## 0.2.0
STUDY mode (engines via MCP) and REBUILD mode (clean-room roles); see README history. Prototype.
