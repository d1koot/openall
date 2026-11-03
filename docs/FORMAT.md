# OpenAll: shelves and book (format draft v0)

> **Lay machine code out on shelves, then bind the shelves into one open book.**

This is the core idea of OpenAll. This document defines what a *shelf* is, what the *book* is, and the rules that
connect them. It is a draft: nothing here is built yet, and every number marked “measured” comes from one small
sample (see the last section).

## 1. Why shelves at all

Claude reads small, structured, labelled pieces well and raw machine code badly. A 57-line C program compiled to a
Windows exe has about 15,000 lines of disassembly (roughly 590 KB of text, on the order of 150,000 tokens). Nobody,
human or model, should read that directly. Shelves turn the binary into pieces that each fit into one working step,
and the book is what a person reads at the end.

Rule of the project: **the model never invents the shelves.** Shelves 0 to 2 are produced by deterministic code
(parsers and disassemblers). Only shelf 3 and the book contain model-written words, and every word there must point
back to a record on shelves 0 to 2.

## 2. The shelves

All shelf files live in `workspace/shelves/`. They are plain text (JSON / JSON Lines / Markdown), so they survive
between sessions and can be diffed in Git.

| Shelf | Name | Made by | Contains |
|---|---|---|---|
| 0 | Container | code | file facts, sections, imports (per DLL), exports, resources, strings, version info |
| 1 | Code | code | functions, basic blocks, call graph, cross-references, origin class |
| 2 | Data | code | string tables, jump tables, vtables, struct-like blobs, who reads/writes them |
| 3 | Meaning | model + checker | one page per function (or per group): what it does, in words, with evidence |

### 2.1 Stable IDs

IDs come from the address, not from a counter, so a re-run never breaks existing references.

| Kind | Form | Example |
|---|---|---|
| Function | `F:<rva hex, 8 digits>` | `F:00001506` |
| Data item | `D:<rva hex>` | `D:00010020` |
| String | `S:<rva hex>` | `S:00010000` |
| Import | `I:<dll>!<name>` | `I:kernel32.dll!ReadFile` |
| Pointer table | `T:<rva hex>` | `T:00005690` |
| Section | `X:<name>` | `X:.text` |

### 2.2 Shelf 1 record (one line of `shelf1_code.jsonl`, produced by `scripts/build_shelves.py`)

```json
{
  "id": "F:00001506",
  "source": "pdata",
  "size": 218, "insn_count": 69, "blocks": 12,
  "callers": ["F:000015e0"],
  "callees": ["F:00001a40", "F:00001b10", "I:msvcrt.dll!tolower"],
  "imports": ["I:msvcrt.dll!tolower"],
  "strings": ["S:00010000"],
  "data_read": [], "data_written": [],
  "address_taken_fns": [],
  "indirect_calls": 0, "indirect_jumps": 0,
  "name_hint": null, "name_source": "none",
  "origin": "unknown",
  "origin_why": "no rule matched; treat as own until shown otherwise",
  "disasm": "disasm/F-00001506.txt"
}
```

- `source` says how the function was found: `pdata` (exact boundaries from the x64 exception table, which exists even
  in stripped files), `entry`, `export`, `symbol`, or `call` (found by following a call; boundaries are heuristic).
- `callees` are functions and imports that are called or tail-jumped to. `imports` lists every import the function
  touches, including ones loaded into a register and called later.
- `name_hint` is only a hint; `name_source` says where it came from (`symbol`, `export`, `none`).
- The disassembly is **not inlined**. It lives in a separate file so a task can load only what it needs. It is only
  written for `own`/`unknown` functions unless `--all-disasm` is given.
- Also written: `bottom_up.json` (call-graph groups, callees first), `shelf2_data.jsonl` (global data and who reads
  or writes it), `shelf0_container.json`, `shelf0_strings.jsonl`, `SUMMARY.md`.

### 2.3 Shelf 3 page (one file per function: `shelf3/F-00001506.md`)

```markdown
# F:00001506
title: read words into a counted list
summary: Reads words from a file handle and counts each distinct word; returns the total. [I]
inputs: a file handle; the address of a list head pointer.
effects: reads the file; allocates nodes; returns the word total.
evidence:
- Each buffer character goes through the import tolower and is written back. [I] refs: I:msvcrt.dll!tolower
- On a zero strcmp result the counter at offset 8 of the node is incremented. [O] refs: F:0000e8b0, I:msvcrt.dll!strcmp
- The compiler probably merged several source functions into this one. [G]
confidence: medium
children_read: F:000014e4, F:0000e880, F:0000e8b0
open_questions: exact identity of F:000014e4.
```

A claim is one bullet ending in a label: `[O]` observed in the shelf data, `[I]` inferred from it, `[D]` public
documentation, `[G]` guess. `[O]` and `[I]` need `refs:`. Runtime and library functions get generated one-line
`stub` pages (a thunk is named after its import). A page `OVERVIEW.md` holds the book’s opening claims in the
same format.

## 3. Origin classes (this solves the biggest scale problem)

In the measured sample, **only 2 of 165 functions were the author’s own code**; the rest was compiler runtime and
statically linked C library. A shelf builder that treats all functions equally wastes most of the work.

Every function gets an `origin`:

- `own`: the program’s own logic. Gets a full page.
- `library`: recognised third-party or standard-library code. Gets a one-line page (“likely printf family”).
- `runtime`: startup, exception handling, compiler helpers. Gets a one-line page.
- `unknown`: not classified. Treated as `own` until proven otherwise.

Ways to classify, cheapest first: reachability from `main`/entry; thin wrappers around a single import; byte-pattern
and string signatures for known libraries; later, signature databases. Classification is a hint with a reason
(`origin_why`), never silent.

**Reference builds (implemented).** The strongest method found so far: compile small reference programs with the
*same toolchain*, normalise their function bytes (mask addresses), and mark any function in the target with the same
normalised bytes as `runtime`. It works on stripped files and needs no symbols. Measured results are in section 8,
including where it fails.

## 4. How shelf 3 is filled

1. Build the call graph on shelf 1 and order functions **bottom-up** (leaves first). Cycles are grouped and
   handled as one unit.
2. For each function, the task is given only: its disassembly (split by block groups if too long), the
   **already written summaries** of its callees, the strings and imports it touches. Never the whole binary.
3. The model writes the page using the template above.
4. The checker (section 6) validates the page. A page that fails goes back for a rewrite.
5. Progress is kept in `workspace/shelves/PROGRESS.json` (which F:ids are done), so work resumes after a break.

## 5. The book

`workspace/book/` is generated from shelf 3 and is meant to be read top to bottom by a person.

```
book/
  00_OVERVIEW.md     what the program is, in ten lines, with a confidence note
  01_STRUCTURE.md    components and how they talk (from the call graph)
  02_FEATURES/       one chapter per feature or subsystem
  03_DATA.md         file, network and memory formats seen
  04_GLOSSARY.md     terms and the names the book gave to things
  05_UNKNOWN.md      everything not understood, and what would resolve it
  INDEX.md           every chapter -> the F:/D:/S:/I: records behind it
```

Two render modes from the same shelves:

- **private**: addresses, names and short excerpts allowed (own analysis).
- **public**: behaviour and structure only; no addresses, no original identifiers, no code excerpts, no long
  strings. This matches the existing spec rules in `CLAUDE.md`.

Hard rules from `CLAUDE.md` apply to every shelf and to the book: no secrets (record “uses credentials of kind X”),
no help to defeat protection (a packed file is described, not unpacked).

## 6. The checker (the part that catches invention)

`scripts/shelf3.py check`, a script, not a model. Implemented rules; a page fails when:

- a claim has no label, or an `[O]`/`[I]` claim has no `refs`;
- a cited record does not exist on any shelf;
- a cited record is **not connected** to the function (not one of its callees, callers, strings, imports, data, or
  the import behind a callee thunk). This stops a page from borrowing evidence that belongs to another function;
- `confidence: high` without at least two evidence bullets that cite valid records;
- `children_read` does not list every callee, or a callee has no page yet (bottom-up order is enforced);
- the page contains something that looks like a secret or token;
- an own/unknown function has no page, or `OVERVIEW.md` is missing.

The book (`shelf3.py book`) refuses to render while the check fails.

What it cannot do: prove a claim is **true**. A claim with real, connected references can still be wrong. It proves
claims are **grounded** and visible to a reviewer, which is the minimum for a trustworthy book. Not yet implemented:
the public render check (no addresses, identifiers or code excerpts).

## 7. Testing without anyone else’s software

For the prototype, test programs are written and compiled by us. Because the source is known, the book can be graded
against the truth: which functions the book found, what it got wrong, what it missed. Suggested first test set:
a word counter, a small file-format parser, a tiny network client, and the same programs built with different
compiler flags and with symbols stripped.

## 8. Measured scale (small samples, treat as rough orders of magnitude)

Test program: 57 lines of C, 1.6 KB source, built with MinGW for Windows x64, with and without symbols.
All measurements below come from `scripts/build_shelves.py` run on our own builds.

| Quantity | Value |
|---|---|
| Raw disassembly of the whole code section | 15,472 lines, ~590 KB (~150,000 tokens) |
| Functions with exact boundaries from `.pdata` (stripped file!) | 122 |
| Functions after adding call targets | 165 (stripped) / 167 (with symbols) |
| Of these, classified `runtime` with two reference builds | 163 |
| Left `unknown` | 2 (`main` and `read_words`, exactly the author’s own code, same addresses in both builds) |
| Disassembly a model would actually need to read | ~4 KB (2 functions, 155 instructions) |

How much the result depends on the reference builds (same target, stripped):

| Reference builds used | `runtime` | `unknown` |
|---|---|---|
| Two (one empty, one using the same library calls) | 163 | 2 |
| One (empty program only) | 86 | 79 |
| None | 0 | 123 (+42 import thunks) |

Same target built with other optimisation flags (references built with `-O1`):

| Target flags | `unknown` functions |
|---|---|
| `-O0` | 10 |
| `-O1` | 2 |
| `-O2` | 5 |
| `-Os` | 5 |
| `-O2`, references also `-O2` | 3 |

What this suggests:

- Raw disassembly is hundreds of times larger than the source. After classification the part worth reading is
  about 150 times smaller. Shelves must compress, not copy.
- Most of a small program is runtime. Origin classification is the central trick, not an extra.
- **The method is only as good as its reference builds.** It survives different optimisation flags because the
  C library comes prebuilt and identical. A different compiler, a different compiler version, or a different
  library will not match, and the target will look almost entirely `unknown`. A real release needs a growing
  signature set per toolchain; this has not been tested beyond one toolchain.
- `.pdata` gives exact function boundaries even without symbols, but only for x64 PE and only for functions that
  have unwind data. Small leaf functions without it are found only by call-following.
- The compiler inlined 5 of 7 source functions. The book will describe *behaviour*, which may not map one-to-one to
  the original source functions. That is expected and should be stated in the book.
- Symbols matter for naming, little for structure: both builds had the same call graph and the same unknown pair.
- Not yet handled: calls through registers or tables (only counted in `indirect_calls`), jump tables, C++ vtables,
  delay-load imports, packed files (only flagged via section entropy), 32-bit PE.

### 8.1 First C++ sample (MinGW g++ -O2, one small program with virtual classes, STL, a lambda and an exception)

Measured on our own build, 23 KB exe (the C++ library is imported from a DLL):

| Quantity | Value |
|---|---|
| Functions | 100 (63 from `.pdata`) |
| `runtime` / `library` thunks / `unknown` | 52 / 36 / 12 |
| Of the 12 unknown | `main` (546 instructions, most of the STL inlined into it), the check function, 4 STL template instantiations, 6 tiny virtual methods |
| Class names | present as plain strings (`6Circle`, `5Shape`, `4Rect`) and in mangled import names |
| Virtual methods | have **no callers** in the call graph; they are only reachable through tables |

What this led to: shelf 2 now lists **pointer tables** (`T:` ids): runs of pointers to known functions in data
sections. Two vtable candidates of four entries each were found and both are used by `main`. Each virtual method
now carries `in_tables`, and `main` carries `uses_tables`, so pages can cite them as evidence.

Still open for C++: telling STL template instantiations from the program’s own code (they differ per program, so
reference builds do not match them), demangling names, reading vtable layout per ABI (Itanium vs MSVC), exception
tables, and MSVC builds, which have not been tested at all.

### 8.2 Second C++ sample: built on the author’s own machine with a different toolchain

Same `inventory.cpp`, built with WinLibs GCC 16.2.0 (UCRT runtime), stripped, via `setup_windows.bat`. Our first
sample used GCC 13 with the older msvcrt runtime, so this is a real cross-toolchain test.

| Reference builds used | `runtime` | `library` thunks | `unknown` |
|---|---|---|---|
| Same toolchain (GCC 16 refs) | 59 | 49 | 18 |
| Foreign toolchain (GCC 13 refs) | 7 | 49 | 70 |
| None | 0 | 49 | 77 |

Confirmed: **reference builds only work for the toolchain they were made with.** Foreign references matched 7
functions out of 126. The compiler leaves a fingerprint in the file (GCC writes its version string into the
binary), so the reference set can be chosen automatically; not implemented yet.

The 18 unknown functions (own estimate, not verified against symbols): `main` with 707 instructions (most of the
STL inlined into it), 6 virtual methods reachable only through the two vtables, about 5 small pieces with no
callers and no table (exception landing pads and compiler-split cold parts, reached through unwind data, not by
calls), and about 5 STL template instantiations (no strings, no tables, 47 to 432 instructions).

New: class names are recovered from vtables. For the Itanium ABI, the pointer just before a vtable leads to a
`type_info` object whose name (`6Circle`) is read. Both vtables got the right class (`Rect`, `Circle`) on both
builds, each used by `main`. MSVC RTTI uses another layout and is not read yet.

Needed next for C++: pick references by toolchain fingerprint; recognise exception landing pads and cold parts
from the unwind data instead of leaving them as orphan functions; a “likely STL template” hint; demangling of
import names (the user’s WinLibs includes `c++filt`); MSVC RTTI.

### 8.3 Toolchain fingerprints, weak matches, exception landing pads

Changes made after the cross-toolchain test:

- **Reference sets per toolchain.** `build_shelves.py --learn ref1.exe ref2.exe` stores only normalised function
  hashes (no binaries, no code) in `refsets/`, under a fingerprint of the compiler (GCC writes its version string
  into the file; otherwise linker version plus C runtime family). Analysing a target picks the matching set
  automatically and prints which one was used or that none exists.
- **Weak matches.** A function of fewer than 6 instructions that matches a reference is not trusted by itself
  (our own `legs()` method is `mov eax,4; ret`, the same bytes as in a reference program). It counts as runtime only
  if a runtime function calls it, nothing of the program’s own uses it, or a runtime function also uses the table
  it sits in. Own virtual methods stay `unknown`.
- **Exception landing pads.** GCC on Windows stores its call-site table inline in the unwind data. The pad addresses
  are now extra entry points when a function is explored. In the GCC 16 sample `main` grew from 707 to 734
  instructions (12 pads), the four former orphan functions got a caller, and 11 functions that had been invisible
  (cleanup code, probably STL destructors) appeared.

Result of the same program on all samples (`unknown` functions, lower is better, C truth is 2):

| Sample | `unknown` |
|---|---|
| C, -O1 (truth: 2) | 2 |
| C, -O0 / -O2 / -Os | 11 / 6 / 6 |
| C++ GCC 16 UCRT (user’s machine), own refs | 30 (was 18 before the hidden cleanup code became visible) |
| C++ GCC 13 msvcrt, own refs | 14 |

Honest reading: `unknown` still mixes the program’s own code with STL template instantiations that no reference
can match, so on C++ it overstates the own code. A “likely template” hint is the next step. Landing pads are only
read for GCC-style tables; MSVC uses a different scheme and has not been tried.

### 8.4 Cost of a full run, and what C++ broke

Measured on the GCC 16 C++ sample (30 `unknown` functions, 15 of them with 12 instructions or fewer):

| Quantity | Value |
|---|---|
| Instruction files loaded at start (`CLAUDE.md`, command, writer role) | about 4,000 tokens |
| Disassembly the pages are written from | about 22,000 tokens |
| Pages (about 700 tokens each) | about 21,000 tokens |
| Rounds, one function per packet | 28 to 30 |
| Rounds, `next --batch 8` (up to 8 independent small functions, 250 instructions) | 7 |
| Largest single packet (`main`, 734 instructions) | about 26 KB, roughly 8,000 tokens |

The real cost is not the instruction files but the number of rounds, because every round carries the whole
conversation. Batching keeps order bottom-up automatically: a function is only ready when all its callees already
have pages, so two functions in one batch can never depend on each other.

Two bugs that only C++ exposed, both fixed: long mangled names (`_ZStlsISt11char_traitsIcE...`) tripped the secret
scanner, and a recursive function (it calls itself) was never “ready”, which also blocked `main`. Functions in the
same recursion cycle no longer block each other.

Environment note: in claude.ai chats the network can be restricted (pypi.org returned 403). The two Python packages
(`capstone`, `pefile`) are therefore shipped as wheels in `vendor/` (Linux and Windows x64) and install without
internet: `pip install --no-index --find-links vendor capstone pefile`.

### 8.5 First real book, reviewed against the source

The first full run of `/openall-shelves` in Claude (claude.ai chat) on the GCC 16 C++ sample produced 30 full pages
and 107 stubs; the checker passed. Compared with the real source:

- **Correct:** both classes and their vtables, each method (`area` as width times height, or a constant times the
  radius squared; `name` returning `"rect"`/`"circle"`; both destructors), `main` (shapes with a radius that depends on
  the argument count, sort by area, count per name, print the total, add one more rectangle, the handler that prints
  `error: ` and returns 3), the throw of `"bad shape"`, and the `std::sort` internals recognised as introsort,
  insertion sort and heap sift. Uncertain points were labelled `[G]` or `confidence: low`.
- **Wrong because of the builder, not the model:** 11 of the 30 “functions” were interior labels of two big blocks
  (the exception handler and the tail of `main`), so several pages described the same code again
  (“catch-report fragment, third view”).
- **Not a blind test:** the project archive contained `inventory.cpp`, and the model says it compared with it. From
  now on the program under test is never inside the project; see `tests/shelf_demo_cpp/README.md`.

Fixes made after this review:

| Problem | Fix | Effect |
|---|---|---|
| Jump into the middle of a known function created a new function | becomes an extra entry point of that function; edges are remapped | `unknown` 30 → 19, `main` and the handler complete |
| `switch` tables not followed (case bodies invisible) | table entries are read (GCC relative style and RVA style) and followed | test function 13 → 48 instructions, 1 → 8 strings; **unresolved indirect jumps are still counted** |
| Reference sets silently became useless after the analyser changed | sets carry `analysis_version`; stale sets are reported and not used | one `--learn` after each analyser change |

Important limit: a checker pass does **not** mean a page is complete. Before the jump-table fix a `switch` function
would have been described from one branch only and still passed. Completeness needs facts on the shelves
(`indirect_jumps`, `landing_pad_count`, `jump_tables`), and pages must treat unresolved ones as open questions.

### 8.6 First blind run (ledger.exe, GCC 16 UCRT, built on the author’s machine)

The run was done in a claude.ai chat with `/openall-shelves`, without telling the model what the program does.
Observed from the progress messages (the book itself was not delivered because usage limits ran out near the end):

- `ledger.exe` came out with **49** `unknown` functions, while the same program built with GCC 13 (msvcrt) has 14.
  The model correctly identified the extra ones as float-to-text and big-number library code (a dtoa-style routine).
  With the UCRT toolchain the C library’s number parsing and printing is linked statically into the exe, and our
  reference programs never used it, so none of it matched. About 35 library functions were treated as the
  program’s own, which cost most of the run (34 of 49 pages were library code).
- Pages for all functions were written and passed the checker; only the overview and the book render were missing
  when the limits hit.

Changes made:

- New reference program `ref_numeric.cpp` (stod, strtod, atof, `cout << double`, `to_string`, `snprintf`, `sscanf`,
  string streams). `setup_windows.bat` now compiles and learns three reference programs. **Not yet verified on a
  UCRT toolchain**: on GCC 13 the effect is small (14 → 13), because that toolchain imports those functions from the
  system DLL. Expected on GCC 16 UCRT: most of the 35 library functions disappear from `unknown`. To be measured.
- Runs survive usage limits: in claude.ai chats the command zips `workspace/shelves/<name>` to
  `<name>_progress.zip` every few packets; unzipping it into the project and running the command again resumes
  (shelves 0-2 are not rebuilt if pages exist).

Lesson: the number of `unknown` functions is the real cost driver. A reference set must cover the library routes a
program is likely to use (formatting, parsing, containers, streams), not only its startup code. Reference programs
should grow with every toolchain, and an unknown cluster that is clearly library code (many functions, no strings,
no callers from own code) deserves its own hint.

### 8.7 Blind test graded against the source (ledger.exe)

Program: a 100-line expression calculator (recursive-descent parser with mutually recursive functions, a `switch`,
exceptions, a map, `std::stod`), built by the author with GCC 16.2 UCRT. Its source was not in the project and was
never shown to the model. The model was only asked for the legal basis and then ran `/openall-shelves`.

| Quantity | Value |
|---|---|
| Functions found | 160 |
| Left `unknown` after learning the numeric reference program | 9 (before: 49) |
| Pages that are the program’s own code | 9, written and checked |
| Truth: functions of the program’s own logic | `expr`, `term`, `power`, `atom`, `number`, `main`, the cold exception path of `main`, and two library template helpers (string constructor, copy of a string vector) |

Grading, page by page: every one of the 9 pages and all 7 overview claims matched the source. This includes the
details that are easy to get wrong: right-associative `^` using only the integer part of the exponent, `stod` with its
three exception types and the saved `errno`, the `"<expr> : error: <msg>"` report that continues with the next
expression, the exit code equal to the number of failed expressions, two built-in variables `pi` and `e`, and the five
built-in examples when no arguments are given. No invented facts were found. Honest gaps were reported as open:
the result of a power with a zero or negative exponent (true answer: 1.0, the loop simply does not run), the exact text
of the five examples, and the values of `pi` and `e`.

Scored, not claimed: the numeric reference program removed 40 of the 49 spurious `unknown` functions on this UCRT
toolchain, which confirms the diagnosis in 8.6.

What this does not show: one program, one toolchain family (GCC), a strong model, and a book delivered without its
shelf 0-2 files (so the facts could not be re-checked from the archive). The checker still proves only grounding.

Change made from the model’s own list of gaps: the shelf data now shows what the file holds at a data address
(double, integer, pointer to a string, array of string pointers, text preview), and the task packets print it, so
constants like `pi = 3.14159` are visible to the page writer. Disassembly lines get a comment when an immediate looks
like ASCII text (some compilers store short strings that way). The comment feature found only one runtime constant in
tests and has **not** yet been shown on a real short string.

### 8.8 Second blind program (vm.exe), preparation

Program: a small bytecode machine (two virtual device classes, a 10-opcode `switch` interpreter, a CRC table,
`std::function` callbacks, an unordered map, exceptions). Source kept outside the project (`openall-blind-kit2`).
Built here with GCC 13 to prepare the run; the blind run on the author’s machine is still to be done and graded.

| Quantity | Value |
|---|---|
| Functions / `unknown` | 169 / 24 |
| Jump tables resolved | 3 (the interpreter `switch` among them); 4 indirect jumps remain unresolved, none in the program’s own code |
| vtables with class names | `Console`, `Sum` (both used by `main`) |
| Largest packet | 16 KB; the whole loop takes 6 rounds with `--batch 8` |

A bug found only by reading the numbers, not by the checker: the `Sum` vtable showed no user. The short-string
heuristic (“`lea` of a short NUL-terminated printable run is a string”) had taken the first bytes of the vtable
pointer (`30 7d 00`) for the string `"0}"` and recorded a string reference instead of a table reference. `Console`
had luck with its bytes. Fixed: an address that holds an 8-byte pointer into the image is never a short string.
Lesson for every heuristic: a wrong guess that is still well-formed passes the checker and reads fine in the book.

### 8.9 Second blind run graded (vm.exe, GCC 16.2 UCRT, author’s machine)

The source (`vm.cpp`) was outside the project; the model answered the legal question with "learning / test sample"
and was told nothing about the program. This time the whole `workspace/shelves/vm` folder (including shelves 0-2)
was returned, so the facts could be checked too.

| Quantity | Value |
|---|---|
| Functions / `unknown` / pages written | 192 / 23 / 23 (13 `high`, 10 `medium` confidence) |
| Claim labels on evidence | 66 observed, 56 inferred, 6 guesses, 1 documented |
| Time to write all pages (a strong model, batched packets) | a few minutes |

Graded against the source: every substantive claim was correct. This includes the 11-slot jump table with opcode 0
invalid, the 1000-step limit, the four error messages and exit code 3, the two output classes and what each does,
native function 1 = square and 2 = add `argc` (and that program never calls native 2), the 31-byte bytecode with the
jump target 5, the table-driven CRC-32 with polynomial 0xEDB88320 (recognised from SIMD code), the `halted/steps/crc/sum`
report line and the return codes 0/2/3. Opcodes 3, 4 and 6 were inferred by elimination and labelled so; they were right.

The prediction “out: 5, 4, 3, 2, 1, 49; halted=1 steps=35 crc=49265cec sum=64; exit code 0” was made without running
anything. Recomputed independently from the real bytecode it is exact, including the CRC.

One flaw: titles such as `Sum::add(int)` look like recovered symbols, but the real method is `out` and the model
invented the name from its role (`Console::add` is misleading). Content was right, the label overclaimed.
Fix: the page writer must give descriptive titles, never identifier-like ones (rule 7 of the writer role).

What this still does not show: two programs, both written by the author, both GCC, one strong model; nothing about
MSVC, packed files, heavy inlining or very large programs. Facts and pages passed their checks; the checker proves
grounding only, and here grading against the source found no false claim.

## 9. Decisions

1. **First platform: Windows PE x64 only.** Decided. ELF, .NET and 32-bit later.
2. Disassembly provider: our own thin layer on Capstone first (done, `build_shelves.py`). A Ghidra export that
   writes the **same** shelf format comes later.
3. `origin` classification lives inside the shelf builder for now (reference builds, thunk rule, symbol-name rule).
4. Language of book pages: the user’s language, with IDs and labels always in English.

Still open:

5. How large may one shelf 3 task be (instructions per function before it is split)?
6. Decided: reference sets are stored as hashes only, one per toolchain fingerprint, in `refsets/`, grown with `--learn`. Still open: who builds reference programs for other compilers, and how many are enough.
7. What counts as a “feature” for the book chapters (call-graph clusters, shared data, strings)?

## 10. Status

| Piece | State |
|---|---|
| Shelf 0, 1, 2 builder for PE x64 (`build_shelves.py`) | prototype, tested on our own builds only |
| Origin classification (reference builds, import thunks named after the import) | prototype, see limits above |
| Bottom-up order and task packets (`shelf3.py next`) | prototype |
| Stub pages, checker, status, private book (`shelf3.py`) | prototype |
| Shelf 3 pages written by Claude | done by hand on the 57-line test program (2 functions); not automated yet |
| Pointer tables / vtable candidates | prototype (found in the first C++ sample) |
| C++ support | started: vtables and class names (Itanium ABI) work on two GCC builds; landing pads, templates, demangling, MSVC open |
| Reference sets by toolchain fingerprint, weak-match rule, landing pads | prototype, tested on three toolchain/language samples |
| Claude Code integration (`/openall-shelves`, `shelf-writer`, CLAUDE.md section) | written; dry-run of the command steps passed; not yet run inside Claude Code |
| Batched task packets, recursion cycles, offline wheels (`vendor/`) | prototype; loop mechanics verified with synthetic pages only |
| `switch` jump tables (GCC and MSVC style), interior-label handling | prototype; MSVC style untested |\n| Blind tests on unseen programs | done twice (`ledger.exe`, `vm.exe`): all pages and overviews matched the source; one naming flaw found and fixed |\n| Public render mode | not started |
| Splitting very large functions | not started (packets carry the whole function) |
| Ghidra export to the same format | not started |

### First end-to-end result (own test program, 2 functions)

Both pages and the overview were written from the task packets only, then compared with the real source:

- every call target the pages name matches the source (`malloc`, `strcmp`, `fopen`, `fclose`, `free`, `perror`
  from thunks; the print, scan and stream calls were inferred and labelled `[I]`);
- the list node layout (word at 0, counter at 8, next at 0x10), the lower-casing, the djb2 hash, the return codes
  0/1/2 and the release loop all match the source;
- nothing in the pages contradicts the source. The things left open were labelled as open.

Caveat: one tiny program, written by the same model that wrote the pages in a single sitting. It shows the loop
works; it does not show the loop scales to large programs, other toolchains or optimised code with heavy inlining.
