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

## 9. Decisions

1. **First platform: Windows PE x64 only.** Decided. ELF, .NET and 32-bit later.
2. Disassembly provider: our own thin layer on Capstone first (done, `build_shelves.py`). A Ghidra export that
   writes the **same** shelf format comes later.
3. `origin` classification lives inside the shelf builder for now (reference builds, thunk rule, symbol-name rule).
4. Language of book pages: the user’s language, with IDs and labels always in English.

Still open:

5. How large may one shelf 3 task be (instructions per function before it is split)?
6. How do we grow the reference-build set, and where is it stored without shipping anyone’s binaries?
7. What counts as a “feature” for the book chapters (call-graph clusters, shared data, strings)?

## 10. Status

| Piece | State |
|---|---|
| Shelf 0, 1, 2 builder for PE x64 (`build_shelves.py`) | prototype, tested on our own builds only |
| Origin classification (reference builds, import thunks named after the import) | prototype, see limits above |
| Bottom-up order and task packets (`shelf3.py next`) | prototype |
| Stub pages, checker, status, private book (`shelf3.py`) | prototype |
| Shelf 3 pages written by Claude | done by hand on the 57-line test program (2 functions); not automated yet |
| Public render mode | not started |
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
