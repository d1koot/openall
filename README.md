# OpenAll

> Drop a repo zip and/or a compiled app into Claude Code. Claude studies it, writes a spec,
> then writes **brand-new code** that reproduces the look and behaviour, under your own name.

**Status: prototype (v0.1).** Read [DISCLAIMER.md](DISCLAIMER.md) before use.
OpenAll is not a stealing tool, and the authors are not responsible for what people build with it.

## How it works

Three roles, strictly separated (clean-room style):

| Role | Sees | Writes |
|---|---|---|
| **Analyst** | the original (`input/`) | only a behavioural spec: `workspace/spec/` |
| **Builder** | only the spec | new code in `workspace/build/` |
| **Verifier** | both | a discrepancy report in `workspace/reports/` |

The loop is `analyze -> build -> verify -> (gaps back to analyze)`, repeated 3-5 times.
A hook (`scripts/guard.py`) blocks the Builder from reading `input/`, and
`scripts/originality_check.py` looks for copied fragments in the result.

## Quick start

1. Install [Claude Code](https://code.claude.com/docs/en/setup) and Python 3.9+.
2. Unzip this project, open the folder in Claude Code.
3. Put the original into `input/` (a repo zip, an `.exe` folder, an `.apk`, ...).
4. Run `python3 scripts/doctor.py` (it only checks, never changes anything).
5. In Claude Code: `/openall-start`, then `/openall-spec`, `/openall-build`, `/openall-verify`, and finally `/openall-package`
   (a clean ZIP with `build.bat`, a README and an honest list of what is built / stubbed / missing).
   Incomplete input (only an exe, repo without some modules) is fine: the agent says what is missing and stubs it.

## One-line start
Open the folder in Claude Code and paste the contents of `PROMPT.txt` (fill in the legal basis).
For a Chrome-like browser give the **whole application folder** (e.g. `chrome.exe` together with `chrome.dll` and its
resources), not just the launcher: the interface lives in the DLL.

## Deep mode for executables
For `.exe`/`.dll` the Analyst starts from `scripts/binary_inventory.py` (pure Python, no dependencies): capabilities from imported
system libraries, exported functions, C++ namespace/class map from RTTI, source-directory hints, command-line switches,
network domains, UI texts and error messages (secret-like strings are redacted). Optional deeper steps via Ghidra
(`analyzeHeadless`) or REA. Test it on a synthetic file: `python3 tests/make_sample_pe.py input/sample.exe`.

## What is supported

| Level | Targets | Notes |
|---|---|---|
| A | Electron / web / PWA, .NET (WPF/WinForms), Java, Android UI | readable code and resources |
| B | Flutter, React Native, Qt, Android logic | design good, logic partial |
| C | native C++, Unity/Unreal, iOS | mostly observation from the outside |

Anything can also be handled in **observe-only mode**: run in a sandbox, take screenshots, walk the UI.

## First prototype target

A Chrome-like **browser shell** (tabs, address bar, bookmarks, history, settings, downloads)
built on an existing open engine (Electron/Chromium). The rendering engine is reused, not re-created.

## Safety

Run unknown binaries only in a VM/sandbox. Never publish secrets you may stumble upon.
The guard hook is best-effort, not a security boundary.

## Licence
MIT, see [LICENSE](LICENSE).
