# Analysis engines for STUDY mode

OpenAll does not decompile by itself. It orchestrates engines and forces a disciplined method
(map -> trace -> cross-check -> write down with evidence). More engines = deeper and more reliable answers.
Facts below come from the projects' own pages as of Oct 2026; versions move fast, check before installing.

## What REA is, and how OpenAll relates to it
REA ("Reverse Engineer Anything") is one CLI plus one MCP server that drives several engines (Ghidra, IDA, Hopper, JADX/apktool,
Rizin, Frida, Playwright...) and covers non-native targets (Electron, .NET, Android, web). An unofficial Python port exists
(`pip install rea-mcp`, MIT, alpha). REA is a *tool belt*; OpenAll is the *method on top of it*: the `researcher` agent,
the evidence labels, the knowledge base that survives between sessions, the triage script, and the guard rules.
You can (and should) use both: REA/ReVa as the hands, OpenAll as the working procedure.
"Better than REA" is not something a config can promise; what you can get is a stack that is *wider* (several MCP bridges at once)
and a procedure that is *stricter* (two-angle verification, KNOWLEDGE.md). Judge it on your own targets.

## Native code (exe, dll, so, firmware)
| Engine | What it gives | Cost | Connect to Claude |
|---|---|---|---|
| **Ghidra** (NSA) | decompiler, xrefs, types, scripting | free | via the bridges below |
| **ReVa** (cyberkaida) | Ghidra MCP server, small purpose-built tools, headless (`mcp-reva`) or GUI; needs Ghidra 12+; Apache-2.0 | free | `uv tool install reverse-engineering-assistant`, set `GHIDRA_INSTALL_DIR`, then `python3 scripts/setup_mcp.py` |
| **GhidraMCP** (LaurieWired) | Ghidra GUI plugin + MCP bridge: decompile, list, rename; Apache-2.0 | free | follow its README (plugin + Python bridge), add to `.mcp.json` yourself |
| **GhidrAssistMCP** | native MCP server extension for Ghidra | free | its README |
| **ida-pro-mcp** / Hex-Rays official IDA MCP | deepest coverage for IDA users (frames, structs, IDAPython) | needs IDA Pro licence | its README |
| **Binary Ninja MCP** (community) | IL levels, types, patches; GPL-3 | needs Binary Ninja licence | its README |
| **radare2 / Rizin + r2mcp** | fast scriptable analysis, read-only and sandbox modes | free | `r2mcp` README |
| **REA** | one MCP over several engines | free + engines | `pip install rea-mcp` then `setup_mcp.py` |

Recommended free stack: **JDK 21+ + Ghidra 12 + ReVa (headless) + REA** and Rizin for quick checks.
Both ReVa and REA can be registered at once (`setup_mcp.py` adds whichever is installed).
Security note: ReVa exposes PyGhidra scripting; never expose its port on a public interface without an API key.

## Triage helpers (cheap, run first)
- **capa** (Mandiant): lists capabilities of a binary ("uses crypto", "talks HTTP", "creates process").
- **Detect It Easy**: compiler, packer, protector. A packed file means: describe, do not defeat.
- **YARA**: match known library/compiler signatures.
- `scripts/binary_inventory.py` (built in): imports by capability, exports, RTTI class map, source paths, switches, domains.

## Managed code and mobile
- **.NET**: `ilspycmd` (decompile to C#), or REA's .NET path.
- **Java / Android**: **jadx** (readable Java), **apktool** (manifest, resources, smali); jadx has community MCP servers.
- **Electron / web**: `npx @electron/asar extract`, then read JS; Playwright for runtime behaviour.

## Dynamic observation (only in a VM/sandbox you confirmed)
- **Frida**: watch real calls and arguments of a running program to confirm a static hypothesis (REA integrates it).
- **strace / procmon / debuggers**: system calls, file and registry access.
Dynamic work verifies; it is not a way around protection (rule 2 stays).

## Practical order for a native program
1. `python3 scripts/doctor.py` -> what do I have?
2. triage: Detect It Easy / capa / `binary_inventory.py`
3. Ghidra auto-analysis through ReVa or REA -> `MAP.md`
4. pick a feature -> entry point (strings, imports) -> xrefs -> decompile -> `features/<name>.md`
5. confirm with a second angle (callers, data types, or Frida in sandbox) -> `KNOWLEDGE.md`
6. `/openall-ask` to dig into anything unclear
