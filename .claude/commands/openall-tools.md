---
description: Check which analysis engines are installed and connect Ghidra/REA to Claude Code
---
1. Run `python3 scripts/doctor.py` and explain the result in plain words (what is ready, what is missing, what is worth installing
   for the user's target; use `docs/TOOLS.md`).
2. If an MCP bridge (mcp-reva, rea-mcp) is installed: run `python3 scripts/setup_mcp.py`, then tell the user to restart Claude Code
   in this folder and check `/mcp`.
3. If nothing is installed: give the shortest install path for their OS (Ghidra 12+ + JDK 21+, `GHIDRA_INSTALL_DIR`,
   `uv tool install reverse-engineering-assistant`, optionally `pip install rea-mcp`). Do not install anything without asking.
4. Never download or run unknown binaries to "set things up" on your own.
