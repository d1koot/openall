#!/usr/bin/env python3
"""Write .mcp.json for Claude Code from the MCP bridges that are ACTUALLY installed.

Never installs anything and never overwrites servers you added yourself: existing entries are kept.
Usage:  python3 scripts/setup_mcp.py          (write/update .mcp.json)
        python3 scripts/setup_mcp.py --dry    (only show what would be written)

Bridges known here (names are the keys in .mcp.json):
  reva  - ReVa, Ghidra headless MCP server. Needs GHIDRA_INSTALL_DIR (Ghidra 12+).
  rea   - REA multi-engine MCP server (`rea mcp` or `rea-mcp mcp`).
Other bridges (GhidraMCP GUI plugin, ida-pro-mcp, r2mcp, jadx MCP...) need their own setup: see docs/TOOLS.md.
"""
import json, os, shutil, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / ".mcp.json"

def candidates():
    env_pass = {k: os.environ[k] for k in ("GHIDRA_INSTALL_DIR", "JAVA_HOME") if os.environ.get(k)}
    out = {}
    if shutil.which("mcp-reva"):
        out["reva"] = {"command": "mcp-reva", "args": [], **({"env": env_pass} if env_pass else {})}
    if shutil.which("rea-mcp"):
        out["rea"] = {"command": "rea-mcp", "args": ["mcp"], **({"env": env_pass} if env_pass else {})}
    elif shutil.which("rea"):
        out["rea"] = {"command": "rea", "args": ["mcp"], **({"env": env_pass} if env_pass else {})}
    return out

def main():
    dry = "--dry" in sys.argv
    found = candidates()
    if not found:
        print("No supported MCP bridge is installed yet. Install one (see docs/TOOLS.md), for example:")
        print("  uv tool install reverse-engineering-assistant   # ReVa, needs Ghidra 12+ and GHIDRA_INSTALL_DIR")
        print("  pip install rea-mcp                              # REA port, multi-engine")
        print("then run this script again.")
        return 1
    current = {"mcpServers": {}}
    if TARGET.exists():
        try:
            current = json.loads(TARGET.read_text())
            current.setdefault("mcpServers", {})
        except Exception:
            print(".mcp.json exists but is not valid JSON; fix or delete it first.")
            return 1
    added = []
    for name, cfg in found.items():
        if name not in current["mcpServers"]:
            current["mcpServers"][name] = cfg
            added.append(name)
    text = json.dumps(current, indent=2, ensure_ascii=False)
    if dry:
        print(text)
        return 0
    TARGET.write_text(text + "\n")
    print("Written:", TARGET.name, "| added:", ", ".join(added) if added else "nothing new (already configured)")
    print("Servers now:", ", ".join(current["mcpServers"]))
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        print("Note: GHIDRA_INSTALL_DIR is not set; Ghidra-based tools will not start until you set it.")
    print("Restart Claude Code in this folder and run /mcp to check the connection.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
