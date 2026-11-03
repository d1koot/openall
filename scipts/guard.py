#!/usr/bin/env python3
"""PreToolUse hook: during phase=build, block access to input/ (the original).

Best-effort guard for the clean-room rule, NOT a security boundary: a determined
user or a clever shell command can get around it. It exists to stop accidents.
Exit code 2 = block the tool call (message goes to Claude).
"""
import json, os, re, sys
from pathlib import Path

ROOT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).resolve()
STATE = ROOT / ".openall" / "state.json"
PROTECTED = (ROOT / "input").resolve()

def phase():
    try:
        return json.loads(STATE.read_text()).get("phase", "idle")
    except Exception:
        return "idle"

def inside(raw, cwd):
    try:
        p = Path(raw)
        if not p.is_absolute():
            p = Path(cwd) / p
        p = p.resolve()
        return p == PROTECTED or PROTECTED in p.parents
    except Exception:
        return False

def main():
    if phase() != "build":
        return 0
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0
    ti = data.get("tool_input") or {}
    cwd = data.get("cwd") or str(ROOT)
    hit = False
    for key in ("file_path", "path", "notebook_path"):
        v = ti.get(key)
        if isinstance(v, str) and inside(v, cwd):
            hit = True
    prot = str(PROTECTED).replace("\\", "/")
    for key in ("pattern", "glob", "command"):
        v = ti.get(key)
        if isinstance(v, str):
            n = v.replace("\\", "/")
            if prot in n or re.search(r"""(^|[\s"'=:(])(\./)?input(/|\s|"|'|$)""", n):
                hit = True
    if hit:
        sys.stderr.write(
            "OpenAll guard: phase=build, access to input/ (the original) is blocked. "
            "Work from workspace/spec/ only. If the spec is missing something, add a question "
            "to workspace/spec/QUESTIONS.md. (If this was a false positive, avoid the bare word 'input' "
            "as a path in the command.)\n"
        )
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())
