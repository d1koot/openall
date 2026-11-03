#!/usr/bin/env python3
"""Set or show the current OpenAll phase: idle | study | analyze | build | verify.
`study` is the default read-and-understand mode (no code is written)."""
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".openall" / "state.json"
PHASES = {"idle", "study", "analyze", "build", "verify"}

def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "set":
        if sys.argv[2] not in PHASES:
            sys.exit("phase must be one of: " + ", ".join(sorted(PHASES)))
        STATE.parent.mkdir(exist_ok=True)
        STATE.write_text(json.dumps({"phase": sys.argv[2]}))
        print("phase =", sys.argv[2])
    else:
        try:
            print(json.loads(STATE.read_text()).get("phase", "idle"))
        except Exception:
            print("idle")

if __name__ == "__main__":
    main()
