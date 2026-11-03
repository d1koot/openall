#!/usr/bin/env python3
"""Pack workspace/build into workspace/dist/<name>.zip with COVERAGE.md and DISCLAIMER.md.
Refuses to package if there is no build script, so the user always gets something they can compile."""
import sys, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "workspace" / "build"
DIST = ROOT / "workspace" / "dist"
SKIP = {"node_modules", ".git", "__pycache__"}

def main():
    if not BUILD.exists() or not any(BUILD.iterdir()):
        print("workspace/build/ is empty: run /openall-build first.")
        return 1
    has_script = (BUILD / "build.bat").exists() or (BUILD / "build.sh").exists()
    if not has_script:
        print("No build.bat / build.sh in workspace/build/. Ask the builder to add them, then run again.")
        return 1
    name = (sys.argv[1] if len(sys.argv) > 1 else "clone").strip() or "clone"
    DIST.mkdir(parents=True, exist_ok=True)
    out = DIST / f"{name}.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(BUILD.rglob("*")):
            if p.is_file() and not (set(p.relative_to(BUILD).parts) & SKIP):
                z.write(p, Path(name) / p.relative_to(BUILD))
        for extra in (ROOT / "workspace" / "COVERAGE.md", ROOT / "DISCLAIMER.md"):
            if extra.exists():
                z.write(extra, Path(name) / extra.name)
            else:
                print(f"warning: {extra.name} missing, not included")
    print("Created", out.relative_to(ROOT))
    return 0

if __name__ == "__main__":
    sys.exit(main())
