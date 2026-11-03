#!/usr/bin/env python3
"""Detect what kind of application lives in input/ and suggest an analysis approach.
Writes workspace/analysis/type.json and prints a summary. Read-only on input/."""
import json, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "input"
OUT = ROOT / "workspace" / "analysis" / "type.json"

TIER = {
    "electron": "A", "web": "A", "dotnet": "A", "java": "A", "android": "A",
    "flutter": "B", "react-native": "B", "qt": "B",
    "native": "C", "unity": "C", "ios": "C",
}
HINT = {
    "electron": "Unpack resources/app.asar (npx @electron/asar extract), read HTML/CSS/JS for layout, tokens and flows.",
    "web": "Read HTML/CSS/JS directly; use Playwright for screenshots and state capture.",
    "dotnet": "Decompile with ilspycmd or read XAML for layout; describe behaviour, do not copy.",
    "java": "Decompile with jadx; read resources/FXML for layout.",
    "android": "apktool for manifest/resources, jadx for logic; layouts, colours and nav graph give the design.",
    "flutter": "Design from screenshots/semantics; Dart logic is packed, use observe-only for behaviour.",
    "react-native": "JS bundle is readable-ish; combine with screenshots.",
    "qt": "QML/resources may be extractable; otherwise observe-only.",
    "native": "Deep mode: run scripts/binary_inventory.py (component map), then drive Ghidra (ReVa/REA MCP: decompile, xrefs, call graph) for specific features; capa/Detect-It-Easy for triage; observe in a sandbox (Frida) only to confirm.",
    "unity": "Assets/Managed may be readable for Mono builds; IL2CPP is hard. Prefer observe-only.",
    "ios": "Needs a decrypted IPA you are entitled to; resources readable, code is hard. Prefer observe-only.",
}
PE_EXT = {".exe", ".dll"}

def add(found, kind, evidence):
    found.setdefault(kind, []).append(evidence)

def pe_is_dotnet(p):
    try:
        with open(p, "rb") as f:
            return b"BSJB" in f.read(4_000_000)
    except Exception:
        return False

def main():
    if not INPUT.exists() or not any(x for x in INPUT.rglob("*") if x.name != ".gitkeep"):
        print("input/ is empty. Put the original (repo zip, app folder, .apk, ...) there.")
        return 1
    found = {}
    names = []
    for p in INPUT.rglob("*"):
        if p.is_file():
            names.append(p)
    lower = {p.name.lower() for p in names}
    rels = [str(p.relative_to(INPUT)).replace("\\", "/").lower() for p in names]
    for p in names:
        ext, rel = p.suffix.lower(), str(p.relative_to(INPUT))
        if ext in (".apk", ".aab"):
            add(found, "android", rel)
            try:
                with zipfile.ZipFile(p) as z:
                    zn = z.namelist()
                    if any(n.endswith("libflutter.so") for n in zn):
                        add(found, "flutter", rel + " (libflutter.so)")
                    if any(n.endswith("index.android.bundle") for n in zn):
                        add(found, "react-native", rel + " (JS bundle)")
            except Exception:
                pass
        elif ext == ".ipa":
            add(found, "ios", rel)
        elif ext == ".jar":
            add(found, "java", rel)
        elif ext == ".asar":
            add(found, "electron", rel)
        elif ext in PE_EXT and pe_is_dotnet(p):
            add(found, "dotnet", rel + " (.NET metadata)")
        elif ext == ".exe":
            add(found, "native", rel)
        elif p.name.lower() == "package.json":
            txt = p.read_text(errors="ignore")
            add(found, "electron" if "electron" in txt else "web", rel)
        elif ext in (".csproj", ".xaml"):
            add(found, "dotnet", rel)
        elif p.name.lower() in ("androidmanifest.xml",) or ext == ".gradle":
            add(found, "android", rel)
        elif p.name.lower() == "pubspec.yaml":
            add(found, "flutter", rel)
    if any(r.endswith("resources/app.asar") for r in rels) or "ffmpeg.dll" in lower and "libegl.dll" in lower:
        add(found, "electron", "Electron runtime files")
    if "unityplayer.dll" in lower or any("_data/managed" in r for r in rels):
        add(found, "unity", "UnityPlayer / Managed")
    if any(n.startswith(("qt5core", "qt6core")) for n in lower):
        add(found, "qt", "Qt libraries")
    if "flutter_windows.dll" in lower:
        add(found, "flutter", "flutter_windows.dll")
    if "native" in found and len(found) > 1:
        del found["native"]
    if not found:
        add(found, "web" if any(n.endswith((".html", ".js")) for n in rels) else "native", "fallback")
    result = [{"type": k, "tier": TIER.get(k, "C"), "evidence": v[:5], "approach": HINT.get(k, "")}
              for k, v in sorted(found.items(), key=lambda kv: TIER.get(kv[0], "C"))]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    for r in result:
        print(f"- {r['type']} (support level {r['tier']}): {', '.join(r['evidence'][:2])}")
        print(f"    approach: {r['approach']}")
    print("\nSaved to", OUT.relative_to(ROOT))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
