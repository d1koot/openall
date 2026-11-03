#!/usr/bin/env python3
"""Look for fragments copied from input/ (original) into workspace/build/ (new code).

Checks: (1) identical runs of 20 tokens, (2) identical long string literals (>=30 chars),
(3) shared distinctive identifiers (advisory). Exit 1 if (1) or (2) found.
Heuristic helper, not a legal guarantee. Boilerplate/framework overlaps can be false positives."""
import hashlib, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC, NEW = ROOT / "input", ROOT / "workspace" / "build"
REPORT = ROOT / "workspace" / "reports" / "originality.md"
EXT = {".js", ".jsx", ".ts", ".tsx", ".py", ".java", ".kt", ".cs", ".xaml", ".xml", ".html", ".css",
       ".scss", ".json", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift", ".go", ".rs", ".dart", ".vue", ".svelte", ".qml"}
SKIP = {"node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "vendor", "target"}
TOK = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]")
STR = re.compile(r"""(["'`])((?:\\.|(?!\1).){30,200})\1""")
IDENT = re.compile(r"\b(?:[a-z]+(?:[A-Z][a-z0-9]+)+|[a-z]+(?:_[a-z0-9]+)+|[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+)\b")
K = 20

def files(base):
    if not base.exists():
        return
    for p in base.rglob("*"):
        try:
            if (p.is_file() and p.suffix.lower() in EXT and not (set(p.parts) & SKIP)
                    and p.stat().st_size < 3_000_000):
                yield p
        except OSError:
            continue

def h(s):
    return hashlib.md5(s.encode("utf-8", "ignore")).digest()[:8]

def scan(base, with_src=False):
    sh, strings, ids = {}, {}, set()
    for p in files(base):
        text = p.read_text(errors="ignore")
        toks = TOK.findall(text)
        for i in range(max(0, len(toks) - K + 1)):
            window = toks[i:i + K]
            if sum(1 for t in window if t[0].isalnum() or t[0] == "_") < 8:
                continue
            sh.setdefault(h(" ".join(window)), str(p.relative_to(base)))
        for m in STR.finditer(text):
            s = m.group(2).strip()
            if len(set(s)) > 8:
                strings.setdefault(s, str(p.relative_to(base)))
        ids.update(i for i in IDENT.findall(text) if len(i) >= 10)
    return sh, strings, ids

def main():
    if not NEW.exists() or not any(files(NEW)):
        print("workspace/build/ has no source files yet; nothing to check.")
        return 0
    if not SRC.exists() or not any(files(SRC)):
        print("N/A: input/ has no readable source files (binary-only original), so there is nothing to compare against. "
              "This is NOT a pass; review the build manually.")
        return 0
    s_sh, s_str, s_id = scan(SRC)
    n_sh, n_str, n_id = scan(NEW)
    shingle_hits = sorted({(n_sh[k], s_sh[k]) for k in n_sh if k in s_sh})
    string_hits = sorted({(n_str[k], s_str[k], k) for k in n_str if k in s_str})
    id_hits = sorted(s_id & n_id)
    lines = ["# Originality report (heuristic)", "",
             f"- identical {K}-token runs: **{len(shingle_hits)}** file pairs",
             f"- identical long strings: **{len(string_hits)}**",
             f"- shared distinctive identifiers (advisory): **{len(id_hits)}**", ""]
    if shingle_hits:
        lines += ["## Copied-looking code runs (new file <- original file)"]
        lines += [f"- `{a}` <- `{b}`" for a, b in shingle_hits[:50]] + [""]
    if string_hits:
        lines += ["## Identical long strings (new file <- original file)"]
        lines += [f"- `{a}` <- `{b}`: {s[:60]}..." for a, b, s in string_hits[:50]] + [""]
    if id_hits:
        lines += ["## Shared identifiers (review; framework names are normal)"]
        lines += [f"- `{i}`" for i in id_hits[:80]] + [""]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines))
    print("\n".join(lines[:6]))
    print("Full report:", REPORT.relative_to(ROOT))
    if shingle_hits or string_hits:
        print("FAIL: rewrite the flagged fragments in your own words/structure.")
        return 1
    print("PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
