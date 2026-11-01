#!/usr/bin/env python3
"""OpenAll shelf 3 (meaning): task packets, stub pages, checker, status, private book. Pure Python, no dependencies.

Commands (all take --shelves DIR, the folder made by build_shelves.py):
  stubs    write one-line pages for runtime/library functions (deterministic, no model needed)
  next     print the next task packet: the next undocumented own/unknown function, callees first
  check    validate every page; non-zero exit if anything is ungrounded
  status   what is done, what is next
  book     render the private book into DIR/book/ (refuses to run if the check fails)

A page is grounded when every claim carries an evidence label and cites records that EXIST and are CONNECTED to the
function (its own callees, callers, strings, imports, data). The checker proves grounding, not truth.
"""
import argparse, json, re, sys
from pathlib import Path

LABELS = "OIDG"
SECRET = re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token\b|BEGIN [A-Z ]*PRIVATE KEY|authorization:)")
TOKENLIKE = re.compile(r"\b[A-Za-z0-9+/=_\-]{40,}\b")
CLAIM = re.compile(r"^(?P<text>.*?)\s*\[(?P<lab>[OIDG])\]\s*(?:refs:\s*(?P<refs>.+))?$")
KEYS = {"title", "summary", "inputs", "effects", "confidence", "children_read", "open_questions",
        "generated", "origin"}


class Shelves:
    def __init__(self, d):
        self.dir = Path(d)
        self.f = {}
        for l in open(self.dir / "shelf1_code.jsonl"):
            r = json.loads(l); self.f[r["id"]] = r
        self.s = {json.loads(l)["id"]: json.loads(l) for l in open(self.dir / "shelf0_strings.jsonl")}
        self.d = {json.loads(l)["id"]: json.loads(l) for l in open(self.dir / "shelf2_data.jsonl")}
        c0 = json.loads((self.dir / "shelf0_container.json").read_text())
        self.c0 = c0
        self.i = {f"I:{dll}!{n}" for dll, ns in c0["imports"].items() for n in ns}
        self.x = {s["id"] for s in c0["sections"]}
        self.order = [g for grp in json.loads((self.dir / "bottom_up.json").read_text()) for g in grp]
        self.pages = self.dir / "shelf3"
        self.pages.mkdir(exist_ok=True)

    def exists(self, ref):
        return ref in self.f or ref in self.s or ref in self.d or ref in self.i or ref in self.x

    def connected(self, fid):
        r = self.f[fid]
        hops = {self.f[c]["thunk_to"] for c in r["callees"] if c in self.f and self.f[c]["thunk_to"]}
        return ({fid} | hops | set(r["callees"]) | set(r["callers"]) | set(r["strings"]) | set(r["imports"]) |
                set(r["data_read"]) | set(r["data_written"]) | set(r["address_taken_fns"]))

    def page_path(self, fid): return self.pages / f"F-{fid[2:]}.md"
    def has_page(self, fid): return self.page_path(fid).exists()
    def needs_model(self, fid): return self.f[fid]["origin"] in ("own", "unknown")


def parse_page(text):
    lines = text.splitlines()
    m = re.match(r"^# (\S+)\s*$", lines[0]) if lines else None
    d = {"id": m.group(1) if m else None, "evidence": [], "raw": text}
    cur = None
    for ln in lines[1:]:
        if cur == "evidence" and ln.startswith("- "):
            d["evidence"].append(ln[2:].strip()); continue
        k = re.match(r"^([a-z_]+):\s*(.*)$", ln)
        if k and k.group(1) in KEYS | {"evidence"}:
            cur = k.group(1)
            if cur != "evidence": d[cur] = k.group(2).strip()
        elif k and not ln.startswith("-"):
            d.setdefault("_unknown_keys", []).append(k.group(1))
    return d


def parse_claim(s):
    m = CLAIM.match(s.strip())
    if not m: return None
    refs = [r.strip() for r in (m.group("refs") or "").split(",") if r.strip()]
    return m.group("text"), m.group("lab"), refs


def check_page(sh, path):
    errs = []
    d = parse_page(path.read_text())
    fid = d["id"]
    if fid is None: return [f"{path.name}: first line must be '# F:xxxxxxxx'"]
    if path.name != f"F-{fid[2:]}.md": errs.append(f"{path.name}: file name does not match heading {fid}")
    if fid not in sh.f: return errs + [f"{fid}: no such function on shelf 1"]
    rec, e = sh.f[fid], lambda m: errs.append(f"{fid}: {m}")
    for k in d.get("_unknown_keys", []): e(f"unknown field '{k}'")
    if SECRET.search(d["raw"]) or TOKENLIKE.search(d["raw"]): e("looks like it contains a secret or token (rule 1)")
    summ = d.get("summary")
    c = parse_claim(summ) if summ else None
    if not c: e("summary missing or has no [O]/[I]/[D]/[G] label at the end")
    stub = d.get("generated") == "stub"
    if not stub:
        if "title" not in d: e("title missing")
        if d.get("confidence") not in ("low", "medium", "high"): e("confidence must be low, medium or high")
        if not d["evidence"]: e("no evidence bullets")
    allowed = sh.connected(fid)
    good_bullets = 0
    for b in d["evidence"]:
        pc = parse_claim(b)
        if not pc: e(f"evidence has no label: '{b[:60]}'"); continue
        _t, lab, refs = pc
        bad = False
        if lab in "OI" and not refs: e(f"[{lab}] claim without refs: '{b[:60]}'"); bad = True
        for r in refs:
            if not sh.exists(r): e(f"ref {r} does not exist on any shelf"); bad = True
            elif r.startswith(("F:", "S:", "D:", "I:")) and r not in allowed:
                e(f"ref {r} is not connected to this function (not a callee, caller, string, import or data of it)"); bad = True
        if refs and lab in "OI" and not bad: good_bullets += 1
    if d.get("confidence") == "high" and good_bullets < 2 and not stub:
        e("confidence high needs at least two evidence bullets with refs (two angles)")
    if not stub:   # bottom-up: every callee must already have a page
        for callee in rec["callees"]:
            if callee.startswith("F:") and callee in sh.f and not sh.has_page(callee):
                e(f"callee {callee} has no page yet (work bottom-up)")
        read = {x.strip() for x in d.get("children_read", "").split(",") if x.strip()}
        for callee in rec["callees"]:
            if callee.startswith("F:") and callee not in read:
                e(f"children_read does not list callee {callee}")
    return errs


def check_overview(sh):
    p = sh.pages / "OVERVIEW.md"
    if not p.exists(): return ["OVERVIEW.md missing in shelf3/"]
    errs = []
    n = 0
    for ln in p.read_text().splitlines():
        if not ln.startswith("- "): continue
        n += 1
        pc = parse_claim(ln[2:])
        if not pc: errs.append(f"OVERVIEW: claim without label: '{ln[:60]}'"); continue
        _t, lab, refs = pc
        if lab in "OI" and not refs: errs.append(f"OVERVIEW: [{lab}] claim without refs: '{ln[:60]}'")
        for r in refs:
            if not sh.exists(r): errs.append(f"OVERVIEW: ref {r} does not exist")
    if n == 0: errs.append("OVERVIEW.md has no claims ('- text [I] refs: ...')")
    return errs


def cmd_stubs(sh, _a):
    made = 0
    for fid, r in sh.f.items():
        if sh.needs_model(fid) or sh.has_page(fid): continue
        if r["thunk_to"]:
            summ = f"Thin thunk that forwards to the import {r['thunk_to'][2:]}. [O]"
            ev = f"- The function body is a single jump through the import table. [O] refs: {fid}, {r['thunk_to']}"
        else:
            summ = f"Runtime or library code, not analysed ({r['origin_why']}). Role unknown. [O]"
            ev = f"- Classified {r['origin']} by shelf 1. [O] refs: {fid}"
        sh.page_path(fid).write_text(f"# {fid}\ngenerated: stub\norigin: {r['origin']}\nsummary: {summ}\nevidence:\n{ev}\n")
        made += 1
    print(f"{made} stub pages written")


def one_line(sh, fid):
    p = sh.page_path(fid)
    if not p.exists(): return "(no page yet)"
    d = parse_page(p.read_text())
    t = d.get("title", "")
    return (t + ": " if t else "") + d.get("summary", "")


def next_task(sh):
    for fid in sh.order:
        if fid in sh.f and sh.needs_model(fid) and not sh.has_page(fid):
            if all(c in sh.f and sh.has_page(c) or c not in sh.f for c in sh.f[fid]["callees"]):
                return fid
    return None


def cmd_next(sh, _a):
    fid = next_task(sh)
    if not fid:
        left = [f for f in sh.f if sh.needs_model(f) and not sh.has_page(f)]
        print("No ready task." if left else "All own/unknown functions have pages."); return 0
    r = sh.f[fid]
    out = [f"# TASK {fid}", "", f"Write `shelf3/F-{fid[2:]}.md`. Use ONLY the facts below. Label every claim: [O] seen in the data below,"
           " [I] inferred from it, [D] public documentation, [G] guess. [O] and [I] claims need `refs:` to records listed here.", "",
           "## Record (shelf 1)", "```json", json.dumps({k: r[k] for k in r if k != "disasm"}, indent=1), "```", "",
           "## Callees already understood (bottom-up)"]
    for c in r["callees"]:
        out.append(f"- {c}: {one_line(sh, c) if c.startswith('F:') else '(import) ' + c[2:]}")
    out += ["", "## Strings used"] + [f"- {s}: {sh.s[s]['text']!r}" for s in r["strings"]]
    out += ["", "## Data touched"] + [f"- {x}" for x in r["data_read"] + r["data_written"]]
    out += ["", "## Disassembly", "```", (sh.dir / r["disasm"]).read_text().rstrip(), "```", "",
            "## Page template", "```",
            f"# {fid}", "title: <short name the book will use>", "summary: <one sentence> [I]", "inputs: <...>",
            "effects: <...>", "evidence:", "- <what you saw> [O] refs: <ids from above>",
            "- <what you concluded> [I] refs: <ids from above>", "confidence: low|medium|high",
            "children_read: <every callee F: id>", "open_questions: <what you could not tell>", "```"]
    print("\n".join(out)); return 0


def cmd_check(sh, _a):
    errs = []
    for p in sorted(sh.pages.glob("F-*.md")): errs += check_page(sh, p)
    errs += check_overview(sh) if (sh.pages / "OVERVIEW.md").exists() else []
    own = [f for f in sh.f if sh.needs_model(f)]
    for f in own:
        if not sh.has_page(f): errs.append(f"{f}: own/unknown function has no page yet")
    if errs:
        print(f"CHECK FAILED: {len(errs)} problem(s)"); [print("  -", x) for x in errs]; return 1
    print(f"CHECK OK: {len(list(sh.pages.glob('F-*.md')))} pages, all claims grounded"); return 0


def cmd_status(sh, _a):
    need = [f for f in sh.f if sh.needs_model(f)]
    done = [f for f in need if sh.has_page(f)]
    stubs = sum(1 for f in sh.f if not sh.needs_model(f) and sh.has_page(f))
    print(f"own/unknown functions: {len(done)}/{len(need)} documented; stubs: {stubs}/{len(sh.f) - len(need)}")
    print("next:", next_task(sh) or "-")


def render_claims(sh, d):
    out = []
    for b in d["evidence"]:
        pc = parse_claim(b)
        if not pc: continue
        t, lab, refs = pc
        shown = []
        for r in refs:
            if r.startswith("S:") and r in sh.s: shown.append(f"{r} “{sh.s[r]['text']}”")
            else: shown.append(r)
        out.append(f"- {t} `[{lab}]`" + (f" ← {', '.join(shown)}" if shown else ""))
    return out


def cmd_book(sh, a):
    if cmd_check(sh, a) != 0: print("Book not written: fix the check first."); return 1
    out = sh.dir / "book"; out.mkdir(exist_ok=True)
    own = [f for f in sh.order if f in sh.f and sh.needs_model(f)]
    ov = (sh.pages / "OVERVIEW.md").read_text()
    (out / "00_OVERVIEW.md").write_text(ov)
    ch, idx, unk = ["# Functions of the program (private book)", "",
                    "Labels: `[O]` observed, `[I]` inferred, `[D]` documented, `[G]` guess. Order: callees before callers.", ""], [], []
    for f in own:
        d = parse_page(sh.page_path(f).read_text())
        ch += [f"## {d.get('title', f)}  ({f}, confidence: {d.get('confidence')})", "", d.get("summary", ""), "",
               f"- inputs: {d.get('inputs', '-')}", f"- effects: {d.get('effects', '-')}", "", "Evidence:"] + render_claims(sh, d)
        def tag(c):
            r = sh.f.get(c)
            if r is None: return c[2:]
            if r["thunk_to"]: return f"{c} (thunk to {r['thunk_to'][2:]})"
            if not sh.needs_model(c): return f"{c} (runtime, not analysed)"
            return f"{c} ({parse_page(sh.page_path(c).read_text()).get('title', '')})"
        ch += ["", "Calls: " + ", ".join(tag(c) for c in sh.f[f]["callees"]), ""]
        idx.append(f"| {d.get('title', f)} | {f} | {', '.join(sh.f[f]['callers']) or '-'} |")
        if d.get("open_questions"): unk.append(f"- {f} {d.get('title', '')}: {d['open_questions']}")
    (out / "01_FUNCTIONS.md").write_text("\n".join(ch) + "\n")
    lib = [(f, sh.f[f]["thunk_to"]) for f in sh.f if sh.f[f]["thunk_to"]]
    rt = [f for f in sh.f if sh.f[f]["origin"] == "runtime"]
    (out / "02_RUNTIME_AND_LIBRARY.md").write_text(
        "# Runtime and library code\n\n" f"{len(rt)} runtime functions matched reference builds and were not analysed.\n\n"
        f"## Library thunks ({len(lib)})\n\n" + "\n".join(f"- {f} → {t[2:]}" for f, t in sorted(lib)) + "\n")
    (out / "03_UNKNOWN.md").write_text("# Open questions\n\n" + ("\n".join(unk) or "- none recorded") + "\n")
    (out / "INDEX.md").write_text("# Index\n\n| Name | Function | Called by |\n|---|---|---|\n" + "\n".join(idx) + "\n")
    print(f"book written to {out}"); return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["stubs", "next", "check", "status", "book"])
    ap.add_argument("--shelves", required=True)
    a = ap.parse_args()
    sh = Shelves(a.shelves)
    r = {"stubs": cmd_stubs, "next": cmd_next, "check": cmd_check, "status": cmd_status, "book": cmd_book}[a.cmd](sh, a)
    sys.exit(r or 0)


if __name__ == "__main__":
    main()
