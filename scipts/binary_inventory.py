#!/usr/bin/env python3
"""Deep-mode static inventory of compiled Windows binaries (.exe/.dll), pure Python, no dependencies.

Builds a LOGICAL MAP of the program for the Analyst: sections, imports grouped by capability, exports,
C++ class/namespace map (from RTTI names), source-file paths (components), command-line switches,
UI-text candidates, error messages, URL domains, version info.

It does NOT decompile, does NOT unpack or defeat protections, and redacts anything that looks like a
secret/key/token. Output goes to workspace/analysis/binary/. Non-PE files get a strings-only report.
Usage: binary_inventory.py [files...] [--top N]   (default: every .exe in input/ plus the N largest .dll)
"""
import argparse, json, math, mmap, re, struct, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "input"
OUT = ROOT / "workspace" / "analysis" / "binary"
MAX_BYTES = 700 * 1024 * 1024

u16 = lambda b, o: struct.unpack_from("<H", b, o)[0]
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
u64 = lambda b, o: struct.unpack_from("<Q", b, o)[0]

def cstr(mm, off, limit=300):
    if off is None or off < 0 or off >= len(mm):
        return ""
    end = mm.find(b"\0", off, off + limit)
    return bytes(mm[off:end if end != -1 else off + limit]).decode("latin1")

class PE:
    def __init__(self, mm):
        self.mm, self.ok, self.err = mm, False, ""
        try:
            self._parse()
        except Exception as e:  # malformed or not a PE
            self.err = str(e)

    def _parse(self):
        mm = self.mm
        if mm[:2] != b"MZ":
            raise ValueError("not an MZ/PE file")
        pe = u32(mm, 0x3C)
        if mm[pe:pe + 4] != b"PE\0\0":
            raise ValueError("no PE signature")
        c = pe + 4
        self.machine, nsec, self.timestamp = u16(mm, c), u16(mm, c + 2), u32(mm, c + 4)
        osz, self.chars = u16(mm, c + 16), u16(mm, c + 18)
        o = c + 20
        self.is64 = u16(mm, o) == 0x20B
        self.subsystem = u16(mm, o + 68)
        dd = o + (112 if self.is64 else 96)
        n = min(u32(mm, dd - 4), 16)
        self.dirs = [(u32(mm, dd + i * 8), u32(mm, dd + i * 8 + 4)) for i in range(n)]
        st = o + osz
        self.sections = []
        for i in range(min(nsec, 96)):
            s = st + i * 40
            vs, va, rs, rp = struct.unpack_from("<IIII", mm, s + 8)
            self.sections.append(dict(name=bytes(mm[s:s + 8]).rstrip(b"\0").decode("latin1"),
                                      vsize=vs, va=va, rsize=rs, rptr=rp, flags=u32(mm, s + 36)))
        self.ok = True

    def d(self, i):
        return self.dirs[i] if i < len(self.dirs) else (0, 0)

    def off(self, rva):
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
                return s["rptr"] + rva - s["va"]
        return rva if rva < 0x1000 else None

    def _thunks(self, tbl_rva, cap=6000):
        mm, step, names = self.mm, (8 if self.is64 else 4), []
        o = self.off(tbl_rva)
        while o is not None and len(names) < cap and o + step <= len(mm):
            v = u64(mm, o) if self.is64 else u32(mm, o)
            if v == 0:
                break
            if v >> (63 if self.is64 else 31):
                names.append(f"#ord{v & 0xFFFF}")
            else:
                names.append(cstr(mm, (self.off(v & 0x7FFFFFFF) or 0) + 2, 200))
            o += step
        return names

    def imports(self):
        res, mm = {}, self.mm
        rva, _ = self.d(1)
        o = self.off(rva) if rva else None
        n = 0
        while o is not None and n < 600 and o + 20 <= len(mm):
            oft, _, _, name, ft = struct.unpack_from("<IIIII", mm, o)
            if name == 0 and ft == 0:
                break
            res.setdefault(cstr(mm, self.off(name)).lower(), []).extend(self._thunks(oft or ft))
            o, n = o + 20, n + 1
        rva, _ = self.d(13)  # delay-load imports
        o = self.off(rva) if rva else None
        n = 0
        while o is not None and n < 600 and o + 32 <= len(mm):
            attrs, name, _, _, int_rva = struct.unpack_from("<IIIII", mm, o)[:5]
            if name == 0:
                break
            if attrs & 1:
                res.setdefault(cstr(mm, self.off(name)).lower() + " (delay)", []).extend(self._thunks(int_rva))
            o, n = o + 32, n + 1
        return res

    def exports(self, cap=400):
        rva, _ = self.d(0)
        o = self.off(rva) if rva else None
        if o is None:
            return []
        mm = self.mm
        count, names_rva = u32(mm, o + 24), u32(mm, o + 32)
        no, out = self.off(names_rva), []
        for i in range(min(count, cap)):
            if no is None:
                break
            out.append(cstr(mm, self.off(u32(mm, no + i * 4)), 200))
        return out

    def pdb_path(self):
        rva, size = self.d(6)
        o = self.off(rva) if rva else None
        mm = self.mm
        for i in range(min(size // 28, 8) if o is not None else 0):
            e = o + i * 28
            if u32(mm, e + 12) == 2:
                raw = u32(mm, e + 24)
                if mm[raw:raw + 4] == b"RSDS":
                    return cstr(mm, raw + 24, 260)
        return ""

    def entropy(self):
        res = []
        for s in self.sections:
            data = bytes(self.mm[s["rptr"]:s["rptr"] + min(s["rsize"], 1 << 20)])
            if not data:
                res.append((s["name"], 0.0))
                continue
            cnt = Counter(data)
            res.append((s["name"], -sum(v / len(data) * math.log2(v / len(data)) for v in cnt.values())))
        return res

CAPS = [
    ("network", ("ws2_32", "winhttp", "wininet", "mswsock", "iphlpapi", "dnsapi", "httpapi", "wsock32")),
    ("crypto", ("bcrypt", "crypt32", "ncrypt", "wintrust", "secur32", "sspicli")),
    ("windowing/UI", ("user32", "gdi32", "comctl32", "uxtheme", "dwmapi", "win32u", "comdlg32", "msimg32")),
    ("graphics", ("d3d", "dxgi", "d2d1", "dwrite", "opengl32", "vulkan", "gdiplus")),
    ("audio/video", ("winmm", "dsound", "mmdevapi", "audioses", "xaudio", "mf", "evr", "avrt", "ksuser")),
    ("shell/files", ("shell32", "shlwapi", "ole32", "oleaut32", "propsys", "shcore")),
    ("registry/security/services", ("advapi32", "wtsapi32", "userenv", "authz")),
    ("devices (USB/BT/HID)", ("setupapi", "hid", "bthprops", "winusb", "cfgmgr32", "wlanapi")),
    ("printing", ("winspool",)),
]
APIS = ("CreateProcess", "ShellExecute", "RegSetValue", "RegCreateKey", "URLDownloadToFile", "InternetOpen",
        "WSAStartup", "OpenClipboard", "SetWindowsHookEx", "RegisterHotKey", "CreateWindowEx", "DragAcceptFiles",
        "CryptProtectData", "BCryptEncrypt", "SetWinEventHook", "GetOpenFileName", "SHGetKnownFolderPath",
        "Shell_NotifyIcon", "ChangeServiceConfig", "CreateService", "LoadLibrary", "WinHttpSendRequest")

ASCII = re.compile(rb"[\x20-\x7e]{6,300}")
UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,300}")
RTTI = re.compile(rb"\.\?A[VU][\w@?$]{2,200}@@")
SRC = re.compile(r"([A-Za-z0-9_./\\+-]{3,160}\.(?:cc|cpp|cxx|c|h|hpp|mm|rs|go|swift|kt|java|cs))\b")
URL = re.compile(r"https?://[^\s\"'<>\\]{4,200}")
SECRETISH = re.compile(r"^(?:[A-Za-z0-9+/=_-]{32,}|AIza[\w-]{20,}|gh[pousr]_\w{20,}|sk-[\w-]{20,}|xox[abp]-[\w-]+)$")
ERRWORDS = ("failed to", "error", "invalid", "cannot", "unable to", "not found", "could not")

def scan_strings(mm):
    st = dict(src=Counter(), switches=Counter(), domains=Counter(), ui=[], ui_seen=set(), errors=[], err_seen=set(),
              classes=set(), redacted=0, total=0)
    def handle(s):
        st["total"] += 1
        if " " not in s and SECRETISH.match(s):
            st["redacted"] += 1
            return
        if len(s) > 8:
            for m in SRC.finditer(s):
                parts = [p for p in re.split(r"[\\/]+", m.group(1)) if p and p != ".."]
                if "src" in parts:
                    parts = parts[parts.index("src"):]
                st["src"]["/".join(parts[:-1][:4]) or "(root)"] += 1
        if s.startswith("--") and 5 <= len(s) <= 70 and re.match(r"--[a-z][a-z0-9-]+(=.*)?$", s):
            st["switches"][s.split("=")[0]] += 1
        if "://" in s:
            for m in URL.finditer(s):
                host = re.sub(r"^https?://", "", m.group(0)).split("/")[0].split("?")[0].split(":")[0].lower()
                if "." in host and len(host) < 80:
                    st["domains"][host] += 1
        if " " in s and 10 <= len(s) <= 140:
            letters = sum(c.isalpha() or c == " " for c in s)
            low = s.lower()
            if letters / len(s) >= 0.88 and len(s.split()) >= 2 and s[0].isupper() and len(st["ui"]) < 600 and s not in st["ui_seen"]:
                st["ui_seen"].add(s); st["ui"].append(s)
            if any(w in low for w in ERRWORDS) and 15 <= len(s) <= 160 and len(st["errors"]) < 150 and s not in st["err_seen"]:
                st["err_seen"].add(s); st["errors"].append(s)
    for m in ASCII.finditer(mm):
        handle(m.group().decode("ascii"))
    for m in UTF16.finditer(mm):
        handle(m.group().decode("utf-16le"))
    for m in RTTI.finditer(mm):
        raw = m.group()[4:-2].decode("ascii", "ignore")
        if "?$" not in raw:
            st["classes"].add("::".join(reversed([p for p in raw.split("@") if p])))
    return st

def version_info(mm):
    out = {}
    for key in ("ProductName", "FileDescription", "CompanyName", "ProductVersion", "OriginalFilename", "InternalName"):
        k = key.encode("utf-16le") + b"\0\0"
        i = mm.find(k)
        if i != -1:
            j = i + len(k)
            while j % 4:
                j += 1
            v = bytes(mm[j:j + 240]).split(b"\0\0")[0]
            v = v + b"\0" if len(v) % 2 else v
            out[key] = v.decode("utf-16le", "ignore").strip()
    return out

def analyse(path):
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        pe = PE(mm)
        info = dict(file=str(path.relative_to(INPUT)) if INPUT in path.parents else str(path), size_mb=round(len(mm) / 1048576, 2))
        if pe.ok:
            imp = pe.imports()
            caps = defaultdict(list)
            for dll in imp:
                base = dll.replace(" (delay)", "")
                for label, prefixes in CAPS:
                    if base.startswith(prefixes):
                        caps[label].append(dll)
            notable = sorted({a for fns in imp.values() for a in fns for p in APIS if a.startswith(p)})
            ent = pe.entropy()
            info.update(
                pe=dict(arch="x64" if pe.is64 else "x86", machine=hex(pe.machine), gui=pe.subsystem == 2,
                        dotnet=bool(pe.d(14)[0]), pdb=pe.pdb_path(), timestamp=pe.timestamp),
                sections=[dict(name=n, size_mb=round(s["rsize"] / 1048576, 2), entropy=round(e, 2))
                          for (n, e), s in zip(ent, pe.sections)],
                packed_hint=any(e > 7.4 and s["rsize"] > 65536 and not s["name"].startswith((".rsrc", ".rdata")) for (n, e), s in zip(ent, pe.sections)),
                imports={d: len(f_) for d, f_ in sorted(imp.items(), key=lambda kv: -len(kv[1]))[:60]},
                capabilities={k: sorted(v) for k, v in caps.items()},
                notable_apis=notable, exports=pe.exports())
        else:
            info["note"] = "Not a Windows PE file (" + pe.err + "); strings-only report."
        info["version_info"] = version_info(mm)
        st = scan_strings(mm)
    classes = sorted(st["classes"])
    ns = defaultdict(list)
    for c in classes:
        ns[c.split("::")[0] if "::" in c else "(global)"].append(c)
    info.update(
        string_count=st["total"], redacted_secret_like=st["redacted"],
        components=[dict(namespace=k, classes=len(v), sample=v[:6]) for k, v in sorted(ns.items(), key=lambda kv: -len(kv[1]))[:60]],
        source_dirs=st["src"].most_common(60), switches=[k for k, _ in st["switches"].most_common(150)],
        url_domains=st["domains"].most_common(40), ui_text=st["ui"][:200], error_messages=st["errors"][:80])
    return info

def to_md(i):
    L = [f"# Binary inventory: {i['file']}", "",
         "Static facts for the Analyst. Not code. Do not copy names, paths or texts into the spec; describe behaviour.", ""]
    L += [f"- size: {i['size_mb']} MB"]
    if "note" in i:
        L += [f"- {i['note']}"]
    if "pe" in i:
        p = i["pe"]
        L += [f"- arch: {p['arch']}, GUI app: {p['gui']}, .NET: {p['dotnet']}" + (" (use a .NET decompiler instead)" if p["dotnet"] else ""),
              f"- build path hint (metadata only): `{p['pdb']}`" if p["pdb"] else "- no debug path",
              f"- packed/protected hint: {i['packed_hint']}" + (" (do NOT defeat protection; report it and fall back to observing behaviour)" if i["packed_hint"] else "")]
    if i["version_info"]:
        L += ["- version info: " + ", ".join(f"{k}={v}" for k, v in i["version_info"].items() if v)]
    if "sections" in i:
        L += ["", "## Sections", "| name | size MB | entropy |", "|---|---|---|"] + [f"| {s['name']} | {s['size_mb']} | {s['entropy']} |" for s in i["sections"]]
        L += ["", "## What it is capable of (from imported system libraries)"]
        L += [f"- **{k}**: {', '.join(v[:8])}" for k, v in i["capabilities"].items()] or ["- (none detected)"]
        if i["notable_apis"]:
            L += ["", "Notable system calls: " + ", ".join(i["notable_apis"][:40])]
        L += ["", "## Imports (library: function count)"] + [f"- {d}: {n}" for d, n in list(i["imports"].items())[:30]]
        if i["exports"]:
            L += ["", f"## Exported functions ({len(i['exports'])} shown)"] + [f"- {e}" for e in i["exports"][:150]]
    if i["components"]:
        L += ["", "## Component map from C++ class names (namespace: class count, samples)"]
        L += [f"- **{c['namespace']}**: {c['classes']} ({', '.join(c['sample'][:4])})" for c in i["components"][:40]]
    if i["source_dirs"]:
        L += ["", "## Source directories referenced in the binary (component hints)"] + [f"- {d}: {n}" for d, n in i["source_dirs"][:40]]
    if i["switches"]:
        L += ["", "## Command-line switches (feature flags / modes)", ", ".join(i["switches"][:100])]
    if i["url_domains"]:
        L += ["", "## Network endpoints (domains only)", ", ".join(d for d, _ in i["url_domains"][:30])]
    if i["ui_text"]:
        L += ["", "## UI text candidates (use only to understand features; write your own copy)"] + [f"- {t}" for t in i["ui_text"][:120]]
    if i["error_messages"]:
        L += ["", "## Error/log messages (hints about behaviour and edge cases)"] + [f"- {t}" for t in i["error_messages"][:50]]
    L += ["", f"_strings scanned: {i['string_count']}; secret-like strings redacted: {i['redacted_secret_like']}_"]
    return "\n".join(L) + "\n"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*")
    ap.add_argument("--top", type=int, default=15, help="how many of the largest DLLs to analyse besides all EXEs")
    a = ap.parse_args()
    if a.files:
        targets = [Path(x).resolve() for x in a.files]
    else:
        exes = [p for p in INPUT.rglob("*") if p.suffix.lower() == ".exe" and p.is_file()]
        dlls = sorted((p for p in INPUT.rglob("*") if p.suffix.lower() in (".dll", ".ocx", ".node") and p.is_file()),
                      key=lambda p: -p.stat().st_size)[:a.top]
        targets = exes + dlls
    if not targets:
        print("No .exe/.dll found in input/.")
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    index = ["# Binary inventory index", ""]
    for p in targets:
        sz = p.stat().st_size
        if sz == 0 or sz > MAX_BYTES:
            print("skip (empty or > 700 MB):", p.name)
            continue
        print(f"analysing {p.name} ({sz / 1048576:.1f} MB) ...", flush=True)
        info = analyse(p)
        name = re.sub(r"[^A-Za-z0-9_.-]+", "_", info["file"])
        (OUT / f"{name}.json").write_text(json.dumps(info, indent=1, ensure_ascii=False), encoding="utf-8")
        (OUT / f"{name}.md").write_text(to_md(info), encoding="utf-8")
        index.append(f"- [{info['file']}]({name}.md): {info['size_mb']} MB, {len(info['components'])} namespaces, "
                     f"{len(info.get('exports', []))} exports, {len(info['switches'])} switches")
    (OUT / "INDEX.md").write_text("\n".join(index) + "\n", encoding="utf-8")
    print("Reports in", OUT.relative_to(ROOT))
    return 0

if __name__ == "__main__":
    sys.exit(main())
