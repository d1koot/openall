#!/usr/bin/env python3
"""OpenAll shelf builder (prototype v0): Windows PE x64 -> shelves 0, 1, 2 (see docs/FORMAT.md).

Everything here is deterministic code. No model is involved and nothing is guessed:
  shelf 0  container facts (sections, imports, exports, strings, hashes)
  shelf 1  functions, call graph, references, origin class, bottom-up order
  shelf 2  data items touched by code (globals, tables) and who reads/writes them
It does NOT unpack or defeat protections (a packed file is only flagged) and redacts secret-like strings.

Needs:  pip install capstone pefile
Usage:  build_shelves.py --learn ref1.exe ref2.exe   (once per toolchain; stores hashes in refsets/)
        build_shelves.py target.exe [--out DIR] [--baseline extra.exe ...] [--all-disasm]
--baseline: reference builds made with the SAME toolchain (your own small programs). Functions whose normalised
bytes also appear there are marked origin=runtime. This is how compiler/library code is separated from the
program's own code.
"""
import argparse, bisect, hashlib, json, math, os, re, struct, sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    import capstone
    from capstone import x86 as cx
    import pefile
except ImportError:
    sys.exit("build_shelves.py needs:  pip install capstone pefile")

ANALYSIS_VERSION = 4        # bump when function discovery changes: reference sets store hashes of what the analyser sees
EXEC_FLAG = 0x20000000
MAX_FUNCS = 60000
RUNTIME_NAME = re.compile(
    r"^(_*mingw|_*gnu|_*pre_c_init|_*pre_cpp|_*atexit|_*security_cookie|_*tmainCRT|_*do_global|_*register_frame|"
    r"_*deregister|_*tls|_*dyn_tls|_*gcc|_*chkstk|__main$|_*fpreset|_*setargv|_*wsetargv|WinMainCRTStartup|"
    r"mainCRTStartup|_*acrt|_*scrt|_*vcrt)")
SECRET = re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token|BEGIN [A-Z ]*PRIVATE KEY|authorization:)")
TOKENLIKE = re.compile(r"^[A-Za-z0-9+/=_\-]{32,}$")


def fid(rva): return f"F:{rva:08x}"
def sid(rva): return f"S:{rva:08x}"
def did(rva): return f"D:{rva:08x}"


class Target:
    """One PE x64 file: parsed once, then discover() fills functions/strings/data."""

    def __init__(self, path):
        self.path = Path(path)
        self.pe = pefile.PE(str(path))
        pe = self.pe
        if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20B:
            raise SystemExit(f"{path}: not a Windows PE x64 file (prototype supports PE x64 only)")
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.image_size = pe.OPTIONAL_HEADER.SizeOfImage
        self.entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.secs = []
        for s in pe.sections:
            self.secs.append(dict(name=s.Name.rstrip(b"\0").decode("latin1"), va=s.VirtualAddress,
                                  vsize=s.Misc_VirtualSize, rsize=s.SizeOfRawData, flags=s.Characteristics,
                                  data=s.get_data()[: max(s.Misc_VirtualSize, 0) or s.SizeOfRawData]))
        self.exec_secs = [s for s in self.secs if s["flags"] & EXEC_FLAG]
        self.data_secs = [s for s in self.secs if not s["flags"] & EXEC_FLAG and not s["flags"] & 0x02000000]  # skip discardable (debug) sections
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        self.iat, self.imports, self.exports = {}, defaultdict(list), {}
        self._load_imports_exports()
        self.symbols = self._coff_symbols()
        self.strings = []           # (rva, text)
        self._str_starts = []
        self._scan_strings()
        self.funcs = {}             # begin_rva -> dict
        self.datarefs = defaultdict(lambda: {"readers": set(), "writers": set()})

    # ---------- container ----------
    def sec_of(self, rva, pool=None):
        for s in (pool if pool is not None else self.secs):
            if s["va"] <= rva < s["va"] + max(s["vsize"], len(s["data"])):
                return s
        return None

    def in_exec(self, rva): return self.sec_of(rva, self.exec_secs) is not None

    def code(self, rva, n=15):
        s = self.sec_of(rva, self.exec_secs)
        if not s: return b""
        o = rva - s["va"]
        return s["data"][o:o + n]

    def _load_imports_exports(self):
        pe = self.pe
        for ent in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = ent.dll.decode("latin1").lower()
            for imp in ent.imports:
                nm = imp.name.decode("latin1") if imp.name else f"ord{imp.ordinal}"
                self.iat[imp.address - self.base] = f"I:{dll}!{nm}"
                self.imports[dll].append(nm)
        for sym in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or []:
            if sym.address and sym.name:
                self.exports[sym.address] = sym.name.decode("latin1")

    def _coff_symbols(self):
        """Function symbols from the COFF table (present only in unstripped files). rva -> name."""
        pe, out = self.pe, {}
        ptr, n = pe.FILE_HEADER.PointerToSymbolTable, pe.FILE_HEADER.NumberOfSymbols
        raw = pe.__data__
        if not ptr or not n or ptr + n * 18 > len(raw): return out
        strtab = ptr + n * 18
        i = 0
        while i < n:
            rec = bytes(raw[ptr + i * 18: ptr + i * 18 + 18])
            n8 = rec[:8]
            value, sec, typ, _stor, naux = struct.unpack("<IhHBB", rec[8:18])
            if n8[:4] == b"\0\0\0\0":
                off = struct.unpack("<I", n8[4:])[0]
                end = bytes(raw[strtab + off: strtab + off + 300]).find(b"\0")
                name = bytes(raw[strtab + off: strtab + off + (end if end >= 0 else 300)]).decode("latin1")
            else:
                name = n8.rstrip(b"\0").decode("latin1")
            if (typ & 0xF0) == 0x20 and 0 < sec <= len(pe.sections):
                out[pe.sections[sec - 1].VirtualAddress + value] = name
            i += 1 + naux
        return out

    def _scan_strings(self):
        for s in self.data_secs:
            if not s["data"]: continue
            for m in re.finditer(rb"[\x20-\x7e]{5,}", s["data"]):
                text = m.group().decode("ascii")
                if SECRET.search(text) or (TOKENLIKE.match(text) and not text.startswith(('_Z', '?'))):
                    text = "<redacted: secret-like string>"
                self.strings.append((s["va"] + m.start(), text[:200], m.end() - m.start()))
        self.strings.sort()
        self._str_starts = [x[0] for x in self.strings]

    def read_at(self, rva, n):
        sec = self.sec_of(rva)
        if not sec: return b""
        o = rva - sec["va"]
        return sec["data"][o:o + n]

    def class_hint(self, table_start):
        """Itanium ABI (GCC/Clang): vtable[-1] -> type_info object -> name pointer -> '6Circle'. Returns 'Circle' or None."""
        b = self.read_at(table_start - 8, 8)
        if len(b) < 8: return None
        ti = struct.unpack("<Q", b)[0] - self.base
        nm = self.read_at(ti + 8, 8)
        if len(nm) < 8: return None
        raw = self.read_at(struct.unpack("<Q", nm)[0] - self.base, 80)
        txt = raw.split(b"\0", 1)[0].decode("latin1")
        m = re.match(r"^(\d+)([A-Za-z_]\w*)$", txt)
        if m and int(m.group(1)) == len(m.group(2)): return m.group(2)
        return None

    def describe_data(self, a):
        """What sits at a data address: integer, double, pointer to a known string, or an array of such pointers."""
        b = self.read_at(a, 64)
        d = {}
        if len(b) >= 4: d["i32"] = struct.unpack_from("<i", b)[0]
        if len(b) >= 8:
            u = struct.unpack_from("<Q", b)[0]
            r = u - self.base
            if 0 < r < 0x10000000 and self.string_at(r) == r: d["ptr_string"] = sid(r)
            else:
                f = struct.unpack_from("<d", b)[0]
                if f == f and 1e-12 < abs(f) < 1e15: d["f64"] = f
        nul = b.find(b"\0")
        head = b[:nul] if nul >= 0 else b[:32]
        if len(head) >= 3 and all(0x20 <= c <= 0x7e for c in head) and "ptr_string" not in d:
            txt = head.decode("ascii")
            d["ascii"] = "<redacted: secret-like>" if SECRET.search(txt) else txt
        arr = []
        for i in range(0, len(b) - 7, 8):
            r = struct.unpack_from("<Q", b, i)[0] - self.base
            if 0 < r < 0x10000000 and self.string_at(r) == r: arr.append(sid(r))
            else: break
        if len(arr) >= 2: d["ptr_array_strings"] = arr
        return d

    def string_at(self, rva):
        i = bisect.bisect_right(self._str_starts, rva) - 1
        if i >= 0:
            start, _t, ln = self.strings[i]
            if start <= rva < start + ln + 1: return start
        return None

    def _short_string(self, rva):
        """Register a short (1-200 chars) NUL-terminated printable string that code points at with lea."""
        sec = self.sec_of(rva, self.data_secs)
        if not sec: return None
        o = rva - sec["va"]
        chunk = sec["data"][o:o + 201]
        if len(chunk) >= 8 and 0 <= struct.unpack_from("<Q", chunk)[0] - self.base < self.image_size:
            return None                        # an 8-byte pointer into the image (vtable slot, function pointer), not text
        end = chunk.find(b"\0")
        if end < 1 or any(c < 0x20 or c > 0x7e for c in chunk[:end]): return None
        text = chunk[:end].decode("ascii")
        if SECRET.search(text) or (TOKENLIKE.match(text) and not text.startswith(('_Z', '?'))): text = "<redacted: secret-like string>"
        i = bisect.bisect_left(self._str_starts, rva)
        self._str_starts.insert(i, rva)
        self.strings.insert(i, (rva, text, end))
        return rva

    # ---------- function discovery ----------
    def _pdata(self):
        d = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if not d.VirtualAddress or not d.Size: return []
        data = self.pe.get_data(d.VirtualAddress, d.Size)
        out = []
        for i in range(len(data) // 12):
            b, e, u = struct.unpack_from("<III", data, i * 12)
            if not b: continue
            if not u & 1:                          # chained unwind info = fragment of another function
                try:
                    if self.pe.get_data(u, 1)[0] >> 3 & 4: continue
                except Exception:
                    pass
            out.append((b, e, u))
        return out

    def container(self, a):
        """Start of the pdata function that strictly contains address a (an interior label), else None."""
        i = bisect.bisect_right(self._pd_starts, a) - 1
        if i >= 0:
            b, e = self._pd_ranges[i]
            if b < a < e: return b
        return None

    def discover(self):
        for b, e, u in self._pdata():
            self.funcs[b] = dict(end=e, source="pdata", unwind=u)
        for rva in [self.entry, *self.exports]:
            self.funcs.setdefault(rva, dict(end=None, source="entry" if rva == self.entry else "export"))
        for rva in self.symbols:
            if self.in_exec(rva): self.funcs.setdefault(rva, dict(end=None, source="symbol"))
        self._pd_ranges = sorted((b, f["end"]) for b, f in self.funcs.items() if f["source"] == "pdata")
        self._pd_starts = [b for b, _e in self._pd_ranges]
        todo = sorted(self.funcs)
        done = set()
        while todo and len(self.funcs) < MAX_FUNCS:
            b = todo.pop()
            if b in done or not self.in_exec(b): continue
            done.add(b)
            for tgt in self._explore(b):
                c = self.container(tgt)
                if c is not None:                      # a jump into the middle of a known function: an extra entry, not a new function
                    ex = self.funcs[c].setdefault("extra", set())
                    if tgt not in ex:
                        ex.add(tgt); done.discard(c); todo.append(c)
                    continue
                if tgt not in self.funcs and self.in_exec(tgt):
                    self.funcs[tgt] = dict(end=None, source="call")
                    todo.append(tgt)
        unexplored = [b for b, f in self.funcs.items() if "calls" not in f]
        for b in unexplored: del self.funcs[b]              # e.g. an entry point outside executable code (packed files)
        if unexplored:
            print(f"warning: {len(unexplored)} function start(s) ignored: not inside executable code "
                  f"(entry point or exports of an odd or packed file)", file=sys.stderr)
        self._finalize()

    def pointer_tables(self):
        """Runs of 8-byte values in data sections that point at known function starts (vtables, callback arrays)."""
        starts, tables = set(self.funcs), []
        for sec in self.data_secs:
            n = len(sec["data"]) // 8
            if not n: continue
            run = []
            for i, v in enumerate(struct.unpack_from(f"<{n}Q", sec["data"], 0)):
                r = v - self.base
                if r in starts:
                    run.append((sec["va"] + i * 8, r))
                else:
                    if run: tables.append((sec, run))
                    run = []
            if run: tables.append((sec, run))
        return tables

    def _parse_lsda(self, rva, begin):
        """Itanium-style call-site table (GCC C++ exceptions). Returns landing pad addresses (rva)."""
        d = self.read_at(rva, 4096)
        p = 0
        def uleb():
            nonlocal p
            r = sh = 0
            while True:
                b = d[p]; p += 1; r |= (b & 0x7F) << sh; sh += 7
                if not b & 0x80: return r
        if d[p] != 0xFF: return []                 # explicit LPStart: not supported
        p += 1
        tt = d[p]; p += 1
        if tt != 0xFF: uleb()
        cs = d[p]; p += 1
        if cs not in (0x01, 0x03): return []
        end = p + uleb()
        pads = set()
        while p < end:
            if cs == 0x01: _a, _l, lp = uleb(), uleb(), uleb()
            else: _a, _l, lp = struct.unpack_from("<III", d, p); p += 12
            uleb()
            if lp: pads.add(begin + lp)
        return sorted(pads)

    def pads_of(self, begin, f=None):
        """All landing pad addresses (rva) from this function's exception table; [] if none."""
        f = f or self.funcs.get(begin) or {}
        u = f.get("unwind")
        if not u or u & 1: return []
        try:
            hdr = self.pe.get_data(u, 4)
            if not (hdr[0] >> 3) & 3: return []
            off = u + 4 + ((hdr[2] + 1) & ~1) * 2
            return self._parse_lsda(off + 4, begin)           # the table is inline (GCC SEH)
        except Exception:
            return []

    def landing_pads(self):
        """parent function rva -> landing pads that are separate function starts (reached by unwinding, not calls)."""
        out = {}
        for b, f in self.funcs.items():
            pads = [x for x in self.pads_of(b, f) if x in self.funcs and x != b]
            if pads: out[b] = pads
        return out

    def table_users(self):
        """function rva -> set of function rvas that use a pointer table the function sits in."""
        res = defaultdict(set)
        for _sec, run in self.pointer_tables():
            start, end = run[0][0], run[-1][0] + 8
            users = {b for b, f in self.funcs.items() if any(start - 16 <= a < end for a in f["reads"])}
            for _a, r in run: res[r] |= users
        return res

    def fingerprint(self):
        """Toolchain fingerprint: compiler version string if present, else linker version + C runtime family."""
        raw = bytes(self.pe.__data__)
        m = re.search(rb"GCC: \(([^)]*)\) ([0-9][0-9.]*)", raw)
        if m: comp = "gcc " + m.group(1).decode("latin1") + " " + m.group(2).decode("latin1")
        else: comp = f"link{self.pe.OPTIONAL_HEADER.MajorLinkerVersion}.{self.pe.OPTIONAL_HEADER.MinorLinkerVersion}"
        dlls = " ".join(self.imports)
        crt = ("ucrt" if "api-ms-win-crt" in dlls else "vcrt" if "vcruntime" in dlls else
               "msvcrt" if "msvcrt.dll" in dlls else "other")
        return f"{comp} | {crt}"

    def _jump_table(self, cands, begin, lim):
        """Resolve a switch table: 32-bit entries, either relative to the table (GCC) or RVAs (MSVC style).
        Accepts a table only if at least two consecutive entries land inside this function. Returns target rvas."""
        for x in reversed(cands):
            raw = self.read_at(x, 4 * 256)
            vals = struct.unpack_from(f"<{len(raw) // 4}i", raw, 0)
            for mode in ("rel", "rva"):
                out = []
                for v in vals:
                    t = x + v if mode == "rel" else v
                    if begin <= t < lim and self.in_exec(t): out.append(t)
                    else: break
                if len(out) >= 2: return out
        return []

    def _explore(self, begin):
        """Recursive descent inside one function. Fills self.funcs[begin]; returns new call targets."""
        f = self.funcs[begin]
        hard_end = f["end"]
        lim = hard_end if hard_end else begin + 0x4000
        known = self.funcs
        pads_in = [x for x in self.pads_of(begin, f) if begin <= x < lim and x != begin]
        extra = [x for x in sorted(f.get("extra", ())) if begin <= x < lim]
        insns, stack, leaders = {}, [begin] + pads_in + extra, {begin} | set(pads_in) | set(extra)
        calls, jumps_out, imps, imp_calls = set(), set(), set(), set()
        strs, fnrefs = set(), set()
        reads, writes = set(), set()
        ind_calls = ind_jumps = 0
        jt = 0
        while stack:
            a = stack.pop()
            cands = []                                   # data addresses that may hold a switch table on this path
            while a not in insns and begin <= a < lim:
                raw = self.code(a)
                ins = next(self.md.disasm(raw, self.base + a, 1), None) if raw else None
                if ins is None: break
                insns[a] = ins
                nxt = a + ins.size
                mn = ins.mnemonic
                # rip-relative memory references (strings, globals, import slots, code addresses)
                for op in ins.operands:
                    if op.type == cx.X86_OP_MEM and op.mem.index and op.mem.base != cx.X86_REG_RIP and op.mem.disp > 0 \
                       and self.sec_of(op.mem.disp, self.data_secs):
                        cands.append(op.mem.disp)        # MSVC style: [imagebase_reg + idx*4 + table_rva]
                    if op.type == cx.X86_OP_MEM and op.mem.base == cx.X86_REG_RIP:
                        t = nxt + op.mem.disp
                        if mn == "lea" and self.sec_of(t, self.data_secs):
                            cands.append(t)              # GCC style: lea reg,[rip+table]
                        if t in self.iat:
                            imps.add(self.iat[t])
                            if mn == "call": imp_calls.add(self.iat[t])
                            continue
                        s = self.string_at(t)
                        if s is None and mn == "lea":
                            s = self._short_string(t)      # code takes the address of a short C string
                        if s is not None: strs.add(sid(s)); continue
                        if self.in_exec(t):
                            fnrefs.add(t); continue
                        if self.sec_of(t, self.data_secs):
                            (writes if op.access & capstone.CS_AC_WRITE else reads).add(t)
                if mn in ("call", "jmp") or mn.startswith("j"):
                    tgt = None
                    if ins.operands and ins.operands[0].type == cx.X86_OP_IMM:
                        tgt = ins.operands[0].imm - self.base
                    if mn == "call":
                        if tgt is not None: calls.add(tgt)
                        elif not (ins.operands and ins.operands[0].type == cx.X86_OP_MEM
                                  and ins.operands[0].mem.base == cx.X86_REG_RIP
                                  and nxt + ins.operands[0].mem.disp in self.iat):
                            ind_calls += 1
                    elif tgt is not None:
                        internal = (begin <= tgt < lim) and (tgt == begin or tgt not in known or known[tgt]["source"] == "call")
                        if hard_end: internal = begin <= tgt < hard_end
                        if internal:
                            leaders.add(tgt)
                            if tgt not in insns: stack.append(tgt)
                        else:
                            jumps_out.add(tgt)           # tail call
                        if mn != "jmp": leaders.add(nxt)
                        if mn == "jmp": break
                    else:                                 # indirect jmp
                        if mn == "jmp":
                            m = ins.operands[0] if ins.operands else None
                            if m is not None and m.type == cx.X86_OP_MEM and m.mem.base == cx.X86_REG_RIP \
                               and nxt + m.mem.disp in self.iat:
                                imp_calls.add(self.iat[nxt + m.mem.disp])
                            else:
                                targets = self._jump_table(cands[-6:], begin, lim)
                                if targets:
                                    jt += 1
                                    for x in targets:
                                        leaders.add(x)
                                        if x not in insns: stack.append(x)
                                else:
                                    ind_jumps += 1
                            break
                if mn in ("ret", "int3", "ud2", "hlt"): break
                a = nxt
        order = sorted(insns)
        end = (order[-1] + insns[order[-1]].size) if order else begin
        f.update(insns=insns, size=(hard_end - begin) if hard_end else end - begin, blocks=len(leaders),
                 calls=calls, tails=jumps_out, imports=imps, import_calls=imp_calls, strs=strs,
                 fnrefs=fnrefs, reads=reads, writes=writes, pads_in=len(pads_in), jump_tables=jt, ind_calls=ind_calls, ind_jumps=ind_jumps)
        return list(calls | jumps_out)

    def _canon(self, a):
        c = self.container(a)
        return a if c is None else c

    def _finalize(self):
        for f in self.funcs.values():                  # calls/jumps into a function's interior count as edges to that function
            if "calls" in f:
                f["calls"] = {self._canon(x) for x in f["calls"]}
                f["tails"] = {self._canon(x) for x in f["tails"]}
        starts = sorted(self.funcs)
        for b, f in self.funcs.items():
            f.setdefault("insns", {})
            f["name_hint"], f["name_source"] = None, "none"
            if b in self.symbols: f["name_hint"], f["name_source"] = self.symbols[b], "symbol"
            elif b in self.exports: f["name_hint"], f["name_source"] = self.exports[b], "export"
            f["norm_hash"] = self._norm_hash(f)

    def _norm_hash(self, f):
        """Hash of the function bytes with addresses masked (so layout changes do not matter)."""
        h = hashlib.sha1()
        for a in sorted(f["insns"]):
            i = f["insns"][a]
            b = bytearray(i.bytes)
            masks = []
            rip = any(o.type == cx.X86_OP_MEM and o.mem.base == cx.X86_REG_RIP for o in i.operands)
            cf = i.mnemonic == "call" or i.mnemonic.startswith("j")
            if rip and i.disp_size: masks.append((i.disp_offset, i.disp_size))
            if cf and i.imm_size: masks.append((i.imm_offset, i.imm_size))
            for off, n in masks:
                for k in range(off, off + n): b[k] = 0
            h.update(bytes(b))
        return h.hexdigest()


# ---------- classification, ordering, output ----------

MIN_STRONG = 6      # a byte match shorter than this is only believed when a runtime function calls it


def classify(t, ref_hashes, pad_of, tab_users):
    funcs = t.funcs
    callers = defaultdict(set)
    for b, f in funcs.items():
        for c in f["calls"] | f["tails"]: callers[c].add(b)
    weak = []
    for b, f in funcs.items():
        n = len(f["insns"])
        f["origin"], f["origin_why"], f["thunk_to"] = "unknown", "no rule matched; treat as own until shown otherwise", None
        if n <= 2 and f["import_calls"] and not f["calls"]:
            f["thunk_to"] = sorted(f["import_calls"])[0]
            f["origin"], f["origin_why"] = "library", "thin thunk to an import"
        elif f["norm_hash"] in ref_hashes and n >= MIN_STRONG:
            f["origin"], f["origin_why"] = "runtime", "bytes match a reference build: " + ref_hashes[f["norm_hash"]]
        elif f["norm_hash"] in ref_hashes and n >= 1:
            weak.append(b)
        elif f["name_source"] == "symbol" and RUNTIME_NAME.match(f["name_hint"] or ""):
            f["origin"], f["origin_why"] = "runtime", "symbol name matches a known runtime pattern"
    changed = True
    while changed:                                   # short matches and landing pads follow their runtime neighbours
        changed = False
        for b in weak:
            f = funcs[b]
            if f["origin"] != "unknown": continue
            cs, us = callers.get(b, ()), tab_users.get(b, ())
            if any(funcs[c]["origin"] == "runtime" for c in cs):
                why = "short bytes match a reference build and a runtime function calls it"
            elif not cs and all(funcs[u]["origin"] == "runtime" for u in us):
                why = "short bytes match a reference build; nothing of the program's own calls or uses it"
            elif any(funcs[u]["origin"] == "runtime" for u in us):
                why = "short bytes match a reference build and a runtime function also uses the table it sits in"
            else:
                continue
            f["origin"], f["origin_why"] = "runtime", why
            changed = True
        for b, parents in pad_of.items():
            f = funcs[b]
            if f["origin"] == "unknown" and all(funcs[p]["origin"] == "runtime" for p in parents):
                f["origin"], f["origin_why"] = "runtime", "landing pad of a runtime function"
                changed = True
    for b in weak:
        if funcs[b]["origin"] == "unknown":
            funcs[b]["origin_why"] = "short function whose bytes also occur in a reference build; not enough to call it runtime"


def refset_dir():
    return Path(os.environ["OPENALL_REFSETS"]) if os.environ.get("OPENALL_REFSETS") else Path(__file__).resolve().parent.parent / "refsets"


def refset_path(fp):
    slug = re.sub(r"[^a-z0-9]+", "-", fp.lower()).strip("-")[:70]
    return refset_dir() / f"{slug}-{hashlib.sha1(fp.encode()).hexdigest()[:8]}.json"


def learn(paths):
    """Store normalised function hashes of reference programs under the toolchain fingerprint (no binaries, no code)."""
    fps, hashes = set(), {}
    for p in paths:
        t = Target(p); t.discover(); fps.add(t.fingerprint())
        for f in t.funcs.values():
            if f["insns"]: hashes.setdefault(f["norm_hash"], Path(p).name)
    if len(fps) != 1: sys.exit("The reference programs come from different toolchains: " + "; ".join(sorted(fps)))
    fp = fps.pop(); rp = refset_path(fp)
    old = json.loads(rp.read_text()) if rp.exists() else {"functions": {}}
    if old.get("analysis_version", ANALYSIS_VERSION) != ANALYSIS_VERSION: old = {"functions": {}}   # stale: start over
    old["fingerprint"] = fp; old["functions"].update(hashes); old["analysis_version"] = ANALYSIS_VERSION
    refset_dir().mkdir(exist_ok=True); rp.write_text(json.dumps(old, indent=0))
    print(f"reference set for [{fp}]: {len(old['functions'])} function hashes -> {rp.name}")


def bottom_up(edges):
    """Tarjan SCC; emits callee groups before their callers."""
    sys.setrecursionlimit(100000)
    idx, low, onst, st, out, c = {}, {}, set(), [], [], [0]
    def go(v):
        idx[v] = low[v] = c[0]; c[0] += 1; st.append(v); onst.add(v)
        for w in edges.get(v, ()):
            if w not in idx: go(w); low[v] = min(low[v], low[w])
            elif w in onst: low[v] = min(low[v], idx[w])
        if low[v] == idx[v]:
            g = []
            while True:
                w = st.pop(); onst.discard(w); g.append(w)
                if w == v: break
            out.append(sorted(g))
    for v in sorted(edges):
        if v not in idx: go(v)
    return out


def entropy(b):
    if not b: return 0.0
    cnt = Counter(b); n = len(b)
    return -sum(v / n * math.log2(v / n) for v in cnt.values())


def ascii_note(i):
    """Compilers store short strings as immediates (movabs rax, 0x332a322b31). Show them as a hint."""
    if i.mnemonic in ("call", "jmp") or i.mnemonic.startswith("j"): return ""
    for op in i.operands:
        if op.type == cx.X86_OP_IMM and op.size >= 4:
            v = op.imm & ((1 << (8 * op.size)) - 1)
            b = v.to_bytes(op.size, "little").rstrip(b"\0")
            if len(b) >= 3 and all(0x20 <= c <= 0x7e for c in b):
                txt = b.decode("ascii")
                return "  ; ascii-looking constant: " + ("<redacted>" if SECRET.search(txt) else repr(txt))
    return ""


def write_shelves(t, out, all_disasm):
    out.mkdir(parents=True, exist_ok=True)
    (out / "disasm").mkdir(exist_ok=True)
    funcs = t.funcs
    callers = defaultdict(set)
    for b, f in funcs.items():
        for c in f["calls"] | f["tails"]:
            if c in funcs: callers[c].add(b)
    pads = t.landing_pads()
    pad_of = defaultdict(set)
    for par, ps in pads.items():
        for x in ps: pad_of[x].add(par)
    str_use = defaultdict(set); dat_r = defaultdict(set); dat_w = defaultdict(set)
    for b, f in funcs.items():
        for s in f["strs"]: str_use[s].add(fid(b))
        for a in f["reads"]: dat_r[a].add(fid(b))
        for a in f["writes"]: dat_w[a].add(fid(b))

    # shelf 0
    raw = Path(t.path).read_bytes()
    sections = [dict(id=f"X:{s['name']}", rva=s["va"], vsize=s["vsize"], raw_size=s["rsize"],
                     executable=bool(s["flags"] & EXEC_FLAG), entropy=round(entropy(s["data"][:1 << 20]), 2))
                for s in t.secs]
    packed = [s["id"] for s in sections if s["entropy"] > 7.2 and s["executable"]]
    shelf0 = dict(file=t.path.name, size=len(raw), sha256=hashlib.sha256(raw).hexdigest(), machine="x64",
                  image_base=hex(t.base), entry=fid(t.entry), coff_symbols=len(t.symbols),
                  subsystem=t.pe.OPTIONAL_HEADER.Subsystem, sections=sections,
                  possibly_packed=packed, imports={k: sorted(set(v)) for k, v in sorted(t.imports.items())},
                  exports=[dict(id=fid(r), name=n) for r, n in sorted(t.exports.items())],
                  strings_count=len(t.strings))
    (out / "shelf0_container.json").write_text(json.dumps(shelf0, indent=1))
    with open(out / "shelf0_strings.jsonl", "w") as fh:
        for rva, text, _ln in t.strings:
            fh.write(json.dumps(dict(id=sid(rva), text=text, used_by=sorted(str_use.get(sid(rva), ())))) + "\n")

    # shelf 2: pointer tables first (T:), then plain data items (D:)
    tables = t.pointer_tables()
    in_tab = defaultdict(list)
    tab_records = []
    for sec, run in tables:
        start, end = run[0][0], run[-1][0] + 8
        users = sorted({fid(b) for b, f in funcs.items() if any(start - 16 <= a < end for a in f["reads"])})
        tid = f"T:{start:08x}"
        for _a, r in run: in_tab[fid(r)].append(tid)
        rec = dict(id=tid, kind="vtable_candidate" if len(run) >= 2 else "function_pointer",
                   section=f"X:{sec['name']}", entries=[fid(r) for _a, r in run], used_by=users)
        if len(run) >= 2:
            ch = t.class_hint(start)
            if ch: rec["class_hint"], rec["class_hint_source"] = ch, "itanium_rtti"
        tab_records.append(rec)
    # shelf 1
    edges = {fid(b): sorted(fid(c) for c in (f["calls"] | f["tails"]) if c in funcs) for b, f in funcs.items()}
    with open(out / "shelf1_code.jsonl", "w") as fh:
        for b in sorted(funcs):
            f = funcs[b]
            path = None
            if all_disasm or f["origin"] in ("own", "unknown"):
                path = f"disasm/F-{b:08x}.txt"
                (out / path).write_text("\n".join(
                    f"{a:08x}  {i.mnemonic} {i.op_str}".rstrip() + ascii_note(i)
                    for a, i in sorted(f["insns"].items())) + "\n")
            rec = dict(id=fid(b), source=f["source"], size=f["size"], insn_count=len(f["insns"]), blocks=f["blocks"],
                       callers=sorted(fid(c) for c in callers.get(b, ())), callees=edges[fid(b)] +
                       sorted(f["import_calls"]), imports=sorted(f["imports"]), strings=sorted(f["strs"]),
                       data_read=sorted(did(a) for a in f["reads"]), data_written=sorted(did(a) for a in f["writes"]),
                       address_taken_fns=sorted(fid(a) for a in f["fnrefs"] if a in funcs),
                       indirect_calls=f["ind_calls"], indirect_jumps=f["ind_jumps"], jump_tables=f.get("jump_tables", 0),
                       landing_pad_count=f.get("pads_in", 0),
                       landing_pads=sorted(fid(x) for x in pads.get(b, ())),
                       landing_pad_of=sorted(fid(x) for x in pad_of.get(b, ())),
                       in_tables=sorted(in_tab.get(fid(b), [])),
                       uses_tables=sorted(r["id"] for r in tab_records if fid(b) in r["used_by"]),
                       name_hint=f["name_hint"], name_source=f["name_source"],
                       origin=f["origin"], origin_why=f["origin_why"], thunk_to=f["thunk_to"], disasm=path)
            fh.write(json.dumps(rec) + "\n")
    groups = bottom_up({k: v for k, v in edges.items()})
    (out / "bottom_up.json").write_text(json.dumps(groups))

    with open(out / "shelf2_data.jsonl", "w") as fh:
        for rec in tab_records: fh.write(json.dumps(rec) + "\n")
        for a in sorted(set(dat_r) | set(dat_w)):
            sec = t.sec_of(a, t.data_secs)
            fh.write(json.dumps(dict(id=did(a), section=f"X:{sec['name']}" if sec else None,
                                     readers=sorted(dat_r.get(a, ())), writers=sorted(dat_w.get(a, ())),
                                     **t.describe_data(a))) + "\n")
    return groups


def summary(t, groups, out):
    by = Counter(f["origin"] for f in t.funcs.values())
    ins = Counter()
    for f in t.funcs.values(): ins[f["origin"]] += len(f["insns"])
    lines = [f"# Shelf summary: {t.path.name}", "",
             f"- functions: {len(t.funcs)} (sources: {dict(Counter(f['source'] for f in t.funcs.values()))})",
             f"- origin: {dict(by)}", f"- instructions by origin: {dict(ins)}",
             f"- strings: {len(t.strings)}; imports: {sum(len(v) for v in t.imports.values())} from {len(t.imports)} DLLs",
             f"- bottom-up groups: {len(groups)} (largest cycle: {max((len(g) for g in groups), default=0)})",
             f"- coff symbols: {len(t.symbols)}"]
    (out / "SUMMARY.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?"); ap.add_argument("--out"); ap.add_argument("--all-disasm", action="store_true")
    ap.add_argument("--baseline", nargs="*", default=[], help="extra reference programs for this run only")
    ap.add_argument("--learn", nargs="+", metavar="REF.exe",
                    help="learn reference programs (same toolchain) into refsets/ and exit")
    a = ap.parse_args()
    if a.learn:
        learn(a.learn); return
    if not a.target: ap.error("give a target exe, or --learn REF.exe ...")
    t = Target(a.target); t.discover()
    fp = t.fingerprint()
    refs = {}
    rp = refset_path(fp)
    stale = rp.exists() and json.loads(rp.read_text()).get("analysis_version") != ANALYSIS_VERSION
    if stale:
        print(f"toolchain: {fp}\nreference set: {rp.name} is STALE (made by an older analyser). Not used. "
              "Re-learn it: build_shelves.py --learn ref1.exe ref2.exe")
    elif rp.exists():
        refs.update({h: n for h, n in json.loads(rp.read_text())["functions"].items()})
        print(f"toolchain: {fp}\nreference set: {rp.name} ({len(refs)} hashes)")
    else:
        print(f"toolchain: {fp}\nreference set: none for this toolchain (run --learn with your own small programs)")
    for bp in a.baseline:
        bt = Target(bp); bt.discover()
        for f in bt.funcs.values():
            if f["insns"]: refs.setdefault(f["norm_hash"], Path(bp).name)
    pads = t.landing_pads(); pad_of = defaultdict(set)
    for par, ps in pads.items():
        for x in ps: pad_of[x].add(par)
    classify(t, refs, pad_of, t.table_users())
    out = Path(a.out) if a.out else Path("workspace/shelves") / Path(a.target).stem
    groups = write_shelves(t, out, a.all_disasm)
    summary(t, groups, out)
    print(f"shelves written to {out}")


if __name__ == "__main__":
    main()
