#!/usr/bin/env python3
"""Check which analysis engines are available. Read-only: never installs or changes anything.

Groups: core, native (Ghidra and friends), MCP bridges, mobile/.NET/JVM, dynamic, triage, web.
Prints, for every missing engine, the install hint, so you can pick what your target needs."""
import os, shutil, subprocess, sys

# (command(s), purpose, install hint). A tuple of commands means "any of these".
GROUPS = [
    ("core", [
        (("python3", "python"), "run OpenAll scripts", "https://www.python.org/downloads/"),
        (("git",), "version control", "https://git-scm.com/"),
    ]),
    ("native engines (decompile / disassemble)", [
        (("analyzeHeadless", "analyzeHeadless.bat"), "Ghidra headless (decompiler, free, needs Java 21+)", "https://ghidra-sre.org/"),
        (("rizin", "rz-bin"), "Rizin (radare2 fork): fast static inspection", "https://rizin.re/"),
        (("r2", "radare2"), "radare2: scriptable disassembler", "https://rada.re/"),
        (("objdump",), "binutils objdump: plain disassembly", "apt install binutils"),
    ]),
    ("MCP bridges (let Claude drive the engines)", [
        (("mcp-reva",), "ReVa: Ghidra headless MCP (Ghidra 12+)", "uv tool install reverse-engineering-assistant"),
        (("rea-mcp", "rea"), "REA: multi-engine MCP (Ghidra/IDA/jadx/Rizin/Frida...)", "pip install rea-mcp  (or the original morluto/rea)"),
        (("uv", "uvx"), "uv: installs/runs the Python MCP servers", "https://docs.astral.sh/uv/"),
    ]),
    ("Java / Android / .NET", [
        (("java",), "Java runtime (Ghidra, jadx need it)", "install JDK 21+"),
        (("jadx",), "decompile APK/JAR to Java", "https://github.com/skylot/jadx"),
        (("apktool",), "decode APK manifest/resources/smali", "https://apktool.org/"),
        (("adb",), "Android emulator/device bridge", "Android platform-tools"),
        (("dotnet",), ".NET SDK", "https://dotnet.microsoft.com/"),
        (("ilspycmd",), "decompile .NET assemblies to C#", "dotnet tool install -g ilspycmd"),
    ]),
    ("dynamic observation (sandbox/VM only!)", [
        (("frida", "frida-ps"), "Frida: watch calls of a running program", "pip install frida-tools"),
        (("strace",), "strace: system calls (Linux)", "apt install strace"),
    ]),
    ("triage helpers", [
        (("capa",), "capa: what capabilities a binary has", "https://github.com/mandiant/capa"),
        (("yara",), "YARA: pattern rules", "https://virustotal.github.io/yara/"),
        (("diec", "die"), "Detect It Easy: packers/compilers", "https://github.com/horsicq/Detect-It-Easy"),
        (("strings",), "strings", "apt install binutils"),
        (("file",), "file type", "apt install file"),
    ]),
    ("web / Electron", [
        (("node",), "Node.js", "https://nodejs.org/"),
        (("npx",), "run asar / playwright without install", "comes with Node.js"),
    ]),
]

ENV_VARS = [
    ("GHIDRA_INSTALL_DIR", "folder of an unpacked Ghidra (needed by ReVa and REA)"),
    ("JAVA_HOME", "JDK folder (needed by Ghidra-based tools)"),
]

def which(cmds):
    for c in cmds:
        p = shutil.which(c)
        if p:
            return c, p
    return None, None

def ghidra_from_env():
    d = os.environ.get("GHIDRA_INSTALL_DIR")
    if not d:
        return False
    return any(os.path.exists(os.path.join(d, "support", n)) for n in ("analyzeHeadless", "analyzeHeadless.bat"))

def main():
    print("OpenAll doctor (read-only)\n")
    print(f"Python {sys.version.split()[0]} on {sys.platform}\n")
    missing_core = False
    ready = {}
    for title, items in GROUPS:
        print(f"== {title}")
        for cmds, why, hint in items:
            name, path = which(cmds)
            ok = bool(path)
            if cmds[0] == "analyzeHeadless" and not ok and ghidra_from_env():
                ok, name = True, "GHIDRA_INSTALL_DIR"
            ready[cmds[0]] = ok
            label = "OK     " if ok else ("MISSING" if title == "core" else "absent ")
            print(f"  [{label}] {cmds[0]:16} {why}" + ("" if ok else f"\n             -> {hint}"))
            if not ok and title == "core":
                missing_core = True
        print()
    print("== environment")
    for var, why in ENV_VARS:
        val = os.environ.get(var)
        print(f"  [{'OK     ' if val else 'unset  '}] {var:20} {why}" + (f" = {val}" if val else ""))
    print()
    import importlib.util
    print("== python packages (shelves workflow for Windows x64 programs)")
    pk_ok = True
    for mod in ("capstone", "pefile"):
        ok = importlib.util.find_spec(mod) is not None
        pk_ok = pk_ok and ok
        print(f"  [{'OK     ' if ok else 'absent '}] {mod:16} " + ("" if ok else "-> pip install capstone pefile   (offline: pip install --no-index --find-links vendor capstone pefile)"))
    print()
    mcp_ok = ready.get("mcp-reva") or ready.get("rea-mcp")
    native_ok = ready.get("analyzeHeadless") or ready.get("rizin") or ready.get("r2")
    print("== summary")
    print("  deep native study with Claude driving a decompiler:", "READY" if (mcp_ok and native_ok) else "not yet")
    if not mcp_ok:
        print("     install an MCP bridge, then run: python3 scripts/setup_mcp.py")
    if not native_ok:
        print("     install Ghidra (or Rizin) for real decompilation")
    print("  shelves study of Windows x64 .exe/.dll (no Ghidra needed):", "READY" if pk_ok else "needs: pip install capstone pefile")
    print("  source-code / web / Electron study: READY (no extra tools needed)")
    print("\nOptional tools unlock deeper analysis; install only what your target needs.")
    print("Run unknown executables only in a VM or sandbox.")
    return 1 if missing_core else 0

if __name__ == "__main__":
    sys.exit(main())
