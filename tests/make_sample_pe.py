#!/usr/bin/env python3
"""Create a tiny synthetic Windows PE (not runnable) to test scripts/binary_inventory.py.
Usage: python3 tests/make_sample_pe.py <output.exe>"""
import struct, sys

def build():
    img = bytearray(0x1400)
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, 0x80)
    img[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", img, 0x84, 0x8664, 2, 1700000000, 0, 0, 240, 0x22)
    o = 0x98
    struct.pack_into("<H", img, o, 0x20B)
    struct.pack_into("<H", img, o + 68, 2)           # GUI subsystem
    struct.pack_into("<I", img, o + 108, 16)         # number of data dirs
    dd = o + 112
    struct.pack_into("<II", img, dd + 0 * 8, 0x2100, 0x60)   # exports
    struct.pack_into("<II", img, dd + 1 * 8, 0x2000, 60)     # imports
    st = o + 240
    struct.pack_into("<8sIIIIIIHHI", img, st, b".text", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<8sIIIIIIHHI", img, st + 40, b".rdata", 0x1000, 0x2000, 0x1000, 0x400, 0, 0, 0, 0, 0x40000040)
    img[0x200:0x210] = b"\x90" * 16
    R = 0x400  # file offset of .rdata (rva 0x2000)
    def put(off, data): img[R + off:R + off + len(data)] = data
    # import descriptors: user32, ws2_32, terminator
    struct.pack_into("<IIIII", img, R + 0x00, 0x2040, 0, 0, 0x20E0, 0x2040)
    struct.pack_into("<IIIII", img, R + 0x14, 0x2060, 0, 0, 0x20F0, 0x2060)
    struct.pack_into("<QQQ", img, R + 0x40, 0x2080, 0x20A0, 0)
    struct.pack_into("<QQ", img, R + 0x60, 0x20C0, 0)
    put(0x80, b"\0\0CreateWindowExW\0"); put(0xA0, b"\0\0RegisterHotKey\0"); put(0xC0, b"\0\0WSAStartup\0")
    put(0xE0, b"user32.dll\0"); put(0xF0, b"ws2_32.dll\0")
    # exports
    struct.pack_into("<IIHHIIIIIII", img, R + 0x100, 0, 0, 0, 0, 0x2160, 1, 2, 2, 0x2138, 0x2130, 0x2138)
    struct.pack_into("<II", img, R + 0x130, 0x2140, 0x2150)
    put(0x140, b"SampleExportA\0"); put(0x150, b"SampleExportB\0"); put(0x160, b"sample.dll\0")
    # strings
    put(0x200, b"Save the current document now\0")
    put(0x220, b"Failed to open the settings file\0")
    put(0x250, b"--enable-tabs-sidebar\0")
    put(0x270, b"https://updates.example.com/check?token=abc123\0")
    put(0x2B0, b"browser/ui/tabs/tab_strip.cc\0")
    put(0x2E0, b"AKIAIOSFODNN7EXAMPLE1234567890abcdef\0")
    put(0x310, b".?AVTabStrip@ui@browser@@\0")
    put(0x340, "Open a new tab page here".encode("utf-16le") + b"\0\0")
    put(0x380, "ProductName".encode("utf-16le") + b"\0\0" + "Sample Browser".encode("utf-16le") + b"\0\0")
    return bytes(img)

if __name__ == "__main__":
    open(sys.argv[1] if len(sys.argv) > 1 else "sample.exe", "wb").write(build())
