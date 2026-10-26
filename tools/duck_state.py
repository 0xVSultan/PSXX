#!/usr/bin/env python3
"""Reads the main RAM out of a DuckStation save state (.sav) and shows or compares what is in it.

    py -3.13 tools/duck_state.py map  state.sav                 the 4 KB pages of RAM that are not zero, as address ranges
    py -3.13 tools/duck_state.py diff before.sav after.sav      what changed between two states, as address ranges (4 KB pages, with the number of changed bytes)
    py -3.13 tools/duck_state.py dump state.sav out.bin         the 2 MB of RAM as a file (address 0x80000000 = offset 0)

A state is a small header, the path of the disc, then a zstd stream (zstd.exe of MSYS2 decodes it). The RAM is found by the exception vector of the kernel at 0x80000080 (lui k0, 0 / addiu
k0, k0, x / jr k0), the same in every BIOS. Checked on a BIOS 4.0 (SCPH7000) state of DuckStation 0.1-11752 (state version 85). VRAM and SPU RAM are in the same stream; not decoded here.
"""
import os
import subprocess
import sys
import tempfile

ZSTD = r"C:\msys64\ucrt64\bin\zstd.exe"
MAGIC = b"\x28\xb5\x2f\xfd"
RAM = 0x200000
PAGE = 0x1000


def load(path):
    b = open(path, "rb").read()
    i = b.find(MAGIC, 0, 4096)
    if i < 0:
        sys.exit("%s: no zstd stream (not a DuckStation state, or an uncompressed one)" % path)
    with tempfile.TemporaryDirectory() as d:
        z, r = os.path.join(d, "s.zst"), os.path.join(d, "s.raw")
        open(z, "wb").write(b[i:])
        p = subprocess.run([ZSTD, "-d", "-f", "-q", z, "-o", r], capture_output=True, text=True)
        if p.returncode:
            sys.exit("zstd failed: " + p.stderr)
        raw = open(r, "rb").read()
    pat = bytes.fromhex("00001a3c")                      # lui $k0, 0 (3c1a0000, little endian)
    pos = -1
    k = 0
    while True:
        k = raw.find(pat, k)
        if k < 0:
            break
        # lui k0,0 ; addiu k0,k0,imm ; jr k0 : the three words of the vector at RAM + 0x80
        # and the B0 table of the kernel at RAM + 0x300 points into the ROM (0xbfc.....): the vector alone is found at another place too
        if raw[k + 6:k + 8] == b"\x5a\x27" and raw[k + 8:k + 12] == bytes.fromhex("08004003") and raw[k + 0x300 - 0x80 + 3:k + 0x300 - 0x80 + 4] == b"\xbf":
            pos = k - 0x80
            break
        k += 4
    if pos < 0 or pos + RAM > len(raw):
        sys.exit("%s: the RAM was not found" % path)
    return raw[pos:pos + RAM]


def ranges(pages):
    out, s = [], None
    for i, v in enumerate(pages):
        if v and s is None:
            s = i
        if not v and s is not None:
            out.append((s, i - 1))
            s = None
    if s is not None:
        out.append((s, len(pages) - 1))
    return out


def show(rs, extra=None):
    for a, b in rs:
        print("  0x%08x..0x%08x  %4d KB%s" % (0x80000000 + a * PAGE, 0x80000000 + (b + 1) * PAGE - 1, (b - a + 1) * 4, extra(a, b) if extra else ""))


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "map":
        ram = load(sys.argv[2])
        show(ranges([any(ram[i:i + PAGE]) for i in range(0, RAM, PAGE)]))
    elif cmd == "diff":
        a, b = load(sys.argv[2]), load(sys.argv[3])
        n = [sum(1 for x, y in zip(a[i:i + PAGE], b[i:i + PAGE]) if x != y) for i in range(0, RAM, PAGE)]
        show(ranges([v > 0 for v in n]), lambda s, e: "  %d bytes changed" % sum(n[s:e + 1]))
    elif cmd == "dump":
        open(sys.argv[3], "wb").write(load(sys.argv[2]))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
