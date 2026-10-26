#!/usr/bin/env python3
"""Map addresses to function names: symaddr.py build/psx/psxx_wallet.elf 0x8001abcd ...  (or the addresses of tools/redux_trap.lua's log on stdin)"""
import bisect, os, re, subprocess, sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
NM = os.path.join(ROOT, "toolchain", "gcc", "bin", "mipsel-none-elf-nm.exe")


def load(elf):
    out = subprocess.run([NM, "-n", elf], check=True, capture_output=True, text=True).stdout
    syms = []
    for l in out.splitlines():
        p = l.split()
        if len(p) == 3 and p[1] in "TtDdBbRr":
            syms.append((int(p[0], 16) & 0xFFFFFFFF, p[2]))
    return syms


def where(syms, a):
    i = bisect.bisect_right([s[0] for s in syms], a) - 1
    return "%08x = %s+0x%x" % (a, syms[i][1], a - syms[i][0]) if i >= 0 else "%08x" % a


if __name__ == "__main__":
    syms = load(sys.argv[1])
    for a in sys.argv[2:]:
        print(where(syms, int(a, 16)))
