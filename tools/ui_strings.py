#!/usr/bin/env python3
"""Helpers of the tools that make the text tables (tools/ui_ids.py, tools/data_pack.py, tools/ui_lint.py): the hash of a text, the C escapes of the lists, the conversions and the
button icons of a text (what a translation has to keep), and the reading of the texts out of a compiled object (the first seed of the lists).

The dictionary that this file used to make was replaced by the tables by identifier (17.45); see tools/ui_ids.py."""
import re, struct

def fnv(b):
    h = 2166136261
    for c in b:
        h = ((h ^ c) * 16777619) & 0xFFFFFFFF
    return h


def esc(b):
    out = []
    for c in b:
        if c == 10: out.append("\\n")
        elif c == 9: out.append("\\t")
        elif c == 92: out.append("\\\\")
        elif c < 32 or c == 127: out.append("\\x%02x" % c)
        else: out.append(chr(c))
    return "".join(out)


def unesc(s):
    out, i = bytearray(), 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "n": out.append(10); i += 2; continue
            if n == "t": out.append(9); i += 2; continue
            if n == "\\": out.append(92); i += 2; continue
            if n == "x" and i + 3 < len(s):
                out.append(int(s[i + 2:i + 4], 16)); i += 4; continue
            raise ValueError("bad escape in %r" % s)
        out += c.encode("utf-8"); i += 1
    return bytes(out)


CONV = re.compile(rb"%[-+ #0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|ll|l|z|j|t)?[diouxXcspfeEgG%]")


def conversions(b):
    return [m.group(0) for m in CONV.finditer(b) if m.group(0) != b"%%"]


def icons(b):
    return sorted(c for c in b if 1 <= c <= 18)


# ---------------------------------------------------------------- the strings of the compiled program
def elf_strings(path):
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF":
        return []
    shoff, = struct.unpack_from("<I", d, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x2E)
    secs = []
    for i in range(shnum):
        name, typ, flags, addr, off, size = struct.unpack_from("<IIIIII", d, shoff + i * shentsize)
        secs.append((name, typ, off, size))
    stroff = secs[shstrndx][2]
    out = []
    for name, typ, off, size in secs:
        n = d[stroff + name:d.index(b"\0", stroff + name)].decode()
        if n.startswith(".rodata") and ".str" in n and typ == 1:      # (.rodata.str1.1, and with -fdata-sections .rodata.<function>.str1.4)
            out += [s for s in d[off:off + size].split(b"\0") if s]
    return out


def looks_like_text(b):
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if re.search(r"[A-Za-z]{3}", s) is None:
        return False
    if re.match(r"^\[[a-z0-9 ]+\]", s):                    # the TTY diagnostics
        return False
    if re.match(r"^(BESCES|PSXX|%s|m/|0x)", s) or re.fullmatch(r"[A-Za-z0-9_./:-]+", s) and " " not in s and not s[0].isupper():
        return False                                        # file names, paths, identifiers
    if s == "(null)":
        return False                                        # printf's stand-in for a null string (hal/psx/vsnprintf.c)
    if " " not in s and not s.endswith("..."):
        # crypto constants and tags of the signer: hash personalisations (ZcashOutputsHash, TapSighash), domain separators (CLSAG_agg_0, HDKD-hard, BIP0340/aux),
        # Base58 program ids, key rows of the keyboard, the 4 letter magics of the files and the pieces of JSON / descriptors, not texts of the screens
        if re.search(r"[a-z][A-Z]|[_/\-\"]|\.\d", s) or re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,}", s):
            return False
        if re.fullmatch(r"QWERTYUIOP|ASDFGHJKL|ZXCVBNM|PSX[A-Z]|XMR[QS]|ZTXR|ZORS|KSIG", s) or s.endswith("("):
            return False
    return True
