#!/usr/bin/env python3
"""Pad a PS-X EXE with zeros up to a given text size (test tool for payload size limits on FreePSXBoot cards)."""
import struct, sys
src, dst, size = sys.argv[1], sys.argv[2], int(sys.argv[3])
b = bytearray(open(src, "rb").read())
t_size = struct.unpack_from("<I", b, 0x1C)[0]
assert size % 2048 == 0 and size >= t_size
b += bytes(size - t_size)
struct.pack_into("<I", b, 0x1C, size)
open(dst, "wb").write(b)
print(dst, "text size", t_size, "->", size)
