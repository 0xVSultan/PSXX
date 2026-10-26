#!/usr/bin/env python3
"""Pack a PS-X EXE into a self-extracting one (LZ4 + a tiny stub); the older, in-place variant kept for comparisons.
Usage: packexe_lz4.py in.exe out.exe"""
import os, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import lz4

ROOT = os.path.normpath(os.path.join(HERE, ".."))
BIN = os.path.join(ROOT, "toolchain", "gcc", "bin")
CC, LD, OBJCOPY, NM = [os.path.join(BIN, "mipsel-none-elf-" + t + ".exe") for t in ("gcc", "ld", "objcopy", "nm")]
CFLAGS = ["-Os", "-ffreestanding", "-fno-builtin", "-nostdlib", "-msoft-float", "-march=r3000", "-mtune=r3000", "-mabi=32",
          "-mno-mt", "-mno-llsc", "-G0", "-fno-pic", "-mno-abicalls", "-mno-gpopt", "-I", os.path.join(ROOT, "core")]


def build_stub(addr, src, src_end, dst, entry, work):
    obj, elf, binf = (os.path.join(work, n) for n in ("stub.o", "stub.elf", "stub.bin"))
    subprocess.run([CC, *CFLAGS, "-c", os.path.join(HERE, "stub", "lz4stub.c"), "-o", obj], check=True)
    subprocess.run([LD, "-nostdlib", "-Ttext=0x%x" % addr, "-e", "stub_main",
                    "--defsym", "STUB_SRC=0x%x" % src, "--defsym", "STUB_END=0x%x" % src_end,
                    "--defsym", "STUB_DST=0x%x" % dst, "--defsym", "STUB_ENTRY=0x%x" % entry, obj, "-o", elf], check=True)
    subprocess.run([OBJCOPY, "-O", "binary", "-j", ".text", elf, binf], check=True)
    syms = subprocess.run([NM, elf], check=True, capture_output=True, text=True).stdout
    entry_addr = next(int(l.split()[0], 16) & 0xFFFFFFFF for l in syms.splitlines() if l.endswith(" stub_main"))
    return open(binf, "rb").read(), entry_addr


def pack(src_exe, dst_exe):
    b = open(src_exe, "rb").read()
    pc, gp, taddr, tsize = struct.unpack_from("<4I", b, 0x10)
    img = b[0x800:0x800 + tsize]
    comp = lz4.compress(img)
    margin = (lz4.inplace_margin(comp, tsize) + 3) & ~3
    C = len(comp)
    blob_addr = taddr + tsize + margin - C
    blob_end = blob_addr + C
    stub_addr = (blob_end + 3) & ~3
    with tempfile.TemporaryDirectory() as work:
        stub, stub_entry = build_stub(stub_addr, blob_addr, blob_end, taddr, pc, work)
    load_addr = blob_addr & ~3
    payload = bytearray(blob_addr - load_addr) + comp + bytes(stub_addr - blob_end) + stub
    payload += bytes((-len(payload)) % 128)
    new_size = len(payload)
    hdr = bytearray(b[:0x800])
    struct.pack_into("<I", hdr, 0x10, stub_entry)
    struct.pack_into("<I", hdr, 0x18, load_addr)
    struct.pack_into("<I", hdr, 0x1C, new_size)
    open(dst_exe, "wb").write(bytes(hdr) + bytes(payload))
    print("LZ4: payload %d B, load 0x%08x, entry 0x%08x, image %d at 0x%08x" % (new_size, load_addr, stub_entry, tsize, taddr))


if __name__ == "__main__":
    pack(sys.argv[1], sys.argv[2])
