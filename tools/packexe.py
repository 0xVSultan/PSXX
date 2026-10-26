"""Pack a PS-X EXE into a self-extracting one (LZMA + a small stub), so it takes less room on a memory card and loads
faster. Usage: packexe.py in.exe out.exe [--ext-dec]

Layout of the packed EXE in RAM:   [ compressed LZMA stream ][ stub ]   at BLOB_ADDR, high in the 2 MB of RAM
 - the stub unpacks the stream out of place to the original load address and jumps to the original entry point;
 - the decoder's probability array lives in free RAM at PROBS_ADDR (about 10 KB), the stack stays at the top;
 - everything else in the header (gp, initial sp, region string) is copied from the original.

The stream is verified with the very decoder source the stub is built from (compiled for the host).

With --ext-dec (a release whose main card was built with PSXX_EXT_DEC, hal/psx/CMakeLists.txt) the stub carries the decoder of the program (stub/lzdec.c, with the properties byte and the
preset dictionary) in place of its own: it copies it to its pocket (MM_DEC_LO, memmap.h), unpacks the main card with it, and leaves it there for the loader (core/pkg/ovl.c).
"""
import os, re, struct, subprocess, sys, tempfile, lzma

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
BIN = os.path.join(ROOT, "toolchain", "gcc", "bin")
CC, LD, OBJCOPY, NM = [os.path.join(BIN, "mipsel-none-elf-" + t + ".exe") for t in ("gcc", "ld", "objcopy", "nm")]
CFLAGS = ["-Os", "-ffreestanding", "-fno-builtin", "-nostdlib", "-msoft-float", "-march=r3000", "-mtune=r3000", "-mabi=32",
          "-mno-mt", "-mno-llsc", "-G0", "-fno-pic", "-mno-abicalls", "-mno-gpopt", "-I", os.path.join(HERE, "stub")]
LC, LP, PB = (int(x) for x in os.environ.get("PSXX_LZMA", "1,2,2").split(","))     # lc,lp,pb; the stub is built with the same (tools/size_matrix.py sweeps them: 1,2,2 is the best for the signer)
BLOB_ADDR = 0x80180000                  # the program sits at 0x80110000; the BIOS shell (0x80030000..0x800A6000 and its heap from 0x80100000) is left alone
PROBS_ADDR = 0x801B0000


def memmap():
    """the fixed places of hal/psx/memmap.h (the decoder's pocket)"""
    d = {}
    for line in open(os.path.join(ROOT, "hal", "psx", "memmap.h"), encoding="utf-8"):
        m = re.match(r"#define (MM_[A-Z0-9_]+) +(0x[0-9A-Fa-f]+)u", line)
        if m:
            d[m.group(1)] = int(m.group(2), 16)
    return d


def build_dec(work):
    """The decoder of the program (stub/lzdec.c) linked at its pocket (MM_DEC_LO): the bytes the stub carries and copies there. Entry at the first byte, code only."""
    mm = memmap()
    obj, elf, binf = (os.path.join(work, n) for n in ("dec.o", "dec.elf", "dec.bin"))
    subprocess.run([CC, *CFLAGS, "-fno-jump-tables", "-c", os.path.join(HERE, "stub", "lzdec.c"), "-o", obj], check=True)
    subprocess.run([LD, "-nostdlib", "-Ttext=0x%x" % mm["MM_DEC_LO"], "-e", "lz_decode", obj, "-o", elf], check=True)
    sizes = subprocess.run([os.path.join(BIN, "mipsel-none-elf-size.exe"), elf], check=True, capture_output=True, text=True).stdout.split()
    text, data, bss = (int(x) for x in sizes[6:9])
    assert data == 0 and bss == 0, "the decoder has data or bss: it has to be code only (.text %d, .data %d, .bss %d)" % (text, data, bss)
    syms = subprocess.run([NM, elf], check=True, capture_output=True, text=True).stdout
    entry = next(int(l.split()[0], 16) & 0xFFFFFFFF for l in syms.splitlines() if l.endswith(" lz_decode"))
    assert entry == mm["MM_DEC_LO"], "lz_decode is not the first byte of the decoder"
    subprocess.run([OBJCOPY, "-O", "binary", "-j", ".text", elf, binf], check=True)
    dec = open(binf, "rb").read()
    assert len(dec) <= mm["MM_DEC_TAG"] - mm["MM_DEC_LO"], "the decoder (%d B) does not fit its pocket" % len(dec)
    return binf, len(dec)


def build_stub(addr, src, dst, size, entry, work, ext_dec=None):
    obj, elf, binf = (os.path.join(work, n) for n in ("stub.o", "stub.elf", "stub.bin"))
    ext = []
    if ext_dec:                                     # the stub carries the decoder of the program and copies it to its pocket (hal/psx/memmap.h)
        mm = memmap()
        ext = ["-DSTUB_EXT_DEC", '-DSTUB_DEC_BIN="%s"' % ext_dec.replace("\\", "/"), "-DSTUB_DEC_AT=0x%xu" % mm["MM_DEC_LO"], "-DSTUB_DEC_TAG=0x%xu" % mm["MM_DEC_TAG"],
               "-DSTUB_DEC_MAGIC=0x%xu" % mm["MM_DEC_MAGIC"], "-DSTUB_PROPS=%d" % ((PB * 5 + LP) * 9 + LC), "-fno-tree-loop-distribute-patterns"]
    subprocess.run([CC, *CFLAGS, "-DLZMA_LC=%d" % LC, "-DLZMA_LP=%d" % LP, "-DLZMA_PB=%d" % PB, *ext, *(["-DSTUB_PROFILE"] if os.environ.get("PSXX_STUB_PROF") else []), "-c", os.path.join(HERE, "stub", "lzmastub.c"), "-o", obj], check=True)
    subprocess.run([LD, "-nostdlib", "-Ttext=0x%x" % addr, "-e", "stub_main",
                    "--defsym", "STUB_SRC=0x%x" % src, "--defsym", "STUB_SIZE=0x%x" % size,
                    "--defsym", "STUB_DST=0x%x" % dst, "--defsym", "STUB_ENTRY=0x%x" % entry,
                    "--defsym", "STUB_PROBS=0x%x" % PROBS_ADDR, obj, "-o", elf], check=True)
    subprocess.run([OBJCOPY, "-O", "binary", "-j", ".text", elf, binf], check=True)   # only .text: other sections sit at address 0
    syms = subprocess.run([NM, elf], check=True, capture_output=True, text=True).stdout
    entry_addr = next(int(l.split()[0], 16) & 0xFFFFFFFF for l in syms.splitlines() if l.endswith(" stub_main"))
    return open(binf, "rb").read(), entry_addr


def verify_host(comp, img, work, ext_dec=False):
    """Decode the stream with stub/lzma_unpack.h compiled for the host and compare with the image (ext_dec: the variant with the properties byte, which is the decoder that the stub carries)."""
    exe = os.path.join(work, "lzma_test.exe")
    subprocess.run(["gcc", "-O1", "-DLZMA_LC=%d" % LC, "-DLZMA_LP=%d" % LP, "-DLZMA_PB=%d" % PB, *(["-DLZMA_DICT"] if ext_dec else []), "-I", os.path.join(HERE, "stub"),
                    os.path.join(HERE, "stub", "lzma_test.c"), "-o", exe], check=True)
    cf, imf, df = (os.path.join(work, n) for n in ("c.bin", "img.bin", "dict.bin"))
    open(cf, "wb").write(comp)
    open(imf, "wb").write(img)
    open(df, "wb").write(b"")
    r = subprocess.run([exe, cf, imf, df, str((PB * 5 + LP) * 9 + LC)] if ext_dec else [exe, cf, imf])
    assert r.returncode == 0, "LZMA decoder verification failed (%d)" % r.returncode


def encode_best(img):
    """The smallest raw LZMA stream over the encoder's match finders, nice lengths and depths (the decoder does not care how the stream was found: the output buffer is its dictionary). The
    first of the smallest in a fixed order, so the build stays repeatable; PSXX_LZMA_SEARCH=0 keeps the single setting of the earlier releases (BT4, 273, 1000). On the main card of the
    trophy release this is 267 bytes less than that setting (BT2, 128: 119,805 against 120,072)."""
    grid = [(lzma.MF_BT4, 273, 1000)]
    if os.environ.get("PSXX_LZMA_SEARCH", "1") != "0":
        grid += [(mf, nice, depth) for mf in (lzma.MF_BT2, lzma.MF_BT3, lzma.MF_BT4, lzma.MF_HC3, lzma.MF_HC4) for nice in (273, 200, 128, 96, 64, 48, 32) for depth in (1000, 100)]
    best = None
    for mf, nice, depth in grid:
        c = lzma.compress(img, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "preset": 9 | lzma.PRESET_EXTREME, "dict_size": 1 << 18, "lc": LC, "lp": LP, "pb": PB,
                                                                "nice_len": nice, "mf": mf, "depth": depth}])
        if best is None or len(c) < len(best):
            best = c
    return best


def pack(src_exe, dst_exe, ext_dec=False):
    b = open(src_exe, "rb").read()
    assert b[:8] == b"PS-X EXE", "not a PS-X EXE"
    pc, gp, taddr, tsize = struct.unpack_from("<4I", b, 0x10)
    img = b[0x800:0x800 + tsize]
    assert len(img) == tsize

    comp = encode_best(img)
    C = len(comp)
    assert C < tsize, "not compressible"
    blob_addr = BLOB_ADDR
    if taddr < 0x80100000:                          # bisect builds linked at the SDK default: old layout
        blob_addr = 0x80120000
        assert taddr + tsize <= blob_addr, "image runs into the packed block"
    else:
        assert taddr >= 0x80110000 and taddr + tsize + 0x10000 <= BLOB_ADDR, "image (and its BSS) runs into the packed block"
    blob_end = blob_addr + C
    stub_addr = (blob_end + 3) & ~3

    with tempfile.TemporaryDirectory() as work:
        dec_bin, dec_len = build_dec(work) if ext_dec else (None, 0)
        stub, stub_entry = build_stub(stub_addr, blob_addr, taddr, tsize, pc, work, dec_bin)
        verify_host(comp, img, work, ext_dec)
    assert stub_addr <= stub_entry < stub_addr + len(stub), "stub entry outside the stub"
    assert stub_addr + len(stub) <= PROBS_ADDR, "stub runs into the decoder's scratch memory"

    payload = comp + bytes(stub_addr - blob_end) + stub
    payload += bytes((-len(payload)) % 128)         # whole memory card frames
    new_size = len(payload)

    hdr = bytearray(b[:0x800])
    struct.pack_into("<I", hdr, 0x10, stub_entry)
    struct.pack_into("<I", hdr, 0x18, blob_addr)
    struct.pack_into("<I", hdr, 0x1C, new_size)
    open(dst_exe, "wb").write(bytes(hdr) + bytes(payload))
    print("%s: image %d B -> LZMA %d B + stub %d B%s = payload %d B (%.1f%%), load 0x%08x, entry 0x%08x"
          % (os.path.basename(src_exe), tsize, C, len(stub), " (with the %d B decoder of the program)" % dec_len if ext_dec else "", new_size, 100.0 * new_size / tsize, blob_addr, stub_entry))


if __name__ == "__main__":
    pack(sys.argv[1], sys.argv[2], "--ext-dec" in sys.argv[3:])
