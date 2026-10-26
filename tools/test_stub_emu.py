"""Runs the unpacking stub of a release (tools/packexe.py --ext-dec) in a MIPS emulator (unicorn): the packed EXE is loaded as the BIOS loads it, the stub runs up to the jump to the
program, and the unpacked image is compared with the one in the EXE before packing; then the decoder that the stub left in its pocket is called the way the loader does (properties byte,
preset dictionary) on a stream made by liblzma. Needs `pip install unicorn`.

  py -3.13 tools/test_stub_emu.py <release dir>"""
import os, struct, sys, lzma, hashlib
from unicorn import Uc, UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE, UcError
from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_SP, UC_MIPS_REG_RA, UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3, UC_MIPS_REG_V0, UC_MIPS_REG_GP

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import packexe, lzma_dict

K0 = 0x80000000
RAM = 2 * 1024 * 1024


def exe_parts(b):
    pc, gp, taddr, tsize = struct.unpack_from("<4I", b, 0x10)
    return pc, taddr, b[0x800:0x800 + tsize]


def fresh():
    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(0, RAM)
    uc.mem_write(0xa0, struct.pack("<II", 0x03e00008, 0))                  # the BIOS A0 vector: jr ra (FlushCache does nothing here)
    return uc


def main():
    d = sys.argv[1]
    packed = open(os.path.join(d, "base_packed.exe"), "rb").read()
    plain = open(os.path.join(d, "base.exe"), "rb").read()
    spc, saddr, spay = struct.unpack_from("<IIII", packed, 0x10)[0], struct.unpack_from("<I", packed, 0x18)[0], packed[0x800:]
    pc0, taddr, image = exe_parts(plain)
    mm = packexe.memmap()
    uc = fresh()
    uc.mem_write(saddr & 0x1fffffff, spay)
    uc.reg_write(UC_MIPS_REG_PC, spc)
    uc.reg_write(UC_MIPS_REG_SP, 0x801fff00)
    steps = {"n": 0}
    def hook(u, addr, size, ud):
        steps["n"] += 1
        if steps["n"] > 400_000_000:
            raise RuntimeError("too many instructions")
    uc.hook_add(UC_HOOK_CODE, hook)
    try:
        uc.emu_start(spc, pc0)                                              # runs until the stub jumps to the entry of the program
    except UcError as e:
        sys.exit("emulation stopped: %s at pc=%08x" % (e, uc.reg_read(UC_MIPS_REG_PC)))
    got = bytes(uc.mem_read(taddr & 0x1fffffff, len(image)))
    ok = got == image
    print("stub: %d instructions, unpacked image %s" % (steps["n"], "identical" if ok else "DIFFERENT"))
    tag = struct.unpack("<I", bytes(uc.mem_read(mm["MM_DEC_TAG"] & 0x1fffffff, 4)))[0]
    print("tag at MM_DEC_TAG: %08x (%s)" % (tag, "ok" if tag == mm["MM_DEC_MAGIC"] else "WRONG"))
    if not ok or tag != mm["MM_DEC_MAGIC"]:
        sys.exit(1)
    # the loader's call: a stream against the image as preset dictionary, properties byte of an overlay (lc 3, lp 0, pb 2 -> (2 * 5 + 0) * 9 + 3 = 93)
    dictionary = image[:len(image) // 2 // 16 * 16]
    data = (image[1000:9000] + os.urandom(300) + image[20000:30000])
    for lc, lp, pb in ((3, 0, 2), (0, 2, 2), (2, 0, 0)):
        comp = lzma_dict.compress(data, dictionary, lc, lp, pb)
        src, probs = 0x801c0000, 0x801b0000
        # keep the dictionary where the decoder expects it: just before the output
        dl = len(dictionary)
        dst = 0x80190000 + dl
        uc.mem_write((dst - dl) & 0x1fffffff, dictionary)
        uc.mem_write(src & 0x1fffffff, comp)
        uc.reg_write(UC_MIPS_REG_A0, src); uc.reg_write(UC_MIPS_REG_A1, dst); uc.reg_write(UC_MIPS_REG_A2, len(data)); uc.reg_write(UC_MIPS_REG_A3, probs)
        sp = 0x801fe000
        props = (pb * 5 + lp) * 9 + lc
        uc.mem_write((sp + 16) & 0x1fffffff, struct.pack("<III", props, dst - dl, dl))     # o32: arguments 5..7 on the stack
        uc.reg_write(UC_MIPS_REG_SP, sp)
        uc.reg_write(UC_MIPS_REG_RA, 0x80000100)
        uc.mem_write(0x100, struct.pack("<I", 0x0000000d))                  # break: the stop mark
        try:
            uc.emu_start(mm["MM_DEC_LO"], 0x80000100)
        except UcError as e:
            sys.exit("decoder call: %s" % e)
        r = uc.reg_read(UC_MIPS_REG_V0)
        out = bytes(uc.mem_read(dst & 0x1fffffff, len(data)))
        print("decoder call lc %d lp %d pb %d with a %d B dictionary: result %d, output %s" % (lc, lp, pb, dl, r, "identical" if out == data else "DIFFERENT"))
        if r != 0 or out != data:
            sys.exit(1)
    print("stub emulation: ok")


main()
