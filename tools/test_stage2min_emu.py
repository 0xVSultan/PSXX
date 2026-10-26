"""Runs the minimal second stage (tools/stage2min) of a boot card in a MIPS emulator (unicorn) against a model of SIO0 and the memory card: the stage2 is read from the card the
way stage 1 does it, runs, reads the program from the card, sets the breakpoint, copies the handler and reboots (the run stops at the reboot entry of the BIOS); then the handler is
run from the debug vector and has to land on the program's entry with its gp and sp. The model is of the protocol (tools/mkcard.py frames, hal/psx/mcard.c), not of the timing.

  py -3.13 tools/test_stage2min_emu.py <boot card .mcd> <packed exe the card was made of> [stage2min.bin]   Needs `pip install unicorn`."""
import os, struct, sys
from unicorn import Uc, UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_LITTLE_ENDIAN, UcError, UC_HOOK_CODE
from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_GP, UC_MIPS_REG_SP

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
FIRST = 65


class Sio:
    def __init__(self, card):
        self.card, self.ctrl, self.i, self.rx, self.ready, self.istat, self.frame = card, 0, 0, 0xFF, False, 0, 0
        self.frames_read = []

    def read(self, uc, off, size, ud):
        if off == 0x40:
            self.ready = False
            return self.rx
        if off == 0x814: return 0x1C000000                                           # GPUSTAT: ready
        if off == 0x44:
            return 0x5 | (2 if self.ready else 0)
        if off == 0x814: return 0x1C000000                                           # GPUSTAT: ready
        if off == 0x4A: return self.ctrl
        if off == 0x70: return self.istat
        return 0

    def write(self, uc, off, size, value, ud):
        if off == 0x4A:
            if (value & 0x2) and not (self.ctrl & 0x2): self.i = 0                    # DTR: the card is selected, a new transaction
            self.ctrl = value & ~0x10
        elif off == 0x70:
            self.istat &= value                                                      # writing 0 to a bit clears it
        elif off == 0x40:
            if not (self.ctrl & 0x1): return
            i, t = self.i, value & 0xFF
            if i == 4: self.frame = t << 8
            if i == 5:
                self.frame |= t
                self.frames_read.append(self.frame)
            f = self.frame
            data = self.card[f * 128:(f + 1) * 128]
            if i < 10:
                self.rx = (0xFF, 0x08, 0x5A, 0x5D, 0x00, 0x00, 0x5C, 0x5D, f >> 8, f & 0xFF)[i]
            elif i < 138: self.rx = data[i - 10]
            elif i == 138:
                c = (f >> 8) ^ (f & 0xFF)
                for b in data: c ^= b
                self.rx = c
            else: self.rx = 0x47
            self.i += 1
            self.ready = True
            if i < 139: self.istat |= 0x80                                           # the acknowledge follows every byte but the last


def main():
    card = open(sys.argv[1], "rb").read()
    exe = open(sys.argv[2], "rb").read()
    s2 = open(sys.argv[3] if len(sys.argv) > 3 else os.path.join(ROOT, "build", "stage2min", "stage2min.bin"), "rb").read()
    pc, gp, taddr, tsize = struct.unpack_from("<4I", exe, 0x10)
    sp = struct.unpack_from("<I", exe, 0x30)[0] + struct.unpack_from("<I", exe, 0x34)[0] or 0x801ffff0
    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(0, 2 * 1024 * 1024)
    uc.mem_map(0x1fc00000, 0x80000)
    sio = Sio(card)
    uc.mmio_map(0x1f801000, 0x1000, sio.read, None, sio.write, None)
    uc.mem_write(0xd000, card[FIRST * 128:FIRST * 128 + len(s2)])                       # what stage 1 does
    if card[FIRST * 128:FIRST * 128 + len(s2)][:-28] != s2[:-28]:
        sys.exit("the stage2 on the card is not the binary given")
    cfg = struct.unpack("<7I", card[FIRST * 128 + len(s2) - 28:FIRST * 128 + len(s2)])
    print("cfg on the card: pc %08x gp %08x sp %08x tload %08x frames %d first %d reboot %08x" % cfg)
    reboot = cfg[6]
    try:
        uc.emu_start(0x8000d000, reboot, count=200_000_000)
    except UcError as e:
        sys.exit("stage2: %s at pc=%08x" % (e, uc.reg_read(UC_MIPS_REG_PC)))
    stop = uc.reg_read(UC_MIPS_REG_PC)
    print("stage2 stopped at %08x (the reboot entry is %08x), %d frames read" % (stop, reboot, len(sio.frames_read)))
    got = bytes(uc.mem_read(taddr & 0x1fffffff, tsize))
    ok = got == exe[0x800:0x800 + tsize]
    print("program in RAM: %s" % ("identical" if ok else "DIFFERENT"))
    order = sio.frames_read == list(range(cfg[5], cfg[5] + cfg[4]))
    print("frames read in order %d .. %d: %s" % (cfg[5], cfg[5] + cfg[4] - 1, "yes" if order else "NO"))
    vec = bytes(uc.mem_read(0x40, 16))
    print("handler stub at the debug vector: %s" % vec.hex())
    ram = bytearray(uc.mem_read(0xd000, 0x700))                                            # unicorn has no MIPS I `rfe`: it is a nop here
    for k in range(0, len(ram), 4):
        if struct.unpack_from("<I", ram, k)[0] == 0x42000010: uc.mem_write(0xd000 + k, bytes(4))
    try:
        uc.emu_start(0x80000040, pc, count=1000)
    except UcError as e:
        sys.exit("handler: %s at pc=%08x" % (e, uc.reg_read(UC_MIPS_REG_PC)))
    ok2 = uc.reg_read(UC_MIPS_REG_PC) == pc and uc.reg_read(UC_MIPS_REG_GP) == gp and uc.reg_read(UC_MIPS_REG_SP) == cfg[2]
    print("handler: pc %08x gp %08x sp %08x -> %s" % (uc.reg_read(UC_MIPS_REG_PC), uc.reg_read(UC_MIPS_REG_GP), uc.reg_read(UC_MIPS_REG_SP), "ok" if ok2 else "WRONG"))
    if not (ok and order and ok2 and stop == reboot):
        sys.exit(1)
    print("stage2min emulation: ok")


main()
