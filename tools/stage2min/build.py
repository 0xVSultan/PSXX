"""Builds the minimal second stage (stage2min.c, start.s, reboot.s) for the boot card: stage2min.bin, the code from 0x8000D000 and the 28 bytes of `cfg` last (the builder patches them).

  py -3.13 tools/stage2min/build.py [--slot2] [--out dir]

The binary is used by toolchain/FreePSXBoot/builder/builder.exe -minload (tools/memprobe-card.ps1 -MinLoad, tools/release.py cards --minload)."""
import argparse, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
BIN = os.path.join(ROOT, "toolchain", "gcc", "bin")
T = lambda n: os.path.join(BIN, "mipsel-none-elf-" + n + ".exe")
ARCH = ["-march=mips1", "-mabi=32", "-EL", "-fno-pic", "-mno-abicalls", "-mfp32"]


def load_hazards(elf):
    """The R3000 does not interlock a load: the instruction right after `lw rX` sees the old rX. Looks for instructions that read the register a load has just filled (the unicorn model of
    tools/test_stage2min_emu.py has no load delay slot, so it does not see this; DuckStation does)."""
    import re
    text = subprocess.run([T("objdump"), "-d", elf], check=True, capture_output=True, text=True).stdout
    ins = []
    for line in text.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+(\S+)\s*(.*)", line)
        if m: ins.append((m.group(1), m.group(2), m.group(3).split("<")[0].strip()))
    bad = []
    for (a1, op1, args1), (a2, op2, args2) in zip(ins, ins[1:]):
        if op1 in ("lw", "lh", "lhu", "lb", "lbu", "lwl", "lwr", "mfc0", "mfc2", "cfc2"):
            rt = args1.split(",")[0]
            if rt == "zero": continue
            reads = args2.replace("(", ",").replace(")", "").split(",")
            if op2 in ("sw", "sh", "sb", "swl", "swr", "mtc0"):
                srcs = reads                       # a store reads rt and the base
            elif op2.startswith("l") or op2 in ("addiu", "addi", "andi", "ori", "xori", "slti", "sltiu", "lui", "li", "move", "mfc0"):
                srcs = reads[1:]
            else:
                srcs = reads                       # branches, jumps, the three operand ops: every operand is read except a destination that is no source (close enough)
                if op2 not in ("beq", "bne", "bgtz", "blez", "jr", "jalr", "bltz", "bgez"):
                    srcs = reads[1:]
            if rt in [x.strip() for x in srcs]:
                bad.append("%s: %s %s ; %s: %s %s" % (a1, op1, args1, a2, op2, args2))
    return bad


def build(out, slot2=False, dbg=False, nops=False, origp=False, layout="reloc", extra_defs=()):
    os.makedirs(out, exist_ok=True)
    objs = []
    srcs = ["stage2min.c", "start.s", "reboot.s"]
    if layout == "orig":                                   # diagnostic: FreePSXBoot's own reboothook.s (tools/stage2min/orig) in place of reboot.s
        srcs = ["stage2min.c", "start.s", os.path.join("orig", "reboothook.s")]
    for src in srcs:
        o = os.path.join(out, os.path.splitext(os.path.basename(src))[0] + ".o")
        extra = (["-DSLOT2"] if slot2 else []) + (["-DDBG"] if dbg else []) if src.endswith(".c") else []
        flags = ["-Os", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-mno-gpopt", "-fomit-frame-pointer", "-fno-strict-aliasing"] if src.endswith(".c") else []
        if src.endswith(".s"):
            extra = (["-Wa,--defsym,DBG=1"] if dbg else []) + (["-Wa,--defsym,NOPS=1"] if nops else []) + (["-Wa,--defsym,ORIGP=1"] if origp else []) + ["-Wa,--defsym,%s=1" % d for d in extra_defs]
        if layout == "inplace" and src.endswith(".s"):
            extra = extra + ["-Wa,--defsym,INPLACE=1"]
        subprocess.run([T("gcc"), *ARCH, *flags, *extra, "-c", os.path.join(HERE, src), "-o", o], check=True)
        objs.append(o)
    name = "stage2min" + ("" if layout == "reloc" else "-" + layout) + ("-dbg" if dbg else "") + ("-nops" if nops else "") + ("-origp" if origp else "") + "".join("-" + d.lower() for d in extra_defs)
    elf, binf = os.path.join(out, name + ".elf"), os.path.join(out, name + ".bin")
    subprocess.run([T("ld"), "-nostdlib", "-T", os.path.join(HERE, "stage2min.ld" if layout == "reloc" else "stage2min-inplace.ld"), *objs, "-o", elf], check=True)
    subprocess.run([T("objcopy"), "-O", "binary", elf, binf], check=True)
    hazards = load_hazards(elf)
    if hazards:
        sys.exit("load delay slot hazards (the next instruction reads the register that a load fills):\n  " + "\n  ".join(hazards))
    n = os.path.getsize(binf)
    print(name + ".bin: %d bytes = %d frames (the original: 1760 bytes = 14 frames and a header frame)" % (n, (n + 127) // 128))
    return binf


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--slot2", action="store_true")
    ap.add_argument("--origp", action="store_true", help="save pc, gp and sp at 0x8000dff0 as the original reboothook.s does")
    ap.add_argument("--layout", choices=("reloc", "orig", "inplace"), default="reloc", help="diagnostic layouts: orig = the reboot hook of FreePSXBoot at its own address, inplace = reboot.s there without copying")
    ap.add_argument("--def", dest="defs", action="append", default=[], help="a diagnostic define for reboot.s (UNIROM: the tags of FreePSXBoot, PAD8: 8 nops)")
    ap.add_argument("--nops", action="store_true", help="a nop after every write of the debug registers, as in the original reboothook.s")
    ap.add_argument("--dbg", action="store_true", help="a diagnostic build that fills the screen with a colour at each step (see stage2min.c)")
    ap.add_argument("--out", default=os.path.join(ROOT, "build", "stage2min"))
    a = ap.parse_args()
    build(a.out, a.slot2, a.dbg, a.nops, a.origp, a.layout, a.defs)
