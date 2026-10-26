"""Builds variants of FreePSXBoot's own stage2 (the sources in this directory, MIT licence, see LICENSE.FreePSXBoot) between the original and tools/stage2min, to find which of
the differences keeps the BIOS 4.1 A from reaching the program in DuckStation. Each variant is a stage2 binary in the layout of the builder's -fastload
(a header frame after it, the program after that), made for builder.exe -stage2:

  v0  the original, built with this toolchain
  v1  v0 without the display set-up and the progress bar
  v2  v1 with the card transfer of tools/stage2min (xfer, one loop) in place of mcReadFrame

  py -3.13 tools/stage2min/orig/make_variants.py [--kernel1] [--out dir]"""
import argparse, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
BIN = os.path.join(ROOT, "toolchain", "gcc", "bin")
T = lambda n: os.path.join(BIN, "mipsel-none-elf-" + n + ".exe")
ARCH = ["-march=mips1", "-mabi=32", "-EL", "-fno-pic", "-mno-shared", "-mno-abicalls", "-mfp32"]
CFLAGS = ARCH + ["-fno-stack-protector", "-nostdlib", "-ffreestanding", "-ffunction-sections", "-mno-gpopt", "-fomit-frame-pointer", "-fno-builtin", "-fno-strict-aliasing",
                 "-Wno-attributes", "-I" + HERE, "-Os", "-flto"]

# the card transfer of tools/stage2min (stage2min.c), as a replacement for mcReadFrame
MYREAD = r'''
static uint8_t myxfer(uint8_t t, int ack)
{
    uint8_t r;
    IREG = ~IRQ_CONTROLLER;
    SIOS[0].ctrl |= 0x10;
    SIOS[0].fifo = t;
    while (!(SIOS[0].stat & 2)) {}
    r = SIOS[0].fifo;
    if (ack) while (!(IREG & IRQ_CONTROLLER)) {}
    return r;
}

static void mcReadFrame(uint32_t frame, uint8_t* buffer)
{
#ifdef FPSXB_SLOT2
    SIOS[0].ctrl = 0x3003;
#else
    SIOS[0].ctrl = 0x1003;
#endif
    busyLoop(100);
    for (int i = 0; i < 140; i++) {
        uint8_t r = myxfer(i == 0 ? 0x81 : i == 1 ? 0x52 : i == 4 ? frame >> 8 : i == 5 ? frame : 0, i < 139);
        if (i >= 10 && i < 138) *buffer++ = r;
    }
    SIOS[0].ctrl = 0;
}
'''


def patch(src, nogpu, myread):
    if nogpu:
        a = src.index("    // Resets CPU and display a solid color")
        b = src.index("    printf(\"Resetting SIO0\\n\");")
        src = src[:a] + src[b:]
        a = src.index("            int32_t fillWidth = WIDTH * stage3Frames / totalStage3Frames;")
        b = src.index("            mcReadFrame(frame, tload);")
        src = src[:a] + src[b:]
    if myread:
        a = src.index("static void mcReadFrame(uint32_t frame, uint8_t* buffer) {")
        b = src.index("static const union Color c_fgIdle")
        src = src[:a] + MYREAD + "\n" + src[b:]
    return src


def build(name, nogpu, myread, kernel1, out):
    d = os.path.join(out, name)
    os.makedirs(d, exist_ok=True)
    src = patch(open(os.path.join(HERE, "stage2.c")).read(), nogpu, myread)
    open(os.path.join(d, "stage2.c"), "w").write(src)
    defs = ["-DPSX_KERNEL1"] if kernel1 else []
    asdef = ["-Wa,--defsym,PSX_KERNEL1=1"] if kernel1 else []
    objs = []
    for s, kind in (("common/crt0/crt0.s", "s"), ("common/syscalls/printf.s", "s"), (os.path.join(d, "stage2.c"), "c"), ("reboothook.s", "s")):
        p = s if os.path.isabs(s) else os.path.join(HERE, s)
        o = os.path.join(d, os.path.basename(s) + ".o")
        if kind == "c":
            subprocess.run([T("gcc"), *CFLAGS, *defs, "-c", p, "-o", o], check=True)
        else:
            subprocess.run([T("gcc"), *ARCH, *asdef, "-I" + HERE, "-g", "-c", p, "-o", o], check=True)
        objs.append(o)
    elf, binf = os.path.join(d, name + ".elf"), os.path.join(d, name + ".bin")
    subprocess.run([T("gcc"), *CFLAGS, "-Wl,-Map=" + os.path.join(d, name + ".map"), "-T" + os.path.join(HERE, "stage2.ld"), "-static", "-Wl,--gc-sections", "-o", elf, *objs], check=True)
    subprocess.run([T("objcopy"), "-O", "binary", elf, binf], check=True)
    print("%s: %d bytes = %d frames" % (name, os.path.getsize(binf), (os.path.getsize(binf) + 127) // 128))
    return binf


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--kernel1", action="store_true")
    ap.add_argument("--out", default=os.path.join(ROOT, "build", "stage2var"))
    a = ap.parse_args()
    build("v0", False, False, a.kernel1, a.out)
    build("v1", True, False, a.kernel1, a.out)
    build("v2", True, True, a.kernel1, a.out)
