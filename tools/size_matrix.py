"""Size of the signer (hal/psx/signer_app.c + core) for different compiler options and LZMA parameters.

  python tools/size_matrix.py            run every variant (a few minutes), print the table, write build/size_matrix.txt

The compile and link commands are taken from `ninja -t commands psxx_signer` (build/signer_cmds.txt); every variant gets its own directory under
build/variants/ and the options after the last -Os of each compile command are replaced. The payload is the LZMA stream with the lc/lp/pb the stub
uses (2, 0, 1) plus the stub (about 1.5 KB), rounded up to memory card frames; the sweep looks for the best lc/lp/pb of every image. Only the sizes
are measured: the speed of the code is not (an unrolled or inlined variant is bigger and often faster)."""
import concurrent.futures as cf, lzma, os, re, struct, subprocess, sys, zlib, bz2

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
TARGET = sys.argv[1] if len(sys.argv) > 1 else "psxx_signer"          # the executable to measure (psxx_signer, psxx_wallet)
CMDS = os.path.join(ROOT, "build", "signer_cmds.txt" if TARGET == "psxx_signer" else "wallet_cmds.txt")
VAR = os.path.join(ROOT, "build", "variants", TARGET)
BIN = os.path.join(ROOT, "toolchain", "gcc", "bin")
STUB = 1560
HOT = ("bn_comba", "keccak_fast", "sha512_fast", "ed25519", "secp256k1", "pallas", "poseidon", "blake2b", "sha256", "keccak.c")

VARIANTS = [
    ("Os (now)", "-Os", None),
    ("O1", "-O1", None),
    ("O2", "-O2", None),
    ("O3", "-O3", None),
    ("Os, no inlining", "-Os -fno-inline", None),
    ("Os, no jump tables", "-Os -fno-jump-tables", None),
    ("Os, no zero-division checks", "-Os -mno-check-zero-division", None),
    ("Os, no gp-relative (-G0)", "-Os -G0", None),
    ("Os, no gp optimisation", "-Os -mno-gpopt", None),
    ("Os, -fno-ipa-cp-clone -fno-ipa-sra", "-Os -fno-ipa-cp-clone -fno-ipa-sra", None),
    ("Os, no tail merging off (-fno-tree-tail-merge)", "-Os -fno-tree-tail-merge", None),
    ("Os, -fmerge-all-constants", "-Os -fmerge-all-constants", None),
    ("Os, -fno-ident -fno-unwind-tables", "-Os -fno-ident -fno-unwind-tables -fno-asynchronous-unwind-tables", None),
    ("Os, -mno-explicit-relocs", "-Os -mno-explicit-relocs", None),
    ("Os + O2 for the hot crypto files", "-Os", "-O2"),
    ("Os + O3 for the hot crypto files", "-Os", "-O3"),
    ("LTO, Os", "-Os -flto", None),
]


def load():
    raw = open(CMDS, "rb").read()
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
    lines = [l.strip().lstrip(chr(0xfeff)) for l in text.split(chr(10))]
    comp = [l for l in lines if " -c " in l and l.endswith(".c") or (" -c " in l and re.search(r" -c \S+$", l))]
    link = next(l for l in lines if "elf2x" in l)
    return comp, link


def run(cmd, cwd):
    r = subprocess.run(cmd.replace('"', "").split(), cwd=cwd, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def build(name, flags, hot, comp, link):
    d = os.path.join(VAR, re.sub(r"[^A-Za-z0-9]+", "_", name))
    os.makedirs(d, exist_ok=True)
    jobs = []
    for c in comp:
        src = c.split(" -c ")[-1]
        obj = re.search(r"-o (\S+) -c", c).group(1)
        os.makedirs(os.path.dirname(os.path.join(d, obj)), exist_ok=True)
        f = hot if hot and any(h in os.path.basename(src) for h in HOT) else flags
        jobs.append(c.replace(" -Os -MD ", " " + f + " -MD ", 1))
    with cf.ThreadPoolExecutor(8) as ex:
        res = list(ex.map(lambda j: run(j, d), jobs))
    for (rc, out), j in zip(res, jobs):
        if rc:
            return None, "compile failed: " + out.strip().splitlines()[-1][:120] if out.strip() else "compile failed"
    m = re.search(r'/C "cd \. && (.*?) && C:\\Windows', link)
    ldcmd = m.group(1)
    if "-flto" in flags:
        ldcmd = ldcmd.replace("-nostdlib", "-nostdlib -flto -Os -fuse-linker-plugin", 1)
    rc, out = run(ldcmd, d)
    if rc:
        return None, "link failed: " + out.strip().splitlines()[-1][:120]
    elf = os.path.join(d, TARGET + ".elf")
    exe = os.path.join(d, TARGET + ".exe")
    e2x = re.search(r'(\S*elf2x\.exe)', link).group(1)
    rc, out = run('"%s" -q "%s" "%s"' % (e2x, elf, exe), d)
    if rc:
        return None, "elf2x failed: " + out.strip()[:120]
    sz = subprocess.run([os.path.join(BIN, "mipsel-none-elf-size.exe"), elf], capture_output=True, text=True).stdout.split("\n")[1].split()
    return (exe, int(sz[0]), int(sz[1]), int(sz[2])), None


def image(exe):
    b = open(exe, "rb").read()
    pc, gp, taddr, tsize = struct.unpack_from("<4I", b, 0x10)
    return b[0x800:0x800 + tsize]


def lz(data, lc=2, lp=0, pb=1, dict_size=1 << 18):
    flt = [{"id": lzma.FILTER_LZMA1, "preset": 9 | lzma.PRESET_EXTREME, "dict_size": dict_size, "lc": lc, "lp": lp, "pb": pb,
            "nice_len": 273, "mf": lzma.MF_BT4, "depth": 1000}]
    return len(lzma.compress(data, format=lzma.FORMAT_RAW, filters=flt))


def payload(c):
    return (c + STUB + 127) // 128 * 128


def main():
    comp, link = load()
    rows = []
    for name, flags, hot in VARIANTS:
        res, err = build(name, flags, hot, comp, link)
        if err:
            print("%-48s %s" % (name, err))
            rows.append((name, None))
            continue
        exe, text, data, bss = res
        img = image(exe)
        c = lz(img)
        print("%-48s image %7d  bss %7d  lzma %7d  payload %7d  (limit 122752)" % (name, len(img), bss, c, payload(c)))
        rows.append((name, (len(img), bss, c, payload(c), exe)))
    ok = [r for r in rows if r[1]]
    base = next(r for r in ok if r[0].startswith("Os (now)"))
    best = min(ok, key=lambda r: r[1][3])
    print("\nsmallest payload:", best[0], best[1][3])
    # compression of the baseline image
    img = image(base[1][4])
    print("\nLZMA parameters for the baseline image (%d bytes):" % len(img))
    sweep = []
    for lc in range(0, 5):
        for lp in range(0, 3):
            if lc + lp > 4:
                continue
            for pb in range(0, 3):
                sweep.append((lz(img, lc, lp, pb), lc, lp, pb))
    sweep.sort()
    for c, lc, lp, pb in sweep[:6]:
        print("  lc %d lp %d pb %d: %d" % (lc, lp, pb, c))
    print("  (stub default lc 2 lp 0 pb 1: %d)" % lz(img))
    for ds in (1 << 16, 1 << 17, 1 << 19, 1 << 20):
        print("  dictionary %d KB: %d" % (ds >> 10, lz(img, 2, 0, 1, ds)))
    print("  for comparison: zlib 9 %d, bz2 %d" % (len(zlib.compress(img, 9)), len(bz2.compress(img, 9))))
    # the sections separately (each with its own best parameters)
    sec = subprocess.run([os.path.join(BIN, "mipsel-none-elf-size.exe"), "-A", base[1][4].replace(".exe", ".elf")], capture_output=True, text=True).stdout
    sizes = {}
    for l in sec.splitlines():
        p = l.split()
        if len(p) >= 3 and p[0].startswith("."):
            sizes[p[0]] = int(p[1])
    t = sizes.get(".text", 0)
    ro = sizes.get(".rodata", 0)
    parts = [("text", img[:t]), ("rodata", img[t:t + ro]), ("data", img[t + ro:])]
    tot = 0
    print("\nthe sections of the baseline image compressed separately, each with its best lc/lp/pb:")
    for pname, d in parts:
        if not d:
            continue
        b = min((lz(d, lc, lp, pb), lc, lp, pb) for lc in range(0, 5) for lp in range(0, 3) for pb in range(0, 3) if lc + lp <= 4)
        print("  %-7s %7d -> %6d (lc %d lp %d pb %d)" % (pname, len(d), b[0], b[1], b[2], b[3]))
        tot += b[0]
    print("  together %d (one stream: %d)" % (tot, lz(img)))
    with open(os.path.join(ROOT, "build", "size_matrix.txt"), "w") as f:
        for name, r in rows:
            f.write("%s\t%s\n" % (name, "failed" if not r else "\t".join(map(str, r[:4]))))


if __name__ == "__main__":
    main()
