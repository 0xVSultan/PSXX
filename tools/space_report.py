#!/usr/bin/env python3
"""The space report of the three cards and of the RAM.

  py -3.13 tools/space_report.py <release dir> [--data <data dir>] [--build-dir build/psx] [--host-dir build/host]

A (the boot card): the payload that FreePSXBoot loads (the packed program and its stub, in whole frames of 128 bytes) against its limit, the padding.
B (the package of the signer and the language module, PSXXPK01) and C (the package of the language data, PSXXPK02): the file against the blocks of a memory card - the first block of
a file holds 7936 bytes of data (the header and icon frames), every other one 8192 - the groups with their stored and unpacked sizes, the padding between the groups (they start on
multiples of PKG_ALIGN), and the padding of the last block, which is the part of the last block that the file does not use and nobody else can: what would be needed to save a block, and what
could be added without costing one.
RAM: the slots and pockets of hal/psx/memmap.h against what is in them (the images and bss from the ELF files, the data of every language from the host test of the module).
The output is text; the numbers are those of the files, nothing is estimated except where it says so."""
import argparse, json, os, re, struct, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import pkg_pack as P
import mkcard as M
import release as R

A_LIMIT = 122752                 # the payload that fits the boot card of FreePSXBoot (tools/size_matrix.py)
FRAME = 128
NM = os.path.join(ROOT, "toolchain", "gcc", "bin", "mipsel-none-elf-nm.exe")


def kb(n):
    return "%d B (%.1f KB)" % (n, n / 1024.0)


def group_table(pkg_bytes, kind):
    info = P.parse(pkg_bytes, None, kind)
    return info["entries"], info


def pkg_section(title, path, kind, extra=""):
    d = open(path, "rb").read()
    entries, info = group_table(d, kind)
    n = len(d)
    nb = M.blocks_needed(n)
    cap = M.capacity(nb)
    last_used = n - M.capacity(nb - 1) if nb > 1 else n
    last_cap = M.BLOCK_DATA if nb > 1 else M.BLOCK_DATA_FIRST
    out = []
    out.append("== %s  (%s)" % (title, os.path.basename(path)))
    out.append("package file      %s: header 48 B + table %d x 48 B = %d B, the groups %d B" % (kb(n), len(entries), 48 + 48 * len(entries), n - 48 - 48 * len(entries)))
    out.append("memory card       %d of 15 blocks (a file of 15 blocks holds %d B at most)" % (nb, M.capacity(15)))
    out.append("last block        %d of %d B used, %d B free in it and not usable by anything else (%.0f%% of the block)" % (last_used, last_cap, last_cap - last_used, 100.0 * (last_cap - last_used) / last_cap))
    out.append("what it takes     to save one block: cut %d B from the package; to add without a new block: up to %d B" % (n - M.capacity(nb - 1) + 1 if nb > 1 else 1, cap - n))
    out.append("blocks left       %d free on a card of 15 blocks (the key store, requests and results of card B use them)" % (15 - nb))
    pad = 0
    rows = []
    for i, e in enumerate(entries):
        end = e["offset"] + e["len"]
        nxt = entries[i + 1]["offset"] if i + 1 < len(entries) else info["total"]
        pad += nxt - end
        rows.append((e["len"], e["rawlen"], e["id"], {1: "lzma", 2: "lzma+A"}.get(e["flags"] & 15, "stored"), nxt - end))
    out.append("alignment padding between the groups (they start on multiples of %d B): %d B in all, the table %d B" % (P.ALIGN, pad, 48 + 48 * len(entries)))
    out.append("groups (stored B, unpacked B, id, how, padding after it), the biggest first:")
    for ln, raw, gid, how, pd in sorted(rows, reverse=True)[:12]:
        out.append("   %7d  %7d  %04x  %-6s  %3d" % (ln, raw, gid, how, pd))
    if len(rows) > 12:
        out.append("   ... %d smaller groups (%d B together)" % (len(rows) - 12, sum(r[0] for r in sorted(rows, reverse=True)[12:])))
    if extra:
        out.append(extra)
    return "\n".join(out), nb, n


def a_section(rel):
    packed = os.path.join(rel, "base_packed.exe")
    base = os.path.join(rel, "base.exe")
    payload = os.path.getsize(packed) - 0x800
    image = open(base, "rb").read()
    tsize = struct.unpack_from("<I", image, 0x1C)[0]
    out = ["== A  (the boot card: base_packed.exe)"]
    out.append("payload           %s of the %d B that the boot card holds: %d B free (%.1f%% used)" % (kb(payload), A_LIMIT, A_LIMIT - payload, 100.0 * payload / A_LIMIT))
    out.append("                  the image is %s unpacked; the payload is in whole frames of %d B" % (kb(tsize), FRAME))
    return "\n".join(out), payload


def symbols(elf, names):
    out = subprocess.run([NM, "-n", elf], capture_output=True, text=True).stdout
    res = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) == 3 and p[2] in names:
            res[p[2]] = int(p[0], 16) & 0xFFFFFFFF
    return res


def ram_section(rel, build_dir, host_dir, data_dir):
    mm = R.MM
    sig = (mm["MM_SIG_LO"], mm["MM_SIG_HI"])
    lang = (mm["MM_LANG_LO"], mm["MM_LANG_HI"])
    p1 = (mm["MM_P1_LO"], mm["MM_P1_HI"])
    p0 = (mm["MM_P0_LO"], mm["MM_P0_HI"])
    info = json.load(open(os.path.join(rel, "release.json")))
    out = ["== RAM  (hal/psx/memmap.h)"]
    b = symbols(os.path.join(build_dir, "psxx_b.elf"), {"__ovl_load_end", "__ovl_bss_start", "__ovl_bss_end"})
    l = symbols(os.path.join(build_dir, "psxx_l.elf"), {"__ovl_load_end", "__ovl_bss_start", "__ovl_bss_end"})
    sig_img = info["overlay_bytes"]
    bss_sig = b["__ovl_bss_end"] - b["__ovl_bss_start"]
    out.append("signer slot       %d of %d B used by the image: %d B free" % (sig_img, sig[1] - sig[0], sig[1] - sig[0] - sig_img))
    out.append("pocket 1          %d of %d B: the bss of the signer %d B, %d B free while the signer runs; as scratch of the language module %d B are used (STAGE + WORK)" % (
        bss_sig, p1[1] - p1[0], bss_sig, p1[1] - p1[0] - bss_sig, 0x0A000 + 0x16000))
    lang_img = l["__ovl_load_end"] - lang[0]
    lang_bss = l["__ovl_bss_end"] - l["__ovl_bss_start"]
    out.append("module slot       %d of %d B: the image %d B, its bss %d B, %d B above it are the second segment of the language data" % (lang_img + lang_bss, lang[1] - lang[0], lang_img, lang_bss, lang[1] - l["__ovl_bss_end"]))
    exe = os.path.join(host_dir, "test_langui.exe")
    pk, js = os.path.join(data_dir, "data.pkg"), os.path.join(data_dir, "data.json")
    if os.path.exists(exe) and os.path.exists(pk):
        env = dict(os.environ, PSXX_USAGE="1")
        r = subprocess.run([exe, pk, js], capture_output=True, text=True, env=env)
        rows = [line.split(None, 3) for line in r.stdout.splitlines() if line.startswith("[arena]")]
        if rows:
            out.append("pocket 0          %d B; the data of a language with its typing keys (the host test of the module), the second segment above the module has %d B more:" % (p0[1] - p0[0], lang[1] - l["__ovl_bss_end"]))
            worst = 0
            for _, lid, rest in [(x[0], x[1], x[2] + " " + x[3]) if len(x) > 3 else (x[0], x[1], x[2]) for x in rows]:
                parts = rest.rsplit(" ", 2)
                name, u0, u1 = parts[0], int(parts[1]), int(parts[2])
                worst = max(worst, u0 + u1)
                out.append("   %-18s %7d B in the pocket%s (%.0f%% of it)" % (name, u0, "" if not u1 else ", %d B above the module" % u1, 100.0 * u0 / (p0[1] - p0[0])))
            out.append("   the most: %d B of %d: %d B of room left in the pocket" % (worst, p0[1] - p0[0], p0[1] - p0[0] - worst))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("release")
    ap.add_argument("--data", help="the directory of the data package (default: the release directory)")
    ap.add_argument("--build-dir", default=os.path.join(ROOT, "build", "psx"))
    ap.add_argument("--host-dir", default=os.path.join(ROOT, "build", "host"))
    a = ap.parse_args()
    rel = a.release if os.path.isabs(a.release) else os.path.join(ROOT, a.release)
    data = a.data or rel
    data = data if os.path.isabs(data) else os.path.join(ROOT, data)
    sections = []
    s, payload = a_section(rel)
    sections.append(s)
    s, nb_b, n_b = pkg_section("B  (the package of the signer and the language module)", os.path.join(rel, "overlay.pkg"), P.KIND["overlay"])
    sections.append(s)
    s, nb_c, n_c = pkg_section("C  (the package of the language data)", os.path.join(data, "data.pkg"), P.KIND["data"])
    sections.append(s)
    sections.append(ram_section(rel, a.build_dir, a.host_dir, data))
    print("\n\n".join(sections))


if __name__ == "__main__":
    main()
