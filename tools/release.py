"""Builds a release set: a base image with its release record filled in, and the package of the overlay that belongs to it.

  py -3.13 tools/release.py build [--build-dir build/psx] [--base psxx_ovl_base] [--overlay psxx_ovl_demo] [--group-id 1] [--out build/release/demo]
  py -3.13 tools/release.py verify <dir>

build:  1. ninja builds the base (the release record is still zero); 2. base_id = SHA-256 of the loaded image with the key, base_id and data key zeroed; 3. ninja builds the overlay against the
        base (its addresses come from the base ELF, see hal/psx/gen_syms.cmake); 4. the overlay bytes (objcopy -O binary) go into a package of kind 1 with the base_id in its header,
        LZMA packed with the image of the base up to its release record as the preset dictionary (codec 2, tools/lzma_dict.py; the loader's decoder is run on the host to check
        them), the package is signed (BIP340, tools/sign_key.py) over its header and table; 5. the public key and base_id are written into the release record of a COPY of the base exe: nothing moves, so the
        base_id stays the hash of the image with the two fields zeroed. Output: <out>/base.exe, overlay.pkg, release.json.
verify: the checks the loader will do, from the files only: the record of the exe, its base_id recomputed, the signature of the package against the key of the record, the base_id of the package against the one of
        the exe, the group hash, the overlay header (load address, sizes, entry point inside the image).
The loader (M3) compares psxx_release_info.base_id with the base_id of the package header (pkg_check_base) and checks the signature of the package against psxx_release_info.key (pkg_open)."""
import argparse, hashlib, json, lzma, os, re, shutil, struct, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import pkg_pack as P
import sign_key
import mkcard as M

SDK_BIN = os.path.join(ROOT, "toolchain", "sdk", "PSn00bSDK-0.24-win32", "bin")
GCC_BIN = os.path.join(ROOT, "toolchain", "gcc", "bin")
REC_MAGIC = b"PSXXREL1"
REC_SIZE = 128                                            # magic 8, pin 32, base_id 32, data pin 32, reserved 24
PIN_AT, BASE_AT, DATA_AT = 8, 40, 72
OVL_MAGIC = b"PSXO"
OVL_HEADER = 32


def memmap():
    """the fixed places of the overlays, from hal/psx/memmap.h (the linker scripts are made from the same numbers)"""
    d = {}
    for line in open(os.path.join(ROOT, "hal", "psx", "memmap.h"), encoding="utf-8"):
        m = re.match(r"#define (MM_[A-Z0-9_]+) +(0x[0-9A-Fa-f]+)u", line)
        if m:
            d[m.group(1)] = int(m.group(2), 16)
    return d


MM = memmap()
# group id -> (code lo, code hi, bss lo, bss hi): the signer's image in its slot with the bss in pocket 1, the language module in its slot with the bss after the image (None)
SLOTS = {1: (MM["MM_SIG_LO"], MM["MM_SIG_HI"], MM["MM_P1_LO"], MM["MM_P1_HI"]), 2: (MM["MM_LANG_LO"], MM["MM_LANG_HI"], None, None)}


def tool_env():
    env = dict(os.environ)
    extra = [SDK_BIN, GCC_BIN, r"C:\msys64\ucrt64\bin", r"C:\msys64\usr\bin"]
    env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    env["PSN00BSDK_LIBS"] = os.path.join(ROOT, "toolchain", "sdk", "PSn00bSDK-0.24-win32", "lib", "libpsn00b")
    return env


def run(cmd, cwd=None, capture=False):
    env = tool_env()
    exe = shutil.which(cmd[0], path=env["PATH"])               # CreateProcess looks in the PATH of this process, not in env
    if not exe:
        sys.exit("program not found: %s" % cmd[0])
    r = subprocess.run([exe] + cmd[1:], cwd=cwd, env=env, capture_output=capture, text=True)
    if r.returncode:
        sys.exit("command failed: %s\n%s" % (" ".join(cmd), (r.stdout or "") + (r.stderr or "")))
    return r.stdout if capture else None


def nm_address(elf, name):
    out = run([os.path.join(GCC_BIN, "mipsel-none-elf-nm.exe"), "-f", "posix", elf], capture=True)
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 3 and p[0] == name:
            return int(p[2], 16) & 0xFFFFFFFF
    sys.exit("symbol %s not found in %s" % (name, elf))


def exe_image(exe_bytes):
    taddr, tsize = struct.unpack_from("<2I", exe_bytes, 0x18)
    return taddr, tsize, exe_bytes[0x800:0x800 + tsize]


def base_id_of(image, rec_off):
    """SHA-256 of the image with the pin, base_id and data pin of the record set to zero"""
    z = bytearray(image)
    z[rec_off + PIN_AT:rec_off + PIN_AT + 96] = b"\0" * 96
    return hashlib.sha256(z).digest()


def unpack(pkg_bytes, e, dictionary):
    """the raw bytes of an LZMA group: codec 1 alone, codec 2 (PKG_CODEC_LZMA_BASE) against the image of the base up to its release record"""
    stored = pkg_bytes[e["offset"]:e["offset"] + e["len"]]
    props = (e["flags"] >> 4) & 255
    lc, lp, pb = props % 9, (props // 9) % 5, props // 45
    if e["flags"] & 15 == 2:
        import lzma_dict
        return lzma_dict.decompress(stored, e["rawlen"], dictionary, lc, lp, pb)
    return lzma.decompress(stored, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": 1 << 18}])


def check_host_decoder(pkg_bytes, dictionary, raws):
    """the decoder of the loader (tools/stub/lzma_unpack.h with LZMA_DICT, as core/pkg/ovl.c builds it), compiled for the host, unpacks every codec 2 group to its raw bytes"""
    import tempfile
    info = P.parse(pkg_bytes, None, P.KIND["overlay"])
    with tempfile.TemporaryDirectory() as w:
        exe = os.path.join(w, "lzma_test.exe")
        run(["gcc", "-O1", "-DLZMA_DICT", "-I", os.path.join(HERE, "stub"),
             os.path.join(HERE, "stub", "lzma_test.c"), "-o", exe])
        open(os.path.join(w, "dict.bin"), "wb").write(dictionary)
        for e in info["entries"]:
            if e["flags"] & 15 != 2:
                continue
            open(os.path.join(w, "c.bin"), "wb").write(pkg_bytes[e["offset"]:e["offset"] + e["len"]])
            open(os.path.join(w, "raw.bin"), "wb").write(raws[e["id"]])
            r = subprocess.run([exe, os.path.join(w, "c.bin"), os.path.join(w, "raw.bin"), os.path.join(w, "dict.bin"), str((e["flags"] >> 4) & 255)])
            if r.returncode:
                sys.exit("the loader's decoder does not reproduce group %d (%d)" % (e["id"], r.returncode))


def find_record(image):
    at = image.find(REC_MAGIC)
    if at < 0 or image.find(REC_MAGIC, at + 1) >= 0:
        raise ValueError("the release record is missing or not unique in the image")
    return at


def parse_overlay(raw, group=1):
    """the header of an overlay image (hal/psx/ovl.ld.in) of the given group, checked against the slot of that group (memmap.h)"""
    code_lo, code_hi, bss_lo, bss_hi = SLOTS.get(group, SLOTS[1])
    if bss_lo is None:
        bss_lo, bss_hi = code_lo, code_hi
    if len(raw) < OVL_HEADER or raw[:4] != OVL_MAGIC:
        raise ValueError("overlay: bad magic")
    ver, entry, load, size, bss, bss_size, rsv = struct.unpack_from("<7I", raw, 4)
    if ver != 1 or rsv:
        raise ValueError("overlay: bad version or reserved field")
    if size != len(raw) or load < code_lo or load + size > code_hi:
        raise ValueError("overlay: size or load address out of range")
    if not (load + OVL_HEADER <= entry < load + size) or entry % 4:
        raise ValueError("overlay: entry point outside the image")
    if code_lo <= bss < code_hi and bss < load + size:
        raise ValueError("overlay: bss inside the image")
    if bss < bss_lo or bss + bss_size > bss_hi or bss % 4:
        raise ValueError("overlay: bss out of range")
    return {"entry": entry, "load": load, "size": size, "bss": bss, "bss_size": bss_size}


def pad_bytes(n):
    """n bytes that do not compress and are the same every time"""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(b"psxx pad %d" % i).digest()
        i += 1
    return out[:n]


def build(a):
    bd = os.path.join(ROOT, a.build_dir)
    out = os.path.join(ROOT, a.out)
    os.makedirs(out, exist_ok=True)
    p = os.path.join(bd, a.overlay + ".elf")               # the overlay is linked again against this base
    if os.path.exists(p):
        os.remove(p)
    if a.lang:
        pl = os.path.join(bd, a.lang + ".elf")
        if os.path.exists(pl):
            os.remove(pl)
    run(["cmake", "-DPSXX_QUIET=%s" % ("ON" if getattr(a, "quiet", False) else "OFF"),                       # production: no TTY diagnostics (hal/psx/log.h)
         "-DPSXX_LTO=%s" % ("OFF" if getattr(a, "no_lto", False) else "ON"),                                # link-time optimisation of A, B and the module
         "-DPSXX_EXT_DEC=%s" % ("OFF" if getattr(a, "own_dec", False) else "ON"), "."], cwd=bd)            # the decoder of A lives in the stub of the boot card (tools/packexe.py --ext-dec)
    run(["ninja", a.base], cwd=bd)
    base_exe = open(os.path.join(bd, a.base + ".exe"), "rb").read()
    taddr, tsize, image = exe_image(base_exe)
    rec_addr = nm_address(os.path.join(bd, a.base + ".elf"), "psxx_release_info")
    rec_off = rec_addr - taddr
    if image[rec_off:rec_off + 8] != REC_MAGIC or any(image[rec_off + PIN_AT:rec_off + PIN_AT + 96]):
        sys.exit("the release record of the fresh base build is not empty")
    base_id = base_id_of(image, rec_off)
    dictionary = image[:rec_off]                           # the code and the constants of the base up to its record: the preset dictionary of the overlays (core/pkg/ovl.c)
    if nm_address(os.path.join(bd, a.base + ".elf"), "__text_start") != taddr or rec_off % 4:
        sys.exit("the image of the base does not start at __text_start, or its release record is not at a multiple of 4")

    run(["ninja", a.overlay], cwd=bd)
    ovl_bin = os.path.join(out, "overlay.bin")
    run([os.path.join(GCC_BIN, "mipsel-none-elf-objcopy.exe"), "-O", "binary", os.path.join(bd, a.overlay + ".elf"), ovl_bin])
    raw = open(ovl_bin, "rb").read()
    ovl = parse_overlay(raw, a.group_id)
    groups = [(a.group_id, raw, "lzma_base_best")]
    lang_raw = b""
    if a.lang:                                             # the language module: a second overlay in the same package
        lang_bin = os.path.join(out, "lang.bin")
        run(["ninja", a.lang], cwd=bd)
        run([os.path.join(GCC_BIN, "mipsel-none-elf-objcopy.exe"), "-O", "binary", os.path.join(bd, a.lang + ".elf"), lang_bin])
        lang_raw = open(lang_bin, "rb").read()
        os.remove(lang_bin)
        parse_overlay(lang_raw, a.lang_group)
        groups.append((a.lang_group, lang_raw, "lzma_base_best"))
    if a.pad:                                              # an extra group of incompressible bytes: a package of several blocks, to try the reading of long files
        groups.append((a.group_id + 1, pad_bytes(a.pad), "stored"))
    ext = bytes.fromhex(a.pub) if getattr(a, "pub", None) else None                    # a Nostr signer of its own signs later (attach); the package has a zero signature until then
    if ext and (getattr(a, "data", None) or len(ext) != 32):
        sys.exit("--pub is the 64 hex digits of the x only public key, and does not go with --data (a data package is signed with tools/sign_key.py)")
    pkg, pin = P.build(P.KIND["overlay"], groups, base_id, base_image=dictionary, pub=ext)      # pin: the public key that signed it (x only)
    check_host_decoder(pkg, dictionary, {gid: r for gid, r, _ in groups})
    open(os.path.join(out, "overlay.pkg"), "wb").write(pkg)
    if ext:
        te = P.HEADER + struct.unpack_from("<H", pkg, 6)[0] * P.ENTRY
        dg = P.digest(pkg[:te]).hex()
        ev = {"kind": P.EVENT_KIND, "created_at": P.EVENT_TIME, "tags": [["d", dg]], "content": dg}       # what the signer is asked to sign: its id is the message of the package
        open(os.path.join(out, "event.json"), "w").write(json.dumps(ev, separators=(",", ":")))

    patched = bytearray(base_exe)
    at = 0x800 + rec_off
    patched[at + PIN_AT:at + PIN_AT + 32] = pin
    patched[at + BASE_AT:at + BASE_AT + 32] = base_id
    dpin = b""
    if getattr(a, "data", None):                                             # the data package (the language card) of this release: the key that has to have signed it goes into the record too
        d = open(os.path.join(ROOT, a.data) if not os.path.isabs(a.data) else a.data, "rb").read()
        dpin = sign_key.public()
        P.parse(d, dpin, P.KIND["data"])                                       # it has to be signed with the key of the release (tools/sign_key.py)
        patched[at + DATA_AT:at + DATA_AT + 32] = dpin
    open(os.path.join(out, "base.exe"), "wb").write(patched)
    info = {"base": a.base, "overlay": a.overlay, "group_id": a.group_id, "base_id": base_id.hex(), "key": pin.hex(), "record_address": "0x%08x" % rec_addr,
            "overlay_load": "0x%08x" % ovl["load"], "overlay_entry": "0x%08x" % ovl["entry"], "overlay_bytes": len(raw), "package_bytes": len(pkg), "data_key": dpin.hex(),
            "lang": a.lang, "lang_group": a.lang_group if a.lang else None, "lang_bytes": len(lang_raw), "ext_dec": not getattr(a, "own_dec", False)}
    if ext:
        info["event_id"] = P.message(pkg[:te], ext).hex()
    json.dump(info, open(os.path.join(out, "release.json"), "w"), indent=2)
    os.remove(ovl_bin)
    print("base id %s\nkey     %s\nbase image %d bytes, record at 0x%08x; overlay %d bytes at 0x%08x (entry 0x%08x), package %d bytes" % (
        base_id.hex(), pin.hex(), tsize, rec_addr, len(raw), ovl["load"], ovl["entry"], len(pkg)))
    if a.lang:
        print("language module %d bytes (group %d)" % (len(lang_raw), a.lang_group))
    if ext:
        print("the package is not signed yet: the signer (the key %s) signs event.json, then" % ext.hex())
        print("  release.py attach %s --sig <the 128 hex digits>" % a.out)
        print("event id %s" % info["event_id"])
        return
    verify_dir(out)


def attach(a):
    """the signature that the Nostr signer made (BIP340 over the id of the event of event.json) goes into the package; checked against the key of the release record"""
    d = os.path.join(ROOT, a.dir) if not os.path.isabs(a.dir) else a.dir
    rel = json.load(open(os.path.join(d, "release.json")))
    pub = bytes.fromhex(rel["key"])
    path = os.path.join(d, "overlay.pkg")
    data = open(path, "rb").read()
    te = P.HEADER + struct.unpack_from("<H", data, 6)[0] * P.ENTRY
    sig = bytes.fromhex(a.sig)
    if len(sig) != P.SIG or not P.bip340.verify(pub, P.message(data[:te], pub), sig):
        sys.exit("the signature is not valid for this package and the key %s" % pub.hex())
    open(path, "wb").write(data[:te] + sig + data[te + P.SIG:])
    print("signature attached to %s" % path)
    verify_dir(d)


def add_data(a):
    """the data key (the key that has to have signed the data package of the language card, C) goes into the release record of base.exe. The base id does not change (the record's keys are zeroed
    for it), neither does the overlay package; the packed program and so the boot cards do: make them again (cards)"""
    d = os.path.join(ROOT, a.dir) if not os.path.isabs(a.dir) else a.dir
    rel = json.load(open(os.path.join(d, "release.json")))
    path = os.path.join(d, "base.exe")
    exe = bytearray(open(path, "rb").read())
    taddr, tsize, image = exe_image(exe)
    rec = find_record(image)
    dpin = bytes.fromhex(a.pin) if a.pin else bytes.fromhex(rel["key"])
    if len(dpin) != 32:
        sys.exit("--pin is the 64 hex digits of the x only public key")
    if a.data:                                                                          # the data package has to be signed by that key
        P.parse(open(a.data, "rb").read(), dpin, P.KIND["data"])
    at = 0x800 + rec
    exe[at + DATA_AT:at + DATA_AT + 32] = dpin
    open(path, "wb").write(exe)
    rel["data_key"] = dpin.hex()
    json.dump(rel, open(os.path.join(d, "release.json"), "w"), indent=2)
    print("data key %s written into the record of %s (base id unchanged: %s)" % (dpin.hex(), path, rel["base_id"]))
    verify_dir(d)


def verify_files(exe_bytes, pkg_bytes):
    """the loader's checks; returns a dict of what was found, raises ValueError with the reason"""
    taddr, tsize, image = exe_image(exe_bytes)
    rec = find_record(image)
    pin = image[rec + PIN_AT:rec + PIN_AT + 32]
    base_id = image[rec + BASE_AT:rec + BASE_AT + 32]
    if not any(pin) or not any(base_id):
        raise ValueError("the release record of the base has not been filled in")
    if base_id_of(image, rec) != base_id:
        raise ValueError("the base id in the record is not the hash of the image")
    try:
        info = P.parse(pkg_bytes, pin, P.KIND["overlay"])
    except P.PkgError as e:
        raise ValueError("package refused: %s" % e.code)
    if info["base_id"] != base_id:
        raise ValueError("the package was made for another base image")
    for x in info["entries"]:
        if not P.group_ok(pkg_bytes, x):
            raise ValueError("group %d has a wrong hash" % x["id"])
    if info["entries"][0]["flags"] & 15 not in (1, 2):
        raise ValueError("the overlay group is not LZMA packed")
    ovls = []
    for e in info["entries"]:                              # the overlays: every LZMA group (the first is the signer, the others e.g. the language module); a stored group is padding
        if e["flags"] & 15 not in (1, 2):
            continue
        try:
            raw = unpack(pkg_bytes, e, image[:rec])
        except (lzma.LZMAError, RuntimeError) as x:
            raise ValueError("group %d does not unpack: %s" % (e["id"], x))
        if len(raw) != e["rawlen"]:
            raise ValueError("the unpacked overlay has the wrong size")
        ovls.append(parse_overlay(raw, e["id"]))
    return {"base_id": base_id, "pin": pin, "overlay": ovls[0], "overlays": ovls}


def verify_dir(d):
    d = os.path.join(ROOT, d) if not os.path.isabs(d) else d
    try:
        r = verify_files(open(os.path.join(d, "base.exe"), "rb").read(), open(os.path.join(d, "overlay.pkg"), "rb").read())
    except ValueError as e:
        print("VERIFY FAILED: %s" % e)
        sys.exit(1)
    print("verified: base id %s.., key %s.., overlay at 0x%08x, %d bytes" % (r["base_id"].hex()[:16], r["pin"].hex()[:16], r["overlay"]["load"], r["overlay"]["size"]))


PKG_NAME = "BESCES-00000PSXXPK01"
BIOS = "2.0-19950510-E"                                    # SCPH-1002


def make_cards(a):
    d = os.path.join(ROOT, a.dir) if not os.path.isabs(a.dir) else a.dir
    verify_dir(d)
    pkg = open(os.path.join(d, "overlay.pkg"), "rb").read()
    info = P.parse(pkg, None, 1)
    rel = json.load(open(os.path.join(d, "release.json")))
    run([sys.executable, os.path.join(HERE, "packexe.py"), os.path.join(d, "base.exe"), os.path.join(d, "base_packed.exe"), *(["--ext-dec"] if rel.get("ext_dec") else [])])
    bios = getattr(a, "bios", None) or BIOS
    boot = "A-boot.mcd" if bios == BIOS and not getattr(a, "minload", False) else "A-boot-%s%s.mcd" % (bios, "-min" if getattr(a, "minload", False) else "")
    extra = []
    if getattr(a, "minload", False):                       # the minimal fastload stage2 (tools/stage2min): the BIOS 1.0 and 4.x do not run the slow loader, and the full fastload does not fit
        sys.path.insert(0, os.path.join(HERE, "stage2min"))
        import build as s2build
        extra = ["-minload", s2build.build(os.path.join(ROOT, "build", "stage2min"))]
    run([os.path.join(ROOT, "toolchain", "FreePSXBoot", "builder", "builder.exe"), "-bios", bios, "-slot", "1", *extra, "-in", os.path.join(d, "base_packed.exe"),
         "-out", os.path.join(d, boot)])

    def card(name, blob):
        c = M.blank_card()
        if blob is not None:
            M.add_file(c, PKG_NAME, blob, "PSXX overlay")
        open(os.path.join(d, name), "wb").write(c)
        print("%-16s %s" % (name, "no package" if blob is None else "%d bytes in the package" % len(blob)))

    bad = bytearray(pkg)
    e = info["entries"][0]
    bad[e["offset"] + 5] ^= 1                              # a byte of the overlay itself
    card("B-ok.mcd", pkg)
    card("B-damaged.mcd", bytes(bad))
    card("B-empty.mcd", None)
    if a.wrong_from:
        w = os.path.join(ROOT, a.wrong_from) if not os.path.isabs(a.wrong_from) else a.wrong_from
        card("B-wrong.mcd", open(os.path.join(w, "overlay.pkg"), "rb").read())
    print("boot card %s" % os.path.join(d, boot))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--build-dir", default="build/psx")
    b.add_argument("--base", default="psxx_ovl_base")
    b.add_argument("--overlay", default="psxx_ovl_demo")
    b.add_argument("--group-id", type=int, default=1)
    b.add_argument("--out", default="build/release/demo")
    b.add_argument("--data", help="the data package (tools/data_pack.py): its pin is written into the release record")
    b.add_argument("--lang", help="the language module: a second overlay target, group --lang-group of the package")
    b.add_argument("--lang-group", type=int, default=2)
    b.add_argument("--quiet", action="store_true", help="the production build: no TTY diagnostics (PSXX_QUIET)")
    b.add_argument("--own-dec", action="store_true", help="the main card carries its own LZMA decoder (PSXX_EXT_DEC=OFF; the boot card's stub is the plain one)")
    b.add_argument("--no-lto", action="store_true", help="without the link-time optimisation of A, B and the module (PSXX_LTO=OFF)")
    b.add_argument("--pub", help="the release is signed by a Nostr signer of your own: its x only public key (64 hex digits); the package stays unsigned (event.json is what to sign), attach follows")
    b.add_argument("--pad", type=int, default=0, help="bytes of an extra group (id group-id + 1) that makes the package long")
    c = sub.add_parser("cards", help="memory card images of a release set: A-boot, B-ok, B-damaged, B-empty and, with --wrong-from, B-wrong")
    c.add_argument("dir")
    c.add_argument("--wrong-from", help="the release directory of another base: its package goes on B-wrong")
    c.add_argument("--bios", help="the BIOS of the console (FreePSXBoot's name, e.g. 4.1-19971216-A); default %s; the boot card is then A-boot-<bios>.mcd" % BIOS)
    c.add_argument("--minload", action="store_true", help="the boot card with the minimal fastload stage2 (tools/stage2min): A-boot-<bios>-min.mcd")
    t = sub.add_parser("attach", help="put the signature of the Nostr signer into the package of a build made with --pub")
    t.add_argument("dir")
    t.add_argument("--sig", required=True, help="128 hex digits")
    v = sub.add_parser("verify")
    v.add_argument("dir")
    ad = sub.add_parser("add-data", help="put the data key (default: the release key) into the release record of base.exe; then make the boot cards again")
    ad.add_argument("dir")
    ad.add_argument("--pin", help="the x only public key (64 hex digits) that signs the data package; default: the key of the release")
    ad.add_argument("--data", help="the data package: checked against the key")
    m = sub.add_parser("manifest", help="the release manifest (a Nostr event to sign) of a release directory and its cards (tools/release_manifest.py)")
    m.add_argument("dir")
    m.add_argument("--cards", required=True, help="the directory of the memory card images (*.mcd)")
    m.add_argument("--name", required=True)
    m.add_argument("--version")
    m.add_argument("--date", help="YYYY-MM-DD")
    m.add_argument("--created-at", type=int, help="the created_at of the event (default: now)")
    m.add_argument("--source-rev", help="the git revision the release was built from (default HEAD)")
    m.add_argument("--description-file", help="the text for people (English) that goes into the manifest as its description (release-notes/<name>.txt)")
    m.add_argument("--spa", help="the verifier page of the release (tools/build_spa.py): its size and SHA-256 go into the manifest")
    am = sub.add_parser("attach-manifest", help="put the signature of the signer into the manifest event; writes manifest_signed.json and package_event.json")
    am.add_argument("dir")
    am.add_argument("--sig", required=True, help="128 hex digits")
    cc = sub.add_parser("check-cards", help="check cards against the signed event and manifest, from files (the Python twin of the verifier page)")
    cc.add_argument("--trust", default="", help="npub or 64 hex digits of the project key")
    cc.add_argument("--boot")
    cc.add_argument("--other", action="append", default=[])
    cc.add_argument("--event", help="the signed package event (package_event.json)")
    cc.add_argument("--manifest", help="the signed release manifest (manifest_signed.json)")
    cc.add_argument("--image-size", type=int, default=0)
    a = ap.parse_args()
    if a.cmd == "build":
        build(a)
    elif a.cmd == "cards":
        make_cards(a)
    elif a.cmd == "attach":
        attach(a)
    elif a.cmd == "add-data":
        add_data(a)
    elif a.cmd in ("manifest", "attach-manifest", "check-cards"):
        import release_manifest as RM
        {"manifest": RM.manifest, "attach-manifest": RM.attach_manifest, "check-cards": RM.check_main}[a.cmd](a)
    else:
        verify_dir(a.dir)


if __name__ == "__main__":
    main()
