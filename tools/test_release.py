"""Tests of the release set (tools/release.py, hal/psx/ovl.ld, hal/psx/release.c): the build is repeatable, a different base gives a different base id and pin, and every
mismatch or damage that the loader has to refuse is refused by the same checks (verify_files).

  py -3.13 tools/test_release.py        (builds a second base, variant 1, in build/psx_variant; needs the PSX toolchain, a minute)"""
import hashlib, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import release as R

fails = 0


def check(name, cond, detail=""):
    global fails
    print("%-62s %s" % (name, "ok" if cond else "FAILED " + detail))
    fails += not cond


def refused(name, exe, pkg, reason):
    try:
        R.verify_files(bytes(exe), bytes(pkg))
        check(name, False, "was accepted")
    except ValueError as e:
        check(name, reason in str(e), "refused with: %s" % e)


def build(build_dir, out):
    class A:
        pass
    a = A()
    a.build_dir, a.base, a.overlay, a.group_id, a.out, a.pad = build_dir, "psxx_ovl_base", "psxx_ovl_demo", 1, out, 0
    a.lang, a.lang_group = None, 2
    R.build(a)
    return open(os.path.join(R.ROOT, out, "base.exe"), "rb").read(), open(os.path.join(R.ROOT, out, "overlay.pkg"), "rb").read()


def main():
    # a second build directory with another base (a number built into the image)
    vd = os.path.join(R.ROOT, "build", "psx_variant")
    if not os.path.exists(os.path.join(vd, "build.ninja")):
        R.run(["cmake", "-S", os.path.join(R.ROOT, "hal", "psx"), "-B", vd, "-G", "Ninja", "--toolchain",
               os.path.join(R.tool_env()["PSN00BSDK_LIBS"], "cmake", "sdk.cmake"), "-DOVL_BASE_VARIANT=1"])
    exe_a, pkg_a = build("build/psx", "build/release/demo")
    exe_a2, pkg_a2 = build("build/psx", "build/release/demo2")
    exe_b, pkg_b = build("build/psx_variant", "build/release/variant")

    check("the build is repeatable (base exe)", exe_a == exe_a2)
    check("the build is repeatable (package)", pkg_a == pkg_a2)
    ra, rb = R.verify_files(exe_a, pkg_a), R.verify_files(exe_b, pkg_b)
    check("both releases verify", True)
    check("another base has another base id", ra["base_id"] != rb["base_id"])
    check("the same signing key for both bases", ra["pin"] == rb["pin"])
    check("the overlay of the variant is at the same address", ra["overlay"]["load"] == rb["overlay"]["load"])

    refused("the package of the other base is refused (its base id)", exe_b, pkg_a, "another base image")
    refused("the package of this base on the other base is refused (its base id)", exe_a, pkg_b, "another base image")

    taddr, tsize, image = R.exe_image(exe_a)
    rec = R.find_record(image)
    at = 0x800 + rec

    def exe_with(off, xor=1):
        d = bytearray(exe_a)
        d[off] ^= xor
        return d

    refused("a changed key in the record", exe_with(at + R.PIN_AT), pkg_a, "PIN")
    refused("a changed base id in the record", exe_with(at + R.BASE_AT), pkg_a, "not the hash")
    refused("a changed byte of the code of the base", exe_with(0x800 + 8), pkg_a, "not the hash")
    refused("a record that has not been filled in", bytes(exe_a[:at + R.PIN_AT]) + b"\0" * 64 + bytes(exe_a[at + R.PIN_AT + 64:]), pkg_a, "not been filled in")

    info = R.P.parse(pkg_a, None, 1)
    e = info["entries"][0]

    def pkg_with(off, xor=1):
        d = bytearray(pkg_a)
        d[off] ^= xor
        return d

    refused("a changed byte in the table of the package", exe_a, pkg_with(R.P.HEADER + 20), "PIN")
    refused("a changed base id in the header of the package", exe_a, pkg_with(20), "PIN")
    refused("a changed byte of the overlay in the package", exe_a, pkg_with(e["offset"] + 5), "wrong hash")
    refused("a truncated package", exe_a, pkg_a[:200], "package refused")

    # the header of the overlay itself
    import struct
    check("the overlay is packed against the image of the base (codec 2)", e["flags"] & 15 == 2)
    raw = R.unpack(pkg_a, e, image[:rec])
    check("the overlay takes bytes from the image of the base", e["len"] < len(R.P.lzma_pack(raw)))
    try:
        other = R.unpack(pkg_a, e, bytes(rec))                 # (the variant base differs in a few bytes only, the overlay may not refer to them: the pin is what binds them)
    except RuntimeError:
        other = None
    check("against another dictionary the overlay does not come out", other != raw)
    for name, off, val in (("entry point outside the image", 8, 0x801B4000 + len(raw) + 4), ("load address below the overlay region", 12, 0x801B0000),
                           ("wrong image size", 16, len(raw) + 4), ("bss beyond the region", 24, 0x01000000)):
        bad = bytearray(raw)
        bad[off:off + 4] = struct.pack("<I", val)
        try:
            R.parse_overlay(bytes(bad))
            check("overlay header: " + name, False, "was accepted")
        except ValueError:
            check("overlay header: " + name, True)
    print("release tests: %d failed" % fails)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
