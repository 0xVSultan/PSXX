"""Test vectors of the overlay loader core (core/pkg/ovl.c) for tests/test_ovl.c (tests/ovl_vectors.txt): synthetic overlays in packages, good ones and ones that have to be refused.

  py -3.13 tools/gen_ovl_vectors.py

Line:  name|region lo|region hi|base id|pin|group|expect|image sha256|package hex[|code lo,code hi,bss lo,bss hi,stage lo,stage hi or -[|dictionary hex]]
  expect: OK, BASE, GROUP, CODEC, OVERLAY, LAYOUT, PKG; for OK the image sha256 is the hash of the unpacked image (all of it, header included), for the others -.
The region is in the line, so the test cases can be small. The last (optional) field cuts the region into the ranges of a layout with slots and pockets (hal/psx/memmap.h): where the image,
the bss and the staged packed bytes may be; without it the whole region is each of them. The dictionary field is the image of the base the loader gives to the unpacker (the preset
dictionary of a group of codec 2, PKG_CODEC_LZMA_BASE). The packages are built by tools/pkg_pack.py (the real packer, liblzma for codec 2), the images by this script: a 32 byte
header like the one of hal/psx/ovl.ld ("PSXO", 1, entry, load, size, bss, bss size, 0) and bytes that look like code."""
import hashlib, os, random, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pkg_pack as P
TESTKEY = hashlib.sha256(b"psxx test signing key").digest()               # a fixed key of its own for the vectors (tools/sign_key.py is the key of the releases)

rng = random.Random(20261023)
LO, HI = 0x801B4000, 0x801C4000                      # a region of 64 KB for most cases
BASE = hashlib.sha256(b"base for the overlay tests").digest()
rows = []


def code(n, compressible=True):
    if compressible:
        words = [rng.randrange(1 << 32) for _ in range(16)]
        return b"".join(struct.pack("<I", words[rng.randrange(16)]) for _ in range(n // 4))
    return bytes(rng.randrange(256) for _ in range(n))


def image(size, load=LO, entry=None, bss=None, bss_size=64, version=1, magic=b"PSXO", reserved=0, compressible=True):
    entry = load + 32 if entry is None else entry
    bss = load + size if bss is None else bss
    return magic + struct.pack("<7I", version, entry, load, size, bss, bss_size, reserved) + code(size - 32, compressible)


def add(name, img, expect, lo=LO, hi=HI, base=BASE, group=1, codec="lzma", asked_group=None, flags=None, pin_base=None, ranges=None, pack_dict=None, give_dict=None):
    """pack_dict: the dictionary the group is packed against (codec lzma_base); give_dict: the one the loader gets (default: the same)"""
    groups = [(group, img, codec)]
    pkg, pin = P.build(P.KIND["overlay"], groups, pin_base or BASE, base_image=pack_dict, key=TESTKEY)
    give = pack_dict if give_dict is None else give_dict
    if flags is not None:                                         # a table with other flags, signed again
        d = bytearray(pkg)
        d[P.HEADER + 2:P.HEADER + 4] = struct.pack("<H", flags)
        pkg = bytes(d)
        pkg, pin = P.resign(pkg, TESTKEY)
    sha = hashlib.sha256(img).hexdigest() if expect == "OK" else "-"
    tail = "|" + ",".join(str(x) for x in ranges) if ranges else ""
    if give:
        tail = (tail or "|-") + "|" + give.hex()
    rows.append("%s|%d|%d|%s|%s|%d|%s|%s|%s%s" % (name, lo, hi, base.hex(), pin.hex(), asked_group or group, expect, sha, pkg.hex(), tail))


add("ok_small", image(512), "OK")
add("ok_no_bss", image(1024, bss_size=0), "OK")
add("ok_bss_at_the_end_of_the_region", image(1024, bss=HI - 64, bss_size=64), "OK")
add("ok_bss_gap", image(1024, bss=LO + 4096, bss_size=128), "OK")
add("ok_load_above_the_start", image(1024, load=LO + 0x100), "OK")
add("ok_large", image(40000), "OK")
add("ok_minimum", image(36), "OK")
add("ok_group_5", image(512), "OK", group=5)

add("base_other", image(512), "BASE", base=hashlib.sha256(b"another base").digest(), pin_base=BASE)
add("group_missing", image(512), "GROUP", asked_group=9)
add("codec_stored", image(512), "CODEC", codec="stored")
add("codec_lc_lp_above_4", image(512), "CODEC", flags=1 | (22 << 4))                                  # lc 4, lp 2: more than the unpacker has room for
add("ok_other_props", image(4096), "OK", codec="lzma_best")                                           # lc, lp, pb of the group
add("header_magic", image(512, magic=b"PSXQ"), "OVERLAY")
add("header_version", image(512, version=2), "OVERLAY")
add("header_reserved", image(512, reserved=1), "OVERLAY")
add("entry_in_header", image(512, entry=LO + 8), "OVERLAY")
add("entry_beyond_image", image(512, entry=LO + 512), "OVERLAY")
add("entry_unaligned", image(512, entry=LO + 34), "OVERLAY")
add("bss_inside_image", image(512, bss=LO + 256), "OVERLAY")
add("bss_unaligned", image(512, bss=LO + 514), "OVERLAY")
add("bss_beyond_region", image(512, bss=HI - 32, bss_size=64), "OVERLAY")
add("bss_start_beyond_region", image(512, bss=HI + 64, bss_size=0), "OVERLAY")
add("size_not_rawlen", image(512).replace(struct.pack("<I", 512), struct.pack("<I", 508), 1), "LAYOUT")   # the size field of the header says 508, the group 512 bytes
add("load_below_region", image(512, load=LO - 0x1000, entry=LO - 0x1000 + 32, bss=LO - 0x1000 + 512), "LAYOUT")
add("load_unaligned", image(512, load=LO + 2, entry=LO + 34, bss=LO + 514), "LAYOUT")
add("image_into_staging", image(3000, compressible=False), "LAYOUT", lo=LO, hi=LO + 4096)            # 3000 packed bytes at the end leave no room for 3000
add("image_beyond_region", image(8000, load=LO + 0x1000), "LAYOUT", lo=LO, hi=LO + 0x2000)
add("region_too_small_for_the_group", image(3000, compressible=False), "LAYOUT", lo=LO, hi=LO + 2000)

# slots and pockets: a region of 256 KB, the image in a slot at the start, the bss in a pocket (above, or below the slot), the packed bytes staged in a scratch range of their own
R_LO, R_HI = LO, LO + 0x40000
SLOT = (R_LO, R_LO + 0x8000)
POCKET = (R_LO + 0x10000, R_LO + 0x14000)
SCRATCH = (R_LO + 0x20000, R_LO + 0x28000)
RG = SLOT + POCKET + SCRATCH
add("slot_bss_in_pocket", image(4096, load=R_LO, bss=POCKET[0], bss_size=0x1000), "OK", lo=R_LO, hi=R_HI, ranges=RG)
add("slot_bss_whole_pocket", image(4096, load=R_LO, bss=POCKET[0], bss_size=0x4000), "OK", lo=R_LO, hi=R_HI, ranges=RG)
add("slot_bss_over_the_staged_bytes", image(4096, load=R_LO, bss=SCRATCH[0], bss_size=0x8000), "OK", lo=R_LO, hi=R_HI, ranges=SLOT + SCRATCH + SCRATCH)
add("slot_bss_below_the_slot", image(4096, load=R_LO + 0x10000, bss=R_LO, bss_size=64), "OK", lo=R_LO, hi=R_HI, ranges=(R_LO + 0x10000, R_LO + 0x18000, R_LO, R_LO + 0x1000) + SCRATCH)
add("slot_image_in_the_second_slot", image(4096, load=R_LO + 0x8000, bss=R_LO + 0x8000 + 4096, bss_size=64), "OK", lo=R_LO, hi=R_HI, ranges=(R_LO + 0x8000, R_LO + 0x10000, R_LO + 0x8000, R_LO + 0x10000) + SCRATCH)
add("slot_bss_outside_its_range", image(4096, load=R_LO, bss=POCKET[1] - 32, bss_size=64), "OVERLAY", lo=R_LO, hi=R_HI, ranges=RG)
add("slot_bss_in_the_code_slot_not_allowed", image(4096, load=R_LO, bss=R_LO + 4096, bss_size=64), "OVERLAY", lo=R_LO, hi=R_HI, ranges=RG)
add("slot_bss_start_before_its_range", image(4096, load=R_LO, bss=POCKET[0] - 64, bss_size=64), "OVERLAY", lo=R_LO, hi=R_HI, ranges=RG)
add("slot_image_beyond_the_slot", image(0x9000, load=R_LO), "LAYOUT", lo=R_LO, hi=R_HI, ranges=RG)
add("slot_load_in_the_next_slot", image(4096, load=R_LO + 0x8000, bss=POCKET[0], bss_size=64), "LAYOUT", lo=R_LO, hi=R_HI, ranges=RG)
add("slot_group_larger_than_the_scratch", image(0x9000, compressible=False), "LAYOUT", lo=R_LO, hi=R_HI, ranges=SLOT + POCKET + (SCRATCH[0], SCRATCH[0] + 0x2000))
add("slot_scratch_on_the_slot", image(3000, compressible=False), "LAYOUT", lo=R_LO, hi=R_HI, ranges=(R_LO, R_LO + 4096) + POCKET + (R_LO, R_LO + 4096))
add("slot_ranges_outside_the_region", image(4096, load=R_LO, bss=POCKET[0], bss_size=64), "LAYOUT", lo=R_LO, hi=R_LO + 0x20000, ranges=RG)
add("slot_empty_range", image(4096, load=R_LO, bss=POCKET[0], bss_size=64), "LAYOUT", lo=R_LO, hi=R_HI, ranges=(R_LO, R_LO + 0x8000, POCKET[0], POCKET[0] + 0, SCRATCH[0], SCRATCH[1]))

# codec 2: packed against a dictionary (the image of the base). The first one finds the whole overlay, its header included, in the dictionary: the stream starts with a match
# into it; the second one takes pieces of the dictionary between bytes of its own, the third one is a stream of its own with an unused dictionary
filler = code(6000, False)
img_whole = image(2048)
dict_whole = filler + img_whole + code(2000, False)
img_mixed = image(8192)
dict_mixed = code(4096) + img_mixed[4000:6000] + code(1024, False)
body = bytearray()
while len(body) < 4096 - 32:
    at = rng.randrange(len(dict_mixed) - 200)
    body += dict_mixed[at:at + rng.randrange(8, 200)] + code(rng.randrange(1, 16) * 4, False)
img_pieces = image(4096)[:32] + bytes(body[:4096 - 32])
add("dict_whole_image_in_the_dictionary", img_whole, "OK", codec="lzma_base", pack_dict=dict_whole)
add("dict_pieces", img_pieces, "OK", codec="lzma_base", pack_dict=dict_mixed)
add("dict_not_used", image(4096, compressible=False), "OK", codec="lzma_base", pack_dict=dict_mixed)
add("dict_slot_bss_in_pocket", image(4096, load=R_LO, bss=POCKET[0], bss_size=0x1000), "OK", lo=R_LO, hi=R_HI, ranges=RG, codec="lzma_base", pack_dict=dict_mixed)
add("dict_given_to_plain_lzma", image(512), "OK", give_dict=dict_mixed)
add("dict_missing", img_whole, "CODEC", codec="lzma_base", pack_dict=dict_whole, give_dict=b"")
add("dict_length_not_a_multiple_of_4", img_whole, "CODEC", codec="lzma_base", pack_dict=dict_whole, give_dict=dict_whole[:-1])

with open(os.path.join(HERE, "..", "tests", "ovl_vectors.txt"), "w") as fh:
    fh.write("# generated by tools/gen_ovl_vectors.py: name|region lo|region hi|base id|pin|group|expect|image sha256|package hex\n")
    fh.write("\n".join(rows) + "\n")
print("%d vectors written" % len(rows))
