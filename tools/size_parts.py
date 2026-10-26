"""What parts of the signer take how much of the image and of the compressed payload (the symbols of the ELF grouped by source file; the
image is compressed again without the ranges of the chosen parts).  python tools/size_parts.py"""
import collections, lzma, os, re, struct, subprocess

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
ELF = os.path.join(ROOT, "build", "psx", "psxx_signer.elf")
EXE = os.path.join(ROOT, "build", "psx", "psxx_signer.exe")
NM = os.path.join(ROOT, "toolchain", "gcc", "bin", "mipsel-none-elf-nm.exe")
STUB = 1572

out = subprocess.run([NM, "-S", "-l", "-n", ELF], capture_output=True, text=True).stdout
b = open(EXE, "rb").read()
pc, gp, taddr, tsize = struct.unpack_from("<4I", b, 0x10)
img = b[0x800:0x800 + tsize]
syms = []
for l in out.splitlines():
    m = re.match(r"([0-9a-f]+) ([0-9a-f]+) (\w) (\S+)\s*(\S*)", l)
    if not m:
        continue
    addr, size, t, name, src = int(m.group(1), 16) & 0xffffffff, int(m.group(2), 16), m.group(3), m.group(4), m.group(5)
    if addr < taddr or addr + size > taddr + tsize or size == 0:
        continue
    srcname = os.path.basename(src.rsplit(":", 1)[0].replace(chr(92), "/")) if src else name
    syms.append((addr, size, name, srcname))


def lz(d):
    return len(lzma.compress(bytes(d), format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "preset": 9 | lzma.PRESET_EXTREME, "dict_size": 1 << 18,
                "lc": 1, "lp": 2, "pb": 2, "nice_len": 273, "mf": lzma.MF_BT4, "depth": 1000}]))


def payload(c):
    return (c + STUB + 127) // 128 * 128


agg = collections.defaultdict(int)
for a, sz, n, s in syms:
    agg[s] += sz
print("the biggest parts of the image (bytes, by source file or symbol):")
for k, v in sorted(agg.items(), key=lambda x: -x[1])[:34]:
    print("  %-30s %7d" % (k, v))
base = lz(img)
print("\nwhole image %d B -> %d B, payload %d B (limit 122752)\n" % (len(img), base, payload(base)))


def without(names):
    mask = bytearray(len(img))
    for a, sz, n, s in syms:
        if n in names or s in names:
            o = a - taddr
            for i in range(o, min(o + sz, len(img))):
                mask[i] = 1
    rest = bytes(x for x, m in zip(img, mask) if not m)
    return sum(mask), lz(rest)


CURVE = {"ed25519.c", "ed25519_sign.c", "secp256k1.c", "secp256k1_sign.c", "pallas.c", "poseidon.c", "bn_comba.c", "POS_RC", "POS_MDS"}
SHIELDED = {"orchard.c", "orchard_out.c", "redpallas.c", "xmr.c", "zec.c", "chacha20poly1305.c"}
for label, names in [
        ("icons", {"ICON_PIX", "ICON_PAL", "ICON_RECT"}),
        ("the font", {"FONT_BDF"}),
        ("the word lists (BIP39, Monero)", {"BIP39_EN", "XMR_EN"}),
        ("icons + font + word lists", {"ICON_PIX", "ICON_PAL", "ICON_RECT", "FONT_BDF", "BIP39_EN", "XMR_EN"}),
        ("icons + word lists (the font stays)", {"ICON_PIX", "ICON_PAL", "ICON_RECT", "BIP39_EN", "XMR_EN"}),
        ("the curve mathematics (ed25519, secp256k1, Pallas, Poseidon, the 256 bit multiplier)", CURVE),
        ("curve mathematics + the signers that use it (Orchard, Monero, Zcash)", CURVE | SHIELDED),
        ("icons + word lists + curve mathematics", {"ICON_PIX", "ICON_PAL", "ICON_RECT", "BIP39_EN", "XMR_EN"} | CURVE)]:
    removed, c = without(names)
    print("%-84s -%7d B image, payload %7d (saves %6d)" % (label, removed, payload(c), payload(base) - payload(c)))


# the split in two programs: what would be loaded from the second card (the signing modules and their screens), what stays with the generator
OVERLAY = {"signer_app.c", "dispatch.c", "txview.c", "btc.c", "evm.c", "tron.c", "xrp.c", "cosmos.c", "nostr.c", "nip19.c", "nip44.c", "solana.c", "stellar.c", "near.c",
           "polkadot.c", "ton.c", "ada.c", "zec.c", "xmr.c", "redpallas.c", "orchard_out.c", "chacha20poly1305.c", "poseidon.c", "POS_RC", "POS_MDS"}
mask = bytearray(len(img))
for a, sz, n, s in syms:
    if n in OVERLAY or s in OVERLAY:
        o = a - taddr
        for i in range(o, min(o + sz, len(img))):
            mask[i] = 1
ov = bytes(x for x, m in zip(img, mask) if m)
rest = bytes(x for x, m in zip(img, mask) if not m)
print("\nsplit: the signing modules and their screens as a program loaded from the second card:")
print("  loaded part: %d B in the image, %d B compressed (%d memory card blocks of 7936 B)" % (len(ov), lz(ov), (lz(ov) + 4 + 7935) // 7936))
print("  what is left of the signer image (curve mathematics, hashes, screens, icons, word lists...): %d B, payload %d B" % (len(rest), payload(lz(rest))))
