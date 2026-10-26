"""The 1024 Sinsemilla points S_j = GroupHash("z.cash:SinsemillaS", I2LEOSP_32(j)) of Orchard (reference code of the Zcash foundation,
build/refzcash), as tests/sinsemilla_table.bin: 1024 x (x, y), 32 bytes little-endian each (64 KB). The signer reads them from files of the
card in slot 2 (PSXXZS01..09) instead of computing a hash to curve for every 10 bits of a note commitment.

  python tools/gen_sinsemilla_table.py                 write tests/sinsemilla_table.bin (about a minute)
  python tools/gen_sinsemilla_table.py <card.mcd>      also put the 9 files on the card image"""
import os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "refshim"), os.path.join(HERE, "..", "build", "refpkgs"), os.path.join(HERE, "..", "build", "refzcash")]
BIN = os.path.join(HERE, "..", "tests", "sinsemilla_table.bin")
PER = 123


def table():
    if os.path.exists(BIN):
        return open(BIN, "rb").read()
    from zcash_test_vectors.orchard.group_hash import group_hash
    out = bytearray()
    for j in range(1024):
        p = group_hash(b"z.cash:SinsemillaS", struct.pack("<I", j))
        out += p.x.s.to_bytes(32, "little") + p.y.s.to_bytes(32, "little")
    open(BIN, "wb").write(out)
    return bytes(out)


def add_to_card(card):
    """put the table on a card image (bytearray) as the files PSXXZS01..09"""
    import psxx_tx
    t = table()
    for k in range((1024 + PER - 1) // PER):
        chunk = t[k * PER * 64:(k + 1) * PER * 64]
        psxx_tx.add_file_raw(card, "PSXXZS", struct.pack("<I", len(chunk)) + bytes(60) + chunk, "PSXX table")


if __name__ == "__main__":
    sys.path.insert(0, HERE)
    t = table()
    print("table:", len(t), "bytes")
    if len(sys.argv) > 1:
        import psxx_tx
        c = psxx_tx.load_card(sys.argv[1])
        add_to_card(c)
        open(sys.argv[1], "wb").write(c)
        print("added to", sys.argv[1])
