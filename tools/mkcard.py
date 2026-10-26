"""Memory card images with files of several blocks, the reference writer and reader of the format that
core/pkg/cardfile.c reads.

  py -3.13 tools/mkcard.py add  <blank.mcd> <out.mcd> --file pkg.bin --tag PSXXPK --number 1 [--title "PSXX package"]
  py -3.13 tools/mkcard.py list <card.mcd>
  py -3.13 tools/mkcard.py read <card.mcd> <name> <out.bin>

Format (PlayStation memory card, 1024 frames of 128 bytes, block n = frames 64n .. 64n+63, frames 1..15 are the directory entries of the blocks 1..15):
  entry: state (0x51 first block of a file, 0x52 middle, 0x53 last, 0xA0 free), 3 zero bytes, size u32 (first block: 8192 per block), next block u16 (the block number minus 1,
         0xFFFF = none), name 20 bytes + 0, zeros, xor of the first 127 bytes
  first block: frame 0 the header ("SC", 0x11 = one icon frame, the number of blocks, the title, palette), frame 1 the icon, the data from frame 2 (62 frames, 7936 bytes);
  the other blocks: 64 frames of data (8192 bytes).  The data of a file is its blocks one after the other, so n blocks hold 8192 n - 256 bytes."""
import argparse, struct, sys

FRAME = 128
BLOCK_DATA_FIRST = 62 * FRAME
BLOCK_DATA = 64 * FRAME


def xor127(b):
    x = 0
    for v in b[:127]:
        x ^= v
    return x


def blank_card():
    """a formatted card without files: the header frame, 15 free entries"""
    d = bytearray(1024 * FRAME)
    d[0:2] = b"MC"
    d[127] = xor127(d[:FRAME])
    for b in range(1, 16):
        e = bytearray(FRAME)
        e[0] = 0xA0
        e[8:10] = bytes([0xFF, 0xFF])
        e[127] = xor127(e)
        d[b * FRAME:(b + 1) * FRAME] = e
    for f in range(16, 36):                      # the sector list of bad frames: none
        d[f * FRAME:f * FRAME + 4] = bytes([0xFF] * 4)
        d[(f + 1) * FRAME - 1] = 0
    return d


def load(path):
    d = bytearray(open(path, "rb").read())
    if len(d) != 1024 * FRAME or d[:2] != b"MC":
        raise SystemExit("%s is not a formatted 128 KB card image" % path)
    return d


def entry(d, b):
    return d[b * FRAME:(b + 1) * FRAME]


def free_blocks(d):
    return [b for b in range(1, 16) if entry(d, b)[0] in (0xA0, 0xA1)]


def capacity(nblocks):
    return nblocks * 8192 - 2 * FRAME


def blocks_needed(nbytes):
    """blocks of a file of nbytes bytes: the first block holds 7936 bytes of data (the header and icon frames), the others 8192"""
    return max(1, -(-(nbytes + 2 * FRAME) // 8192))


def name_of(tag, number):
    assert len(tag) == 6
    return "BESCES-00000%s%02d" % (tag, number)


def add_file(d, name, blob, title="PSXX package", blocks=None):
    """a save file of as many blocks as the data needs (or the given blocks, in the order of the chain); returns the list of the blocks"""
    n = max(1, -(-(len(blob) + 2 * FRAME) // 8192))
    free = free_blocks(d)
    if blocks is None:
        if n > len(free):
            raise SystemExit("not enough free blocks: %d needed, %d free" % (n, len(free)))
        blocks = free[:n]
    assert len(blocks) == n and all(b in free for b in blocks)
    data = blob + b"\0" * (capacity(n) - len(blob))
    for i, b in enumerate(blocks):
        base = 64 * b * FRAME
        if i == 0:
            hdr = bytearray(FRAME)
            hdr[0:4] = b"SC" + bytes([0x11, n])
            t = title.encode()[:60]
            hdr[4:4 + len(t)] = t
            pal = [0, 30 | 24 << 5 | 4 << 10, 24 | 24 << 5 | 26 << 10, 12 | 12 << 5 | 14 << 10, 3 | 5 << 5 | 12 << 10]
            for k, c in enumerate(pal):
                hdr[96 + 2 * k:98 + 2 * k] = struct.pack("<H", c)
            d[base:base + FRAME] = hdr
            icon = bytearray(FRAME)
            for y in range(16):
                for x in range(16):
                    c = 1 if (x in (1, 14) or y in (1, 14)) and 1 <= x <= 14 and 1 <= y <= 14 else 0
                    icon[y * 8 + x // 2] |= c << (4 * (x % 2))
            d[base + FRAME:base + 2 * FRAME] = icon
            chunk, data = data[:BLOCK_DATA_FIRST], data[BLOCK_DATA_FIRST:]
            d[base + 2 * FRAME:base + 64 * FRAME] = chunk
        else:
            chunk, data = data[:BLOCK_DATA], data[BLOCK_DATA:]
            d[base:base + BLOCK_DATA] = chunk
        e = bytearray(FRAME)
        e[0] = 0x51 if i == 0 else (0x53 if i == n - 1 else 0x52)
        e[4:8] = struct.pack("<I", 8192 * n if i == 0 else 0)
        e[8:10] = struct.pack("<H", blocks[i + 1] - 1) if i < n - 1 else b"\xff\xff"
        if i == 0:
            e[10:10 + len(name)] = name.encode()
        e[127] = xor127(e)
        d[b * FRAME:(b + 1) * FRAME] = e
    return blocks


def find_file(d, name):
    """the data of a file (all of its blocks) and the chain; raises ValueError on a damaged chain"""
    for b in range(1, 16):
        e = entry(d, b)
        if e[0] == 0x51 and bytes(e[10:30]).rstrip(b"\0") == name.encode():
            blocks, seen, cur = [b], {b}, b
            while True:
                nxt = struct.unpack("<H", bytes(entry(d, cur)[8:10]))[0]
                if nxt == 0xFFFF:
                    break
                cur = nxt + 1
                if cur in seen or not 1 <= cur <= 15 or entry(d, cur)[0] not in (0x52, 0x53):
                    raise ValueError("damaged chain")
                blocks.append(cur)
                seen.add(cur)
            out = b""
            for i, bl in enumerate(blocks):
                base = 64 * bl * FRAME
                out += bytes(d[base + 2 * FRAME:base + 64 * FRAME] if i == 0 else d[base:base + BLOCK_DATA])
            return out, blocks
    raise ValueError("no such file")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add")
    a.add_argument("blank")
    a.add_argument("out")
    a.add_argument("--file", required=True)
    a.add_argument("--tag", default="PSXXPK")
    a.add_argument("--number", type=int, default=1)
    a.add_argument("--title", default="PSXX package")
    l = sub.add_parser("list")
    l.add_argument("card")
    r = sub.add_parser("read")
    r.add_argument("card")
    r.add_argument("name")
    r.add_argument("out")
    x = ap.parse_args()
    if x.cmd == "add":
        d = load(x.blank)
        blob = open(x.file, "rb").read()
        blocks = add_file(d, name_of(x.tag, x.number), blob, x.title)
        open(x.out, "wb").write(d)
        print("%s: %s, %d bytes in blocks %s" % (x.out, name_of(x.tag, x.number), len(blob), blocks))
    elif x.cmd == "list":
        d = load(x.card)
        for b in range(1, 16):
            e = entry(d, b)
            print("block %2d  state %02x  size %6d  next %5d  %s" % (b, e[0], struct.unpack("<I", bytes(e[4:8]))[0], struct.unpack("<H", bytes(e[8:10]))[0],
                                                                        bytes(e[10:30]).rstrip(b"\0").decode(errors="replace")))
    else:
        data, blocks = find_file(load(x.card), x.name)
        open(x.out, "wb").write(data)
        print("%d bytes from blocks %s" % (len(data), blocks))


if __name__ == "__main__":
    main()
