#!/usr/bin/env python3
"""Coin images for the PSX UI (coin flip): ui/coin/*.png (two coins side by side) -> hal/psx/coin_data.h

The source is one large picture with the two sides of the coin. Each side is cut out, the near-white background is
replaced by the colour of the coin's rim (so the downscaling leaves no light halo), shrunk to SIZE x SIZE with a
circular mask and reduced to 15 colours + transparent (luminance ramp with Floyd-Steinberg dithering): a 4 bit texture with a 16 entry
CLUT. The header holds the CLUT (16 bit colours, entry 0 = 0 = transparent) and the 4 bit texels of the ring and the two emblems as one stream of
a context model (COIN_CM, decoder hal/psx/coin_cm.h: the left and the upper texel are the context of every bit; 5.8 KB in the payload instead of the
7.1 KB that LZMA made of the packed texels), with the SHA-256 of the texels for tests/test_coin.c; hal/psx/coin.c unpacks them once and uploads them.
On a 640 wide screen the pixels are twice as wide as high, so draw the coin 2 x SIZE wide (textured quad); a flip
animation is then the quad's width following |cos(angle)| with the side changing at the edge-on moment.

Usage: gen_coin.py [--preview out.png]     (SIZE below)
"""
import glob, hashlib, os, sys
import numpy as np
from PIL import Image, ImageFilter

HERE = os.path.dirname(os.path.abspath(__file__))
SRC_GLOB = os.path.join(HERE, "..", "ui", "coin", "*.png")
OUT = os.path.join(HERE, "..", "hal", "psx", "coin_data.h")
SIZE = 112
RIM = (110, 80, 35)          # fill for the background before shrinking
NAMES = ("heads", "tails")   # left half: crown, right half: XMR
IN = 80                      # the emblem textures: IN x IN texels
R_IN = 39.0                  # the emblem is the circle of this radius (texels); the ring is the rest


def load():
    path = sorted(glob.glob(SRC_GLOB))[0]
    im = Image.open(path).convert("RGB")
    a = np.array(im).astype(int)
    fg = np.abs(a - np.array([245, 245, 245])).sum(axis=2) > 60
    w = im.width
    sides = []
    for x0, x1 in ((0, w // 2), (w // 2, w)):
        ys, xs = np.where(fg[:, x0:x1])
        box = (xs.min() + x0, ys.min(), xs.max() + x0 + 1, ys.max() + 1)
        sub = a[box[1]:box[3], box[0]:box[2]].copy()
        sub[~fg[box[1]:box[3], box[0]:box[2]]] = RIM
        c = Image.fromarray(sub.astype("uint8"), "RGB")
        s = max(c.size)
        sq = Image.new("RGB", (s, s), RIM)
        sq.paste(c, ((s - c.width) // 2, (s - c.height) // 2))
        sides.append(sq)
    return sides


def prepare(sq):
    sm = sq.resize((SIZE, SIZE), Image.LANCZOS).filter(ImageFilter.UnsharpMask(radius=1.0, percent=80, threshold=2))
    a = np.array(sm).astype(float)
    Y = 0.299 * a[..., 0] + 0.587 * a[..., 1] + 0.114 * a[..., 2]
    yy, xx = np.mgrid[0:SIZE, 0:SIZE]
    r = SIZE / 2.0
    inside = np.hypot(xx + 0.5 - r, yy + 0.5 - r) <= r - 0.5
    return a, Y, inside


def palette(sides):
    """15 grey-level ramp along the coin's gold: the picture is nearly one hue, so the palette entries are the mean
    colours of 15 luminance levels (1-D k-means), and the dithering (Floyd-Steinberg) works on the luminance only. This
    spends all 16 colours on tonal detail, which looks clearly better than a 3-D median cut at the same size. One palette for both
    sides (and so for the common ring and the two centres, which are drawn next to each other)."""
    vals = np.concatenate([Y[inside] for a, Y, inside in sides])
    n = 15
    c = np.quantile(vals, (np.arange(n) + 0.5) / n)
    for _ in range(40):
        asg = np.abs(vals[:, None] - c[None, :]).argmin(axis=1)
        for k in range(n):
            if (asg == k).any():
                c[k] = vals[asg == k].mean()
        c.sort()
    pal = np.zeros((n, 3))
    sums = np.zeros((n, 3)); cnt = np.zeros(n)
    for a, Y, inside in sides:
        asg = np.abs(Y[..., None] - c[None, None, :]).argmin(axis=2)
        for k in range(n):
            m = inside & (asg == k)
            sums[k] += a[m].sum(axis=0); cnt[k] += m.sum()
    for k in range(n):
        pal[k] = sums[k] / cnt[k] if cnt[k] else (c[k],) * 3
    clut = [0] + [((int(v[0]) >> 3) | ((int(v[1]) >> 3) << 5) | ((int(v[2]) >> 3) << 10) | 0x8000) for v in pal]
    return c, clut


def dither(side, c):
    a, Y, inside = side
    work = Y.copy()
    idx = np.zeros((SIZE, SIZE), int)
    for y in range(SIZE):
        for x in range(SIZE):
            if not inside[y, x]:
                continue
            old = work[y, x]
            k = int(np.abs(c - old).argmin())
            idx[y, x] = k + 1                              # 1..15, 0 is transparent
            e = old - c[k]
            if x + 1 < SIZE: work[y, x + 1] += e * 7 / 16
            if y + 1 < SIZE:
                if x > 0: work[y + 1, x - 1] += e * 3 / 16
                work[y + 1, x] += e * 5 / 16
                if x + 1 < SIZE: work[y + 1, x + 1] += e * 1 / 16
    return idx


class BitCoder:
    """the binary range coder of LZMA with 16 bit probabilities (p: the probability of a 0) and the adaptive model of hal/psx/coin_cm.h, both ways"""

    def __init__(self, data=None):
        self.p, self.n = [32768] * 4096, [0] * 4096
        self.range, self.low, self.cache, self.csize, self.out = 0xFFFFFFFF, 0, 0, 1, bytearray()
        if data is not None:
            self.data, self.at = data, 4
            self.code = int.from_bytes(data[:4], "big")

    def _shift(self):
        if self.low < 0xFF000000 or self.low >= 1 << 32:
            carry, c = self.low >> 32, self.cache
            while True:
                self.out.append((c + carry) & 0xFF)
                c = 0xFF
                self.csize -= 1
                if not self.csize:
                    break
            self.cache = (self.low >> 24) & 0xFF
        self.csize += 1
        self.low = (self.low & 0x00FFFFFF) << 8

    def _adapt(self, k, b):
        q, c = self.p[k], self.n[k]
        d = min(c, 30) + 2
        self.p[k] = q - q // d if b else q + (65536 - q) // d
        if c < 30:
            self.n[k] = c + 1

    def encode(self, k, b):
        bound = (self.range >> 16) * self.p[k]
        if b:
            self.low += bound
            self.range -= bound
        else:
            self.range = bound
        self._adapt(k, b)
        while self.range < 1 << 24:
            self.range = (self.range << 8) & 0xFFFFFFFF
            self._shift()

    def decode(self, k):
        bound = (self.range >> 16) * self.p[k]
        b = int(self.code >= bound)
        if b:
            self.code -= bound
            self.range -= bound
        else:
            self.range = bound
        self._adapt(k, b)
        while self.range < 1 << 24:
            self.range = (self.range << 8) & 0xFFFFFFFF
            self.code = ((self.code << 8) | (self.data[self.at] if self.at < len(self.data) else 0)) & 0xFFFFFFFF
            self.at += 1
        return b

    def finish(self):
        for _ in range(5):
            self._shift()
        assert self.out[0] == 0
        return bytes(self.out[1:])                     # the first byte is always 0 (coin_cm.h leaves it out)


def cm_texels(images, coder, decode=False):
    """the texels of the images (2D arrays of 4 bit indexes) through the context model, row by row; with decode the arrays are filled in"""
    for im in images:
        h, w = im.shape
        for y in range(h):
            for x in range(w):
                ctx = ((int(im[y, x - 1]) if x else 0) << 4 | (int(im[y - 1, x]) if y else 0)) << 4
                node = 1
                for b in range(3, -1, -1):
                    if decode:
                        bit = coder.decode(ctx + node)
                    else:
                        bit = (int(im[y, x]) >> b) & 1
                        coder.encode(ctx + node, bit)
                    node = node << 1 | bit
                if decode:
                    im[y, x] = node & 15


def main():
    srcs = [prepare(sq) for sq in load()]
    c, clut = palette(srcs)
    idx = [dither(sd, c) for sd in srcs]
    yy, xx = np.mgrid[0:SIZE, 0:SIZE]
    d = np.hypot(xx + 0.5 - SIZE / 2.0, yy + 0.5 - SIZE / 2.0)
    centre = d < R_IN                                       # the emblem; outside it the two sides have the same rim text, stars and ring
    ring = np.where(centre, 0, idx[0])                      # one ring for both: taken from the heads side
    lo = (SIZE - IN) // 2
    cen = [np.where(centre, ix, 0)[lo:lo + IN, lo:lo + IN] for ix in idx]
    images = [np.array(ring, np.uint8), np.array(cen[0], np.uint8), np.array(cen[1], np.uint8)]
    enc = BitCoder()
    cm_texels(images, enc)
    cm = enc.finish()
    back = [np.zeros_like(im) for im in images]
    cm_texels(back, BitCoder(cm), decode=True)
    assert all((a == b).all() for a, b in zip(images, back)), "the context model does not give the texels back"
    texels = b"".join(im.tobytes() for im in images)                     # one byte per texel, as coin_cm_decode writes them

    with open(OUT, "w", newline="\n") as f:
        f.write("#pragma once\n/* Generated by tools/gen_coin.py from ui/coin -- do not edit.\n"
                " * 4 bit textures with one 16 entry CLUT (entry 0 = transparent). The two sides have the same rim (the ring with the text and the stars): the ring is one\n"
                " * %d x %d texel texture with a hole, drawn for both sides; the emblems are two %d x %d texel textures (the circle of radius %.1f), drawn on top of the ring.\n"
                " * COIN_CM: the ring, the crown and the XMR as one stream of the context model of coin_cm.h (%d bytes for %d texels); COIN_TEXELS_SHA256 is the hash of\n"
                " * the texels it gives, one byte each. */\n"
                "#include <stdint.h>\n\n#define COIN_SIZE %d\n#define COIN_WORDS (COIN_SIZE * COIN_SIZE / 4)\n#define COIN_IN %d\n#define COIN_IN_WORDS (COIN_IN * COIN_IN / 4)\n"
                "#define COIN_TEXELS_SHA256 \"%s\"\n\n"
                % (SIZE, SIZE, IN, IN, R_IN, len(cm), len(texels), SIZE, IN, hashlib.sha256(texels).hexdigest()))
        f.write("static const uint16_t COIN_CLUT[16] = {%s};\n" % ", ".join("0x%04x" % v for v in clut))
        f.write("static const uint8_t COIN_CM[%d] = {\n" % len(cm))
        for i in range(0, len(cm), 24):
            f.write("\t" + ",".join("0x%02x" % b for b in cm[i:i + 24]) + ",\n")
        f.write("};\n")
    print("wrote", OUT, "(ring %d x %d + 2 x %d x %d texels: %d bytes of the context model + 1 CLUT)" % (SIZE, SIZE, IN, IN, len(cm)))
    out = [("heads", np.where(centre, idx[0], ring), clut), ("tails", np.where(centre, idx[1], ring), clut)]

    if "--preview" in sys.argv:
        path = sys.argv[sys.argv.index("--preview") + 1]
        bg = (20, 20, 60)
        z = 4
        sheet = Image.new("RGB", ((2 * SIZE * 2 + 8) * z // 2 + 8, SIZE * z + 8), bg)
        x = 4
        for name, idx, clut in out:
            img = Image.new("RGB", (SIZE, SIZE), bg)
            px = img.load()
            for y in range(SIZE):
                for xx in range(SIZE):
                    i = idx[y, xx]
                    if i:
                        c = clut[i]
                        px[xx, y] = (((c & 31) << 3), (((c >> 5) & 31) << 3), (((c >> 10) & 31) << 3))
            wide = img.resize((SIZE * 2 * z // 2, SIZE * z), Image.NEAREST)   # 2:1 pixels
            sheet.paste(wide, (x, 4)); x += wide.width + 8
        sheet.save(path)


if __name__ == "__main__":
    main()
