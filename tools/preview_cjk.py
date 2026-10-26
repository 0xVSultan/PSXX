#!/usr/bin/env python3
"""Pictures of how the glyphs of the language card look on the console screen: the framebuffer of the apps is 640 x 240 (NTSC), whose
pixels a 4:3 television stretches to twice their width in height, so every picture comes twice: `*_fb.png`, the framebuffer as it is, and `*_tv.png`, the same with every line
doubled, what a television shows (an emulator window with aspect correction too).

  python tools/preview_cjk.py            -> build/preview/cjk_*.png

Unifont (SIL OFL 1.1) supplies the 16 x 16 hanzi, kana and hangul, Terminus 10 x 18 bold (the font of the apps) the Latin and Cyrillic letters. The hanzi come in two sizes:
`native` draws a font pixel as one pixel (16 x 16 on the framebuffer: narrow on a television), `wide` as two pixels side by side (32 x 16, square on a television).
"""
import gzip, os, random, sys, unicodedata
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "build", "preview")
UNIFONT = os.path.join(HERE, "font_dl", "unifont", "unifont-18.0.01.hex.gz")
TERMINUS = os.path.join(HERE, "font_dl_terminus", "src", "terminus-font-4.49.1", "ter-u18b.bdf")
LISTS = os.path.join(HERE, "wordlist_dl")
W, H = 640, 240


def load_unifont(needed):
    g = {}
    with gzip.open(UNIFONT, "rt") as f:
        for line in f:
            cp, hexs = line.strip().split(":")
            c = int(cp, 16)
            if c in needed:
                g[c] = (len(hexs) // 2 // 16 * 8, [int(hexs[i:i + len(hexs) // 16], 16) for i in range(0, len(hexs), len(hexs) // 16)])
    return g


def load_terminus():
    glyphs, enc, rows, in_bitmap = {}, None, [], False
    for line in open(TERMINUS, encoding="utf-8", errors="replace").read().splitlines():
        if line.startswith("ENCODING "): enc = int(line.split()[1])
        elif line == "BITMAP": in_bitmap, rows = True, []
        elif line == "ENDCHAR":
            if enc is not None: glyphs[enc] = rows
            enc, in_bitmap = None, False
        elif in_bitmap:
            rows.append(int(line, 16) << (8 if len(line) <= 2 else 0) >> 0 if len(line) <= 2 else int(line, 16))
    return glyphs


class Screen:
    def __init__(self):
        self.im = Image.new("RGB", (W, H), (20, 20, 40))
        self.px = self.im.load()

    def dot(self, x, y, c):
        if 0 <= x < W and 0 <= y < H: self.px[x, y] = c

    def uni(self, g, ch, x, y, sx, col):
        """a Unifont glyph (width 8 or 16) with each font pixel sx pixels wide and one high"""
        if ord(ch) not in g: return 8 * sx
        wbits, rows = g[ord(ch)]
        for r, bits in enumerate(rows):
            for b in range(wbits):
                if bits >> (wbits - 1 - b) & 1:
                    for k in range(sx): self.dot(x + b * sx + k, y + r, col)
        return wbits * sx

    def term(self, t, ch, x, y, col):
        rows = t.get(ord(ch))
        if rows is None: return 10
        for r, bits in enumerate(rows):
            for b in range(10):
                if bits >> (15 - b) & 1: self.dot(x + b, y + r, col)
        return 10

    def text(self, t, s, x, y, col=(255, 255, 255)):
        for ch in s: x += self.term(t, ch, x, y, col)

    def save(self, name):
        os.makedirs(OUT, exist_ok=True)
        self.im.save(os.path.join(OUT, name + "_fb.png"))
        self.im.resize((W, 2 * H), Image.NEAREST).save(os.path.join(OUT, name + "_tv.png"))


def words(name):
    """the words as they are drawn: composed (NFC); the lists are decomposed (NFKD) for the seed, the glyphs are of the composed characters"""
    return [unicodedata.normalize("NFC", w.strip()) for w in open(os.path.join(LISTS, name + ".txt"), encoding="utf-8") if w.strip()]


def main():
    rnd = random.Random(7)
    zh = words("chinese_simplified")
    zht = words("chinese_traditional")
    ja = words("japanese")
    ko = words("korean")
    need = set()
    for lst in (zh, zht, ja, ko):
        for w in lst:
            need.update(ord(c) for c in w)
    uni = load_unifont(need | set(ord(c) for c in "0123456789"))
    ter = load_terminus()
    mn = rnd.sample(zh, 12)

    for tag, sx, cw in (("native", 1, 16), ("wide", 2, 32)):
        # the screen of typing a mnemonic: the words so far, and the grid to choose from
        s = Screen()
        s.text(ter, "Recovery words  (Chinese)", 16, 2)
        s.text(ter, "Word 7 of 12", 16, 22, (150, 160, 200))
        x = 16
        for i, w in enumerate(mn[:6]):
            x += s.uni(uni, w, x, 46, sx, (255, 220, 80)) + 6
        s.text(ter, "Choose the character:", 16, 70, (150, 160, 200))
        grid = sorted(set(c for w in zh for c in w), key=ord)[:1000]
        cols = (W - 32) // cw
        for i, c in enumerate(grid[: cols * 6]):
            gx, gy = 16 + (i % cols) * cw, 94 + (i // cols) * 20
            if i == cols + 3:
                for yy in range(gy - 2, gy + 18):
                    for xx in range(gx - 2, gx + cw): s.dot(xx, yy, (80, 80, 160))
            s.uni(uni, c, gx, gy, sx, (255, 255, 255))
        s.text(ter, "move, X choose, O back", 16, 220, (150, 160, 200))
        s.save("cjk_%s_zh" % tag)

        # the traditional characters and the characters of the other languages at the same size
        s = Screen()
        s.text(ter, "Traditional, Japanese (kana, kanji), Korean (hangul)", 16, 2)
        y = 28
        for line in (" ".join(rnd.sample(zht, 14)), " ".join(rnd.sample(ja, 10)), " ".join(rnd.sample(ko, 10))):
            x = 16
            for ch in line:
                if ch == " ": x += 8; continue
                x += s.uni(uni, ch, x, y, sx, (255, 255, 255)) + (0 if cw == 32 else 1)
            y += 26
        y += 6
        s.text(ter, "Latin and Cyrillic (the font of the apps, 10x18):", 16, y, (150, 160, 200))
        s.text(ter, "abandon ability able about above absent", 16, y + 22)
        s.text(ter, "абакус абзац авангард адвокат", 16, y + 44)
        s.save("cjk_%s_other" % tag)

        # the most crowded characters of the lists: the test of the size
        dense = sorted(set(c for w in zh + zht for c in w if ord(c) in uni), key=lambda c: -sum(bin(r).count("1") for r in uni[ord(c)][1]))[:60]
        s = Screen()
        s.text(ter, "The 60 most crowded characters of the Chinese lists", 16, 2)
        cols = (W - 32) // (cw + 4)
        for i, c in enumerate(dense):
            s.uni(uni, c, 16 + (i % cols) * (cw + 4), 30 + (i // cols) * 22, sx, (255, 255, 255))
        s.save("cjk_%s_dense" % tag)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
