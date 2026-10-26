#!/usr/bin/env python3
"""Convert a fixed-size BDF bitmap font (ASCII, Latin-1, Latin Extended-A/B) into hal/psx/font_bdf.h and
hal/psx/kb_variants.h (and copy its licence next to it).

  python tools/gen_bdf_font.py --bdf tools/font_dl_terminus/src/terminus-font-4.49.1/ter-u18b.bdf \\
         --license tools/font_dl_terminus/src/terminus-font-4.49.1/OFL.TXT --name "Terminus 4.49.1 10x18 bold"
  python tools/gen_bdf_font.py --preview      -> build/preview/bitmap_fonts.png (candidates side by side)

Table format: FONT_RUNS[m] = {first code point, count} runs of the sorted code points, FONT_BDF[n][CELL_H] of uint16_t, one value per pixel row, bit 15 = leftmost
pixel (fonts up to 16 pixels wide).
"""
import argparse, os, shutil, sys

HERE = os.path.dirname(os.path.abspath(__file__))
TERM = os.path.join(HERE, "font_dl_terminus", "src", "terminus-font-4.49.1")


def parse(path):
    """-> (cell_w, cell_h, {code: [row ints, bit 15 = leftmost]})"""
    glyphs, enc, rows, in_bitmap, bbx, w, h = {}, None, [], False, None, 0, 0
    for line in open(path, encoding="utf-8", errors="replace").read().splitlines():
        if line.startswith("FONTBOUNDINGBOX"):
            _, w, h, *_ = line.split(); w, h = int(w), int(h)
        elif line.startswith("ENCODING "): enc = int(line.split()[1])
        elif line == "BITMAP": in_bitmap, rows = True, []
        elif line == "ENDCHAR":
            if enc is not None: glyphs[enc] = rows
            enc, in_bitmap = None, False
        elif in_bitmap:
            nbits = len(line) * 4
            rows.append(int(line, 16) << (16 - nbits))      # left-align into 16 bits
    return w, h, glyphs


def table(path):
    w, h, g = parse(path)
    assert 0 < w <= 16 and 0 < h <= 32
    out = []
    for c in range(0x20, 0x80):
        rows = g.get(c, [0] * h) if c != 0x7F else [0] * h
        assert len(rows) == h, (c, len(rows), h)
        out.append(rows)
    for c in range(0x20, 0x7F): assert c in g, "missing glyph %d" % c
    return w, h, out


def preview():
    from PIL import Image, ImageDraw
    bg, fg = (20, 20, 60), (255, 255, 255)
    lines = ["1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
             "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "npub1l0O1Iijg abcdefghijklmnopqrstuvwxyz"]
    cands = [("Terminus 8x16 normal", "ter-u16n.bdf"), ("Terminus 8x16 bold", "ter-u16b.bdf"),
             ("Terminus 10x18 bold", "ter-u18b.bdf"), ("Terminus 10x20 bold", "ter-u20b.bdf"), ("Terminus 8x14 bold", "ter-u14b.bdf")]
    scale = 3
    tabs = [(n, *table(os.path.join(TERM, f))) for n, f in cands]
    H = sum(len(lines) * (t[2] + 2) + 20 for t in tabs) + 8
    out = Image.new("RGB", (330 * scale, H * scale), bg)
    y = 4
    for name, cw, ch, t in tabs:
        ImageDraw.Draw(out).text((4 * scale, y * scale), "%s  %dx%d  %d chars/line  %d lines" % (name, cw, ch, 288 // cw, 240 // ch), fill=(255, 200, 80))
        y += 16
        for line in lines:
            row = Image.new("RGB", (330, ch + 2), bg); px = row.load()
            for i, c in enumerate(line):
                for r, bits in enumerate(t[min(max(ord(c), 32), 127) - 32]):
                    for x in range(cw):
                        xx = 8 + i * cw + x
                        if (bits >> (15 - x)) & 1 and xx < 330: px[xx, r + 1] = fg
            out.paste(row.resize((330 * scale, (ch + 2) * scale), Image.NEAREST), (0, y * scale))
            y += ch + 2
        y += 6
    os.makedirs(os.path.join(HERE, "..", "build", "preview"), exist_ok=True)
    p = os.path.join(HERE, "..", "build", "preview", "bitmap_fonts.png")
    out.save(p); print("wrote", os.path.normpath(p))


VIET = [0x1A0, 0x1A1, 0x1AF, 0x1B0] + list(range(0x1EA0, 0x1EFA))
UNIFONT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "font_dl", "unifont", "unifont-18.0.01.hex.gz")


def add_vietnamese(g, h):
    """Terminus lacks most of the Vietnamese letters: the missing ones come from Unifont (8 x 16, GPL / OFL), placed on the baseline of the 10 x 18 cell and made bold
    horizontally (a pixel is copied one to the right) to match the weight of Terminus bold."""
    import gzip
    need = set(c for c in VIET if c not in g)
    ref = g[ord("x")]
    bottom = max(i for i, r in enumerate(ref) if r)                      # the last row of an x in the cell
    dy = bottom - 13                                                     # in Unifont the last row of an x is 13
    assert 0 <= dy and 16 + dy <= h, dy
    with gzip.open(UNIFONT, "rt") as f:
        for line in f:
            cp, hx = line.strip().split(":")
            c = int(cp, 16)
            if c in need:
                assert len(hx) == 32, "U+%04X is not an 8 x 16 glyph" % c
                rows = [int(hx[i:i + 2], 16) for i in range(0, 32, 2)]
                out = [0] * dy + [((b << 8) >> 1) | ((b << 8) >> 2) for b in rows]
                g[c] = out + [0] * (h - len(out))
                need.discard(c)
    assert not need, "Unifont lacks %s" % ", ".join("U+%04X" % c for c in sorted(need))


def glyph_codes(g):
    """Code points shipped in the font: ASCII, Latin-1 (without NBSP and the soft hyphen), Latin Extended-A and the
    Latin Extended-B letters the font has."""
    cps = list(range(0x20, 0x7F)) + [c for c in range(0xA1, 0x100) if c != 0xAD] + list(range(0x100, 0x180)) \
        + [c for c in range(0x180, 0x250) if c in g] \
        + [c for c in list(range(0x400, 0x460)) + [0x490, 0x491] if c in g] \
        + [c for c in [0x1A0, 0x1A1, 0x1AF, 0x1B0] + list(range(0x1EA0, 0x1EFA))]      # Cyrillic (Russian, Ukrainian, Belarusian, Bulgarian, Serbian, Macedonian), Vietnamese
    cps = sorted(set(cps))
    for c in cps:
        assert c in g, "missing glyph U+%04X" % c
    return cps


# letters that do not decompose (NFD) into a base letter plus accent, and symbols, for the keyboard's popup row
EXTRA_BASE = {
    "æ": "a", "Æ": "A", "ǣ": "a", "Ǣ": "A", "ǽ": "a", "Ǽ": "A", "œ": "o", "Œ": "O", "ø": "o", "Ø": "O", "ǿ": "o", "Ǿ": "O",
    "ß": "s", "ſ": "s", "đ": "d", "Đ": "D", "ð": "d", "Ð": "D", "þ": "t", "Þ": "T", "ŧ": "t", "Ŧ": "T", "ł": "l", "Ł": "L",
    "ŋ": "n", "Ŋ": "N", "ŉ": "n", "ƞ": "n", "Ɲ": "N", "ħ": "h", "Ħ": "H", "ı": "i", "İ": "I", "ĳ": "i", "Ĳ": "I", "ĸ": "k",
    "ƒ": "f", "ǥ": "g", "Ǥ": "G", "ƶ": "z", "Ƶ": "Z", "Ʒ": "Z", "Ǯ": "Z", "ǯ": "z", "ȷ": "j", "ǰ": "j", "Ə": "E", "Ǝ": "E",
    "Ɛ": "E", "Ɔ": "O", "ª": "a", "º": "o", "©": "c", "®": "r", "µ": "u", "ɡ": "g", "Ŀ": "L", "ŀ": "l",
    "¡": "!", "¿": "?", "¢": "$", "£": "$", "¤": "$", "¥": "$", "±": "+", "×": "*", "÷": "/", "«": "<", "»": ">",
    "·": ".", "°": "0", "¹": "1", "¼": "1", "½": "1", "²": "2", "³": "3", "¾": "3", "´": "'", "¨": "\"", "¯": "^", "¸": ",",
    "§": "&", "¶": "&", "¦": "|", "¬": "~", "¢": "$",
}


def variants(cps):
    """base character -> string of the shipped characters that belong on its key (popup row of the keyboard)"""
    import unicodedata
    out = {}
    for c in cps:
        ch = chr(c)
        if c < 0x80:
            continue
        base = EXTRA_BASE.get(ch)
        if base is None:
            d = unicodedata.normalize("NFD", ch)
            if len(d) > 1 and d[0].isascii() and d[0].isalpha():
                base = d[0]
        if base is None:
            return_missing.append(ch)
            continue
        out.setdefault(base, []).append(ch)
    return out


return_missing = []


def write(bdf, lic, name):
    w, h, g = parse(bdf)
    assert 0 < w <= 16 and 0 < h <= 32
    add_vietnamese(g, h)
    cps = glyph_codes(g)
    assert cps == sorted(cps)
    dst = os.path.join(HERE, "..", "hal", "psx")
    with open(os.path.join(dst, "font_bdf.h"), "w", newline="\n") as f:
        f.write("#pragma once\n/* Generated by tools/gen_bdf_font.py -- do not edit.\n * %s, %d glyphs: ASCII 0x20..0x7E, Latin-1, Latin Extended-A, the "
                "Latin Extended-B letters the font has, Cyrillic U+0400..045F and U+0490/0491, Vietnamese; %dx%d pixels per character; licence: LICENSE.font.\n"
                " * FONT_RUNS: the code points as runs of consecutive ones (first, count), in order; FONT_BDF: one uint16_t per pixel row, bit 15 = leftmost pixel. */\n" % (name, len(cps), w, h))
        f.write("#define FONT_BDF_CELL_W %d\n#define FONT_BDF_CELL_H %d\n#define FONT_NGLYPHS %d\n" % (w, h, len(cps)))
        runs = []                                                    # runs of consecutive code points: {first code point, count}; the glyphs follow in this order
        for c in cps:
            if runs and c == runs[-1][0] + runs[-1][1]:
                runs[-1][1] += 1
            else:
                runs.append([c, 1])
        f.write("#define FONT_NRUNS %d\nstatic const unsigned short FONT_RUNS[FONT_NRUNS][2] = {\n" % len(runs))
        for i in range(0, len(runs), 6):
            f.write("    " + ", ".join("{0x%04x, %d}" % (a, n) for a, n in runs[i:i + 6]) + ",\n")
        f.write("};\n")
        f.write("static const unsigned short FONT_BDF[FONT_NGLYPHS][%d] = {\n" % h)
        for c in cps:
            rows = g[c]
            assert len(rows) == h, (c, len(rows), h)
            f.write("    {%s},  /* U+%04X */\n" % (", ".join("0x%04x" % r for r in rows), c))
        f.write("};\n")
    shutil.copyfile(lic, os.path.join(dst, "LICENSE.font"))
    print("wrote font_bdf.h: %s %dx%d, %d glyphs, %d bytes of table" % (name, w, h, len(cps), len(cps) * h * 2))

    v = variants(cps)
    if return_missing:
        print("not reachable through a base key:", " ".join("U+%04X" % ord(c) for c in return_missing))
    with open(os.path.join(dst, "kb_variants.h"), "w", newline="\n", encoding="utf-8") as f:
        f.write("#pragma once\n/* Generated by tools/gen_bdf_font.py -- do not edit. Characters of the font that are typed through a base key of the\n"
                " * keyboard (popup row). UTF-8, in code point order. */\n")
        f.write("static const struct { char base; const char *chars; } KB_VARIANTS[] = {\n")
        bs = chr(92)
        for base in sorted(v):
            esc = "".join("".join("%sx%02x" % (bs, b) for b in ch.encode("utf-8")) for ch in v[base])
            lit = bs + base if base == "'" else base
            f.write("    {'%s', \"%s\"},   /* %s */\n" % (lit, esc, "".join(v[base])))
        f.write("};\n#define KB_NVARIANTS (sizeof KB_VARIANTS / sizeof KB_VARIANTS[0])\n")
    print("wrote kb_variants.h: %d base keys, %d characters" % (len(v), sum(len(x) for x in v.values())))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--preview", action="store_true")
    ap.add_argument("--bdf"); ap.add_argument("--license"); ap.add_argument("--name", default="bitmap font")
    a = ap.parse_args()
    if a.preview: preview()
    else: write(a.bdf, a.license, a.name)
