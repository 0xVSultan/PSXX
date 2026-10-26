#!/usr/bin/env python3
"""Controller button icons for the PSX UI: ui/buttons/kenney/Double/*.png -> hal/psx/icons_data.h

Source: Kenney "Input Prompts" (PlayStation), CC0. The 128 px images are cropped to their content, shrunk to fit a text
line (20..30 pixels), blended onto the UI background colour (so the anti-aliased edges look right without alpha
blending on the GPU; fully transparent pixels stay 0 = transparent) and packed into one 16 bit atlas strip of 160
pixels width. The D-pad icons show all four arms; the arm(s) the screen waits for are white, the others dim grey (the
source images mark the active arm red). START and SELECT show the label under the button.

Usage: gen_icons.py [--preview out.png]
Icon order = control characters 1..15 in hal/psx/font.h:
cross circle square triangle start select up down left right updown leftright l1 l2 r1 r2 dpad eyes
(dpad = all four arms white, eyes = a pair of eyes drawn here, "show / hide the whole text")
"""
import os, sys
import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "ui", "buttons", "kenney", "Double")
OUT = os.path.join(HERE, "..", "hal", "psx", "icons_data.h")
BG = (20, 20, 60)            # background of the wallet UI (gpu_init in wallet_app.c)
ATLAS_W = 128                 # the strip is at VRAM (640, 256): x 640..767; the coin page starts at x 768 (coin.c), so the strip must stay narrower than 128 pixels
ROUND = 22                   # face buttons
DPAD = 26
PILL_H = 26                  # START / SELECT including the label
TRIG_H = 22                  # L1 L2 R1
DIM = (92, 98, 128)          # inactive D-pad arms
LIT = (255, 255, 255)        # the arm the screen waits for
COLORS = 32                  # the colours of the whole strip (median cut, no dithering): the anti-aliased edges keep their look and the strip packs 1.2 KB smaller in the payload


def load(name):
    im = Image.open(os.path.join(SRC, name + ".png")).convert("RGBA")
    return im.crop(im.getbbox())


def fit(im, w, h):
    """shrink to fit w x h (keeping the aspect), premultiplied so that edges do not pick up colours from transparent pixels"""
    k = min(w / im.width, h / im.height)
    nw, nh = max(1, round(im.width * k)), max(1, round(im.height * k))
    return im.convert("RGBa").resize((nw, nh), Image.LANCZOS).convert("RGBA")


def recolor_dpad(im):
    """white -> dim grey, red (active arm) -> white; in between by the amount of red"""
    a = np.array(im).astype(float)
    red = np.clip((a[:, :, 0] - a[:, :, 1]) / 150.0, 0, 1)[:, :, None]
    base = np.array(DIM, float)[None, None, :]
    lit = np.array(LIT, float)[None, None, :]
    a[:, :, :3] = base * (1 - red) + lit * red
    return Image.fromarray(a.astype("uint8"), "RGBA")


def pill(name):
    """label above the button in the source: cut at the empty rows between them and put the label under the button"""
    im = load(name)
    a = np.array(im)[:, :, 3]
    blank = [r for r in range(1, im.height - 1) if a[r].max() == 0]
    cut = blank[len(blank) // 2]
    label, shape = im.crop((0, 0, im.width, cut)), im.crop((0, cut, im.width, im.height))
    label, shape = label.crop(label.getbbox()), shape.crop(shape.getbbox())
    gap = 6
    out = Image.new("RGBA", (max(label.width, shape.width), shape.height + gap + label.height), (0, 0, 0, 0))
    out.alpha_composite(shape, ((out.width - shape.width) // 2, 0))
    out.alpha_composite(label, ((out.width - label.width) // 2, shape.height + gap))
    return fit(out, 60, PILL_H)


def eyes():
    """a pair of eyes (view toggle): white eyeballs, blue iris, dark pupil, drawn 8x too big and shrunk for smooth edges"""
    from PIL import ImageDraw
    k = 8
    im = Image.new("RGBA", (64 * k, 30 * k), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    for cx in (16, 48):
        d.ellipse(((cx - 14) * k, 1 * k, (cx + 14) * k, 29 * k), fill=(245, 245, 250, 255))
        d.ellipse(((cx - 7) * k, 6 * k, (cx + 7) * k, 24 * k), fill=(70, 130, 230, 255))
        d.ellipse(((cx - 3.5) * k, 11 * k, (cx + 3.5) * k, 19 * k), fill=(10, 10, 30, 255))
        d.ellipse(((cx - 6) * k, 8 * k, (cx - 2) * k, 12 * k), fill=(255, 255, 255, 255))
    return fit(im, 40, 20)


def icons():
    return [
        ("cross",    fit(load("playstation_button_color_cross"), ROUND, ROUND)),
        ("circle",   fit(load("playstation_button_color_circle"), ROUND, ROUND)),
        ("square",   fit(load("playstation_button_color_square"), ROUND, ROUND)),
        ("triangle", fit(load("playstation_button_color_triangle"), ROUND, ROUND)),
        ("start",    pill("playstation3_button_start")),
        ("select",   pill("playstation3_button_select")),
        ("up",       fit(recolor_dpad(load("playstation_dpad_up")), DPAD, DPAD)),
        ("down",     fit(recolor_dpad(load("playstation_dpad_down")), DPAD, DPAD)),
        ("left",     fit(recolor_dpad(load("playstation_dpad_left")), DPAD, DPAD)),
        ("right",    fit(recolor_dpad(load("playstation_dpad_right")), DPAD, DPAD)),
        ("updown",   fit(recolor_dpad(load("playstation_dpad_vertical")), DPAD, DPAD)),
        ("leftright", fit(recolor_dpad(load("playstation_dpad_horizontal")), DPAD, DPAD)),
        ("l1",       fit(load("playstation_trigger_l1"), 40, TRIG_H)),
        ("l2",       fit(load("playstation_trigger_l2"), 40, TRIG_H)),
        ("r1",       fit(load("playstation_trigger_r1"), 40, TRIG_H)),
        ("r2",       fit(load("playstation_trigger_r2"), 40, TRIG_H)),
        ("dpad",     fit(recolor_dpad(load("playstation_dpad_all")), DPAD, DPAD)),
        ("eyes",     eyes()),
    ]


def pixel(p):
    r, g, b, a = (int(v) for v in p)
    if a < 8:
        return 0
    k = a / 255.0
    r = int(r * k + BG[0] * (1 - k) + 0.5); g = int(g * k + BG[1] * (1 - k) + 0.5); b = int(b * k + BG[2] * (1 - k) + 0.5)
    return (r >> 3) | ((g >> 3) << 5) | ((b >> 3) << 10) | 0x8000


def quantize(data):
    """the opaque pixels of the strip (15 bit values) reduced to COLORS colours; transparent pixels (0) stay 0"""
    opaque = [i for i, v in enumerate(data) if v]
    rgb = np.array([[(data[i] & 31) << 3, ((data[i] >> 5) & 31) << 3, ((data[i] >> 10) & 31) << 3] for i in opaque], dtype=np.uint8)
    im = Image.fromarray(rgb.reshape(1, -1, 3), "RGB").quantize(colors=COLORS, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
    pal = np.array(im.getpalette()[:3 * COLORS]).reshape(-1, 3)
    idx = np.array(im).reshape(-1)
    out = list(data)
    for j, i in enumerate(opaque):
        r, g, b = (int(v) for v in pal[idx[j]])
        out[i] = (r >> 3) | ((g >> 3) << 5) | ((b >> 3) << 10) | 0x8000
    return out


def main():
    ic = icons()
    # shelf packing in icon order: a new row when the next icon does not fit
    placed = []
    x = y = rowh = 0
    for name, im in ic:
        if x + im.width > ATLAS_W or name == "eyes":      # eyes: own row (the right part of the strip lies under the coin page)
            x = 0; y += rowh; rowh = 0
        placed.append((name, im, x, y))
        x += im.width
        rowh = max(rowh, im.height)
    height = y + rowh
    atlas = Image.new("RGBA", (ATLAS_W, height), (0, 0, 0, 0))
    for name, im, px, py in placed:
        atlas.alpha_composite(im, (px, py))
    data = quantize([pixel(p) for p in np.array(atlas).reshape(-1, 4)])

    with open(OUT, "w", newline="\n") as f:
        f.write("#pragma once\n/* Generated by tools/gen_icons.py from ui/buttons/kenney (CC0) -- do not edit. */\n#include <stdint.h>\n\n")
        f.write("#define ICONS_W %d\n#define ICONS_H %d\n#define ICON_COUNT %d\n\n" % (ATLAS_W, height, len(placed)))
        f.write("/* x, y, w, h inside the strip, in the order of the control characters 1..%d */\n" % len(placed))
        f.write("static const struct { uint8_t x, y, w, h; } ICON_RECT[ICON_COUNT] = {\n")
        for name, im, px, py in placed:
            f.write("\t{%d, %d, %d, %d},   /* %s */\n" % (px, py, im.width, im.height, name))
        f.write("};\n\n")
        pal = sorted(set(data) | {0})                      # index 0 = 0 = transparent
        f.write("/* the colours of the strip: 16 bit pixels (bit 15 set, 0 = transparent) */\n")
        f.write("#define ICON_NPAL %d\n" % len(pal))
        f.write("static const uint16_t ICON_PAL[ICON_NPAL] = {" + ",".join("0x%04x" % v for v in pal) + "};\n\n")
        f.write("/* the pixels as indices into ICON_PAL (a palette of 33 colours packs far better than 16 bit values), ICONS_W x ICONS_H */\n")
        f.write("static const uint8_t ICON_PIX[ICONS_W * ICONS_H] = {\n")
        for i in range(0, len(data), 32):
            f.write("\t" + ",".join("%d" % pal.index(v) for v in data[i:i + 32]) + ",\n")
        f.write("};\n")
    print("wrote", OUT, "(%d x %d, %d bytes of pixels)" % (ATLAS_W, height, len(data) * 2))

    if "--preview" in sys.argv:
        out = sys.argv[sys.argv.index("--preview") + 1]
        z = 5
        big = Image.new("RGBA", (ATLAS_W, height), BG + (255,))
        for i, v in enumerate(data):                      # what is in the header, not the atlas before the reduction of the colours
            if v:
                big.putpixel((i % ATLAS_W, i // ATLAS_W), ((v & 31) << 3, ((v >> 5) & 31) << 3, ((v >> 10) & 31) << 3, 255))
        big.resize((ATLAS_W * z, height * z), Image.NEAREST).save(out)


if __name__ == "__main__":
    main()
