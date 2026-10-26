#!/usr/bin/env python3
"""Shows the report that the memory probe (hal/psx/memprobe.c) wrote to a memory card: the files PSXXMP01.. of a card image (the .mcd of an emulator, or a dump of a real card).

  py -3.13 tools/memprobe_read.py <card.mcd> [--all] [--out report.txt]

Without --all the newest report (the highest number) is shown. The text is the one of the [mem] TTY lines: the BIOS and its ROM CRC-32, the checkpoints, the ranges of the RAM that were
free (never written in the whole run), busy at the start (live BIOS memory), or written (with the checkpoint in which the first write was seen), and the first writes themselves.
"""
import argparse, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mkcard as M


def reports(d):
    """[(number, name, text)] of the PSXXMP files of the card image"""
    out = []
    for b in range(1, 16):
        e = M.entry(d, b)
        if e[0] != 0x51:
            continue
        name = e[10:30].split(b"\0")[0].decode("ascii", "replace")
        m = re.match(r"BESCES-00000PSXXMP(\d\d)$", name)
        if not m:
            continue
        data = bytes(d[b * 8192 + 2 * M.FRAME:(b + 1) * 8192])
        out.append((int(m.group(1)), name, data.split(b"\0")[0].decode("ascii", "replace")))
    return sorted(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("card")
    ap.add_argument("--all", action="store_true", help="every report on the card")
    ap.add_argument("--out", help="write the text to this file as well")
    a = ap.parse_args()
    r = reports(M.load(a.card))
    if not r:
        sys.exit("no PSXXMP report on %s" % a.card)
    if not a.all:
        r = r[-1:]
    text = "".join("== %s\n%s\n" % (name, t) for _, name, t in r)
    print(text)
    if a.out:
        open(a.out, "w", encoding="utf-8", newline="\n").write(text)


if __name__ == "__main__":
    main()
