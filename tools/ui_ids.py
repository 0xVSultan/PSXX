#!/usr/bin/env python3
"""The texts of the screens by identifier.

  py -3.13 tools/ui_ids.py seed  [--build-dir build/psx] [--force]     make tools/strings/en_<range>.txt from the strings of the compiled program (once; then they are edited by hand)
  py -3.13 tools/ui_ids.py check [--strict]                            the lists: names, texts, the Hungarian lists against the English ones
  py -3.13 tools/ui_ids.py gen   [--out build/gen]                     ui_ids.h (the identifiers) and ui_tabs_<range>.c (the English and Hungarian tables of the range, ui_reg_<range>())
  py -3.13 tools/ui_ids.py rebalance [--write]                         every text into the lowest range whose sources use it (after sources have been moved to identifiers)
  py -3.13 tools/ui_ids.py prune [--write]                             take out the texts that no source uses
  py -3.13 tools/ui_ids.py pack  <lang> [--out DIR]                    the tables of the language of the data card (one blob per range: DIR/ui_<range>.bin)

The ranges (a: the main card, b: the signer, l: the language module) have a list of texts each: tools/strings/en_<range>.txt, one line per text,  NAME<TAB>text  (the text is written as in
C: \\n, \\t, \\\\, \\xHH; the button icons are \\x01 .. \\x12). The name becomes the identifier TXT_<NAME>; its number is the line's place in the list of the range. The Hungarian list
hu_<range>.txt has the same names; a name that is missing or has an empty text is not translated (shown in English). A translation has to keep the % conversions of the English text, in
the same order (it is the format of sprintf) and its button icons, or the program would read the wrong arguments: check and pack refuse it.

Table (little endian): "UD2\\0", u32 tab_id, u16 n, u16 0, u16 anchor[(n + 7) / 8], the texts in the order of the lines, each ended by a 0 byte; anchor[k] = offset of text 8 * k from the start of the texts.
tab_id = FNV-1a 32 of the names, the conversions and the icons of the English texts in order: a table made for another list is not accepted by the program."""
import argparse, os, re, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import ui_strings as U

STRINGS = os.path.join(HERE, "strings")
RANGES = ["a", "b", "l"]
LANGS = ["en", "hu"]
OBJ_DIR = {"a": "CMakeFiles/psxx_a.dir", "b": "CMakeFiles/psxx_b_obj.dir", "l": "CMakeFiles/psxx_l_obj.dir"}
ICON_NAMES = {1: "X", 2: "O", 3: "SQ", 4: "TRI", 5: "START", 6: "SELECT", 7: "UP", 8: "DOWN", 9: "LEFT", 10: "RIGHT", 11: "UPDOWN", 12: "LEFTRIGHT",
              13: "L1", 14: "L2", 15: "R1", 16: "R2", 17: "DPAD", 18: "EYES"}
NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


HU_ID = 15                      # Hungarian is a language of the data card (tools/data_pack.py LANGS): its texts are ui_15_<range>.txt, not in the main card, the signer or the module


def path_of(lang, r):
    if lang == "hu":
        return os.path.join(STRINGS, "ui_%d_%s.txt" % (HU_ID, r))
    return os.path.join(STRINGS, "%s_%s.txt" % (lang, r))


def read_list(path):
    """[(name, text bytes)] in file order"""
    out, seen = [], set()
    for n, line in enumerate(open(path, encoding="utf-8"), 1):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        if "\t" not in line:
            raise SystemExit("%s:%d: no tab" % (path, n))
        name, text = line.split("\t", 1)
        if not NAME_RE.match(name):
            raise SystemExit("%s:%d: bad name %r" % (path, n, name))
        if name in seen:
            raise SystemExit("%s:%d: the name %s is twice in the list" % (path, n, name))
        seen.add(name)
        try:
            out.append((name, U.unesc(text)))
        except ValueError as e:
            raise SystemExit("%s:%d: %s" % (path, n, e))
    return out


def load_english():
    """{range: [(name, text)]}; the files have to exist"""
    out = {}
    for r in RANGES:
        p = path_of("en", r)
        if not os.path.exists(p):
            raise SystemExit("%s does not exist (py -3.13 tools/ui_ids.py seed)" % p)
        out[r] = read_list(p)
    names = {}
    for r in RANGES:
        for name, _ in out[r]:
            if name in names:
                raise SystemExit("the name %s is in the range %s and in %s" % (name, names[name], r))
            names[name] = r
    return out


def tab_id(entries):
    h = b"-\n"                                      # number 0 is the empty text (a field that was never set shows nothing)
    for name, text in entries:
        h += name.encode() + b"\0" + b" ".join(U.conversions(text)) + b"\0" + bytes(U.icons(text)) + b"\n"
    return U.fnv(h)


def pack_table(texts, tid):
    """texts: list of bytes (b'' = not translated)"""
    n = len(texts)
    assert 0 < n < 4096
    body, anchors = bytearray(), []
    for i, t in enumerate(texts):
        if i % 8 == 0:
            anchors.append(len(body))
        assert b"\0" not in t
        body += t + b"\0"
    assert len(body) < 65536, "the texts are too long for 16 bit offsets"
    return b"UD2\0" + struct.pack("<IHH", tid, n, 0) + b"".join(struct.pack("<H", a) for a in anchors) + bytes(body)


def problems(en, tr):
    """the mistakes of a translation (dict name -> bytes) against the English list"""
    errs, names = [], dict(en)
    for name, v in tr.items():
        if name not in names:
            errs.append("%s: not a text of the program" % name)
            continue
        k = names[name]
        if v == b"":
            continue
        if U.conversions(k) != U.conversions(v):
            errs.append("%s: the %% conversions differ (%s -> %s)" % (name, b" ".join(U.conversions(k)).decode(), b" ".join(U.conversions(v)).decode()))
        if U.icons(k) != U.icons(v):
            errs.append("%s: the button icons differ" % name)
        if b"\0" in v:
            errs.append("%s: a 0 byte" % name)
        try:
            v.decode("utf-8")
        except UnicodeDecodeError:
            errs.append("%s: not UTF-8" % name)
        if len(v) > 4 * len(k) + 40:
            errs.append("%s: much longer than the English text (the screens are 640 pixels wide)" % name)
    return errs


def table_for(en_list, tr):
    return pack_table([b""] + [tr.get(name, b"") for name, _ in en_list], tab_id(en_list))


# ---------------------------------------------------------------- seed
def slug(text):
    has_icon = any(1 <= c <= 18 for c in text)
    s = bytes(c if not 1 <= c <= 18 else 32 for c in text)       # the icons are not in the name (a hint line gets HINT_)
    s = U.CONV.sub(b" N ", s)
    words = [w.upper() for w in re.findall(r"[A-Za-z0-9]+", s.decode("utf-8", "replace"))]
    out = []
    for w in words:
        if out and out[-1] == "N" and w == "N":
            continue
        if len("_".join(out + [w])) > 30 and out:
            break
        out.append(w)
    name = "_".join(out)
    if has_icon:
        name = "HINT_" + name if name else "HINT"
    if not name:
        return "TEXT"
    return name if name[0].isalpha() else "T_" + name


def cmd_seed(a):
    ranges_of = {}
    for r in RANGES:
        seen = set()
        for obj in sorted(set(x for x in __import__("glob").glob(os.path.join(a.build_dir, OBJ_DIR[r], "**", "*.obj"), recursive=True))):
            for s in U.elf_strings(obj):
                if U.looks_like_text(s):
                    seen.add(s)
        for s in seen:
            ranges_of.setdefault(s, set()).add(r)
    by_range = {r: [] for r in RANGES}
    for s, rs in ranges_of.items():
        by_range[min(rs)].append(s)                              # used by several parts: the lowest range (a is always in RAM)
    used = set()
    for r in RANGES:
        p = path_of("en", r)
        if os.path.exists(p) and not a.force:
            raise SystemExit("%s exists (--force to make it again)" % p)
    for r in RANGES:
        lines = ["# The English texts of the range '%s' (%s): NAME<TAB>text, C escapes. The order is the numbering: new texts go to the end. tools/ui_ids.py" % (r, {"a": "the main card", "b": "the signer", "l": "the language module"}[r])]
        for s in sorted(by_range[r]):
            base = slug(s)
            name, k = base, 2
            while name in used:
                name = "%s_%d" % (base, k)
                k += 1
            used.add(name)
            lines.append("%s\t%s" % (name, U.esc(s)))
        with open(path_of("en", r), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
        print("%s: %d texts" % (path_of("en", r), len(by_range[r])))


# ---------------------------------------------------------------- check, gen, pack
def load_translation(lang, r):
    p = path_of(lang, r)
    return dict(read_list(p)) if os.path.exists(p) else None


def cmd_check(a):
    en = load_english()
    bad = 0
    for r in RANGES:
        for name, text in en[r]:
            if text == b"":
                print("ERROR: %s_%s: %s is empty (the English table has to be complete)" % ("en", r, name)); bad += 1
            if b"\0" in text:
                print("ERROR: en_%s: %s has a 0 byte" % (r, name)); bad += 1
        print("range %s: %d texts, tab_id %08x" % (r, len(en[r]), tab_id(en[r])))
        for lang in LANGS[1:]:
            tr = load_translation(lang, r)
            if tr is None:
                print("  %s: no list" % lang)
                continue
            errs = problems(en[r], tr)
            miss = sum(1 for name, _ in en[r] if tr.get(name, b"") == b"")
            print("  %s: %d of %d translated, %d missing, %d errors" % (lang, len(en[r]) - miss, len(en[r]), miss, len(errs)))
            for e in errs:
                print("ERROR: %s_%s: %s" % (lang, r, e))
            bad += len(errs)
            if a.strict and miss:
                bad += miss
    return 1 if bad else 0


def c_array(name, data):
    rows = []
    for i in range(0, len(data), 16):
        rows.append("\t" + ",".join("0x%02x" % b for b in data[i:i + 16]) + ",")
    return "const uint8_t %s[%d] = {\n%s\n};\n" % (name, len(data), "\n".join(rows))


def cmd_gen(a):
    en = load_english()
    os.makedirs(a.out, exist_ok=True)
    h = ["/* generated by tools/ui_ids.py: do not edit. Include ui_text.h first. */", "#pragma once", ""]
    for r in RANGES:
        R = r.upper()
        h.append("#define UI_N_%s %d" % (R, len(en[r]) + 1))
        h.append("#define UI_TABID_%s 0x%08xu" % (R, tab_id(en[r])))
    h.append("")
    h.append("enum {")
    for r in RANGES:
        for i, (name, _) in enumerate(en[r]):
            h.append("\tTXT_%s = UI_ID(UI_R_%s, %d)," % (name, r.upper(), i + 1))
    h.append("};")
    h.append("")
    for r in RANGES:
        h.append("int ui_reg_%s(void);                 /* make the tables of the range known (English, Hungarian if there is one); 0 or -1 */" % r)
    with open(os.path.join(a.out, "ui_ids.h"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(h) + "\n")
    for r in RANGES:                                      # one source per range: the part of the program that carries the range links it
        R = r.upper()
        c = ["/* generated by tools/ui_ids.py: do not edit */", "#include <stdint.h>", '#include "ui_text.h"', '#include "ui_ids.h"', ""]
        c.append(c_array("ui_tab_en_%s" % r, table_for(en[r], dict(en[r]))))
        hu = load_translation("hu", r)
        if hu is not None:
            errs = problems(en[r], hu)
            if errs:
                raise SystemExit("hu_%s: %s" % (r, "; ".join(errs[:5])))
            c.append("#ifdef UI_WITH_HU                                   /* the host programs only (the layout tests): on the console Hungarian comes from the data card */")
            c.append(c_array("ui_tab_hu_%s" % r, table_for(en[r], hu)) + "#endif")
        c.append("int ui_reg_%s(void)" % r)
        c.append("{")
        c.append("\tint rc = ui_table_set(UI_R_%s, UI_LANG_EN, ui_tab_en_%s, sizeof ui_tab_en_%s, UI_TABID_%s, UI_N_%s);" % (R, r, r, R, R))
        if hu is not None:
            c.append("#ifdef UI_WITH_HU")
            c.append("\trc |= ui_table_set(UI_R_%s, UI_LANG_HU, ui_tab_hu_%s, sizeof ui_tab_hu_%s, UI_TABID_%s, UI_N_%s);" % (R, r, r, R, R))
            c.append("#endif")
        c.append("\treturn rc ? -1 : 0;")
        c.append("}")
        with open(os.path.join(a.out, "ui_tabs_%s.c" % r), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(c) + "\n")
    print("%s: %s texts" % (a.out, "+".join(str(len(en[r])) for r in RANGES)))


def cmd_pack(a):
    en = load_english()
    tr_any = False
    os.makedirs(a.out, exist_ok=True)
    for r in RANGES:
        tr = load_translation(a.lang, r)
        if tr is None:
            continue
        errs = problems(en[r], tr)
        if errs:
            raise SystemExit("\n".join("%s_%s: %s" % (a.lang, r, e) for e in errs))
        blob = table_for(en[r], tr)
        with open(os.path.join(a.out, "ui_%s.bin" % r), "wb") as f:
            f.write(blob)
        print("range %s: %d texts, %d bytes" % (r, len(en[r]), len(blob)))
        tr_any = True
    if not tr_any:
        raise SystemExit("no list of the language %s in %s" % (a.lang, STRINGS))


# ---------------------------------------------------------------- ranges by use
OVL_ONLY = {  # the files that only the signer (the overlay B) needs: hal/psx/CMakeLists.txt OVL_ONLY_SRC, signer_app.c
    "hal/psx/signer_app.c", "hal/psx/signer_vanity.h", "hal/psx/signer_ms.h",
    "core/sign/btc.c", "core/sign/pb.c", "core/sign/txview.c", "core/sign/evm.c", "core/sign/tron.c", "core/sign/xrp.c", "core/sign/cosmos.c", "core/sign/nostr.c", "core/sign/nip19.c", "core/sign/nip44.c",
    "core/sign/solana.c", "core/sign/stellar.c", "core/sign/near.c", "core/sign/polkadot.c", "core/sign/ton.c", "core/sign/ada.c", "core/sign/zec.c", "core/sign/xmr.c",
    "core/sign/redpallas.c", "core/sign/orchard_out.c", "core/ec/secp_van.c", "core/ec/secp_pub.c", "core/sign/mswallet.c", "core/vanity/vanity.c", "core/sign/dispatch.c",
    "core/sign/kaspa.c", "core/sign/btcmsg.c", "core/ec/ed25519_sign.c", "core/ec/secp256k1_sign.c", "core/hash/chacha20poly1305.c", "core/ec/poseidon.c", "core/coin/orchard_sign.c"}
LANG_ONLY = {"hal/psx/lang_ui.c", "hal/psx/fontext.c", "core/lang/lang.c", "core/lang/nfkd.c", "core/lang/langin.c"}


def range_of_file(rel):
    rel = rel.replace("\\", "/")
    if rel in OVL_ONLY:
        return "b"
    if rel in LANG_ONLY:
        return "l"
    return "a"


def cmd_rebalance(a):
    """A text belongs to the lowest range whose sources use it (a: always in RAM, then b, then l); the object files the seed read hide the strings that the compiler merged"""
    en = load_english()
    used = used_names()
    moved = []
    lists = {r: list(en[r]) for r in RANGES}
    for r in RANGES:
        for name, text in en[r]:
            if name in used:
                want = min(used[name])
                if want != r:
                    moved.append((name, r, want))
    for name, r, want in moved:
        text = dict(lists[r])[name]
        lists[r] = [(n, t) for n, t in lists[r] if n != name]
        lists[want].append((name, text))
    unused = [name for r in RANGES for name, _ in lists[r] if name not in used]
    print("%d texts moved to the range that uses them, %d not used by any source yet" % (len(moved), len(unused)))
    for name, r, want in moved[:20]:
        print("  %s: %s -> %s" % (name, r, want))
    if a.write:
        for r in RANGES:
            p = path_of("en", r)
            head = [l for l in open(p, encoding="utf-8").read().split("\n") if l.startswith("#")]
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(head + ["%s\t%s" % (name, U.esc(text)) for name, text in lists[r]]) + "\n")
        print("the lists are written")
    else:
        print("(--write to change the lists)")


def used_names():
    """{name: set of ranges of the sources that use TXT_<name>}"""
    used = {}
    for d in ("hal/psx", "core"):
        for dp, _, fs in os.walk(os.path.join(ROOT, d)):
            for f in fs:
                if not f.endswith((".c", ".h")):
                    continue
                path = os.path.join(dp, f)
                rel = os.path.relpath(path, ROOT).replace("\\", "/")
                for name in set(re.findall(r"\bTXT_([A-Z0-9_]+)\b", open(path, encoding="utf-8", errors="replace").read())):
                    used.setdefault(name, set()).add(range_of_file(rel))
    return used


def cmd_prune(a):
    """take the texts out of the lists that no source uses (after the sources have been moved to identifiers: what the seed took from the objects and is not a text of the screens)"""
    en = load_english()
    used = used_names()
    dropped = []
    for r in RANGES:
        keep = [(n, t) for n, t in en[r] if n in used]
        dropped += [(n, t) for n, t in en[r] if n not in used]
        en[r] = keep
    print("%d texts are not used by any source" % len(dropped))
    for n, t in dropped[:60]:
        print("  %s: %s" % (n, U.esc(t)[:70]))
    if a.write:
        for r in RANGES:
            p = path_of("en", r)
            head = [l for l in open(p, encoding="utf-8").read().split("\n") if l.startswith("#")]
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(head + ["%s\t%s" % (name, U.esc(text)) for name, text in en[r]]) + "\n")
        print("the lists are written: " + ", ".join("%s %d" % (r, len(en[r])) for r in RANGES))
    else:
        print("(--write to change the lists)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seed"); s.add_argument("--build-dir", default=os.path.join(ROOT, "build", "psx")); s.add_argument("--force", action="store_true")
    c = sub.add_parser("check"); c.add_argument("--strict", action="store_true")
    g = sub.add_parser("gen"); g.add_argument("--out", default=os.path.join(ROOT, "build", "gen"))
    pr = sub.add_parser("prune"); pr.add_argument("--write", action="store_true")
    rb = sub.add_parser("rebalance"); rb.add_argument("--write", action="store_true")
    p = sub.add_parser("pack"); p.add_argument("lang"); p.add_argument("--out", default=os.path.join(ROOT, "build", "uipack"))
    a = ap.parse_args()
    if a.cmd == "seed":
        cmd_seed(a)
    elif a.cmd == "check":
        sys.exit(cmd_check(a))
    elif a.cmd == "gen":
        cmd_gen(a)
    elif a.cmd == "rebalance":
        cmd_rebalance(a)
    elif a.cmd == "prune":
        cmd_prune(a)
    else:
        cmd_pack(a)


if __name__ == "__main__":
    main()
