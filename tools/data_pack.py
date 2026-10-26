#!/usr/bin/env python3
"""Builds the package of the data card (C): the word lists of the languages the main card does not carry, the glyphs they need, the Chinese mappings, and the index of the languages. One package file of kind 2 (core/pkg/pkg.h, tools/pkg_pack.py), up to 15 blocks of a memory card.

  py -3.13 tools/data_pack.py build [--out build/release/m5/data.pkg]    build, verify, print the sizes
  py -3.13 tools/data_pack.py info <data.pkg>                            list the groups

Groups (id: content):
  0x0001  language index: u8 count, then 32 byte records  u8 id, u8 flags (1 BIP39 list, 2 Monero list, 4 words are one character), u8 glyph sets (bit 0 hanzi, 1 hangul, 2 kana,
          (bit 3 unused: the Cyrillic comes with the base font), u8 Monero checksum prefix length, u16 BIP39 group, u16 Monero group, u8 separator (0 space, 1 U+3000), u8 reserved[3], char name[16] (NUL padded)
  0x01xx  glyph sets: u8 width, u8 height, u8 format, u8 0, u16 n; the code points ascending: the first as u16, then the differences, one byte each (255: u16 follows);
          then the bitmaps [n]: format 0: height rows of u16 little endian each, bit 15 the leftmost pixel; format 1 (16 x 16): 16 bytes with the upper 8 pixels of
          each column, left to right (bit 7 the top pixel), then 16 bytes with the lower 8 pixels.
          0x0101 hanzi (Unifont 16 x 16, format 1), 0x0102 hangul syllables and the compatibility jamo (format 0: the syllables repeat whole rows of their jamo, LZMA
          finds those better in rows, 533 bytes less than format 1), 0x0103 kana (format 1; the complete kana, the small katakana extensions, a few fullwidth marks)
  0x02xx  BIP39 word lists of language xx (tools/wl_pack.py blobs, composed text on decoding)       0x03xx  Monero word lists
  0x05xx  the Monero list of language xx made from its BIP39 list: u16 length, then a coded mask of that length (tools/wl_pack.py pack_mask), one bit per BIP39 word, set for
          the words the Monero list keeps; Japanese, Spanish: that is all (every Monero word is a word of the BIP39 list, in the same order). French, Italian: then a
          tools/wl_pack.py blob of the Monero words that are not in the BIP39 list; both lists are ascending in the order of the UTF-8 bytes, and the Monero list is the two
          merged in that order (core/wordlist/wl.c wl_merge)
  The Chinese lists are coded with the range coder of the word lists (wl_pack.py enc_bits, enc_shuffle; core/wordlist/wl.c wl_rc_bit, wl_rc_shuffle): bits by the counts of
  the bits before them, permutations as swaps:
  0x0400  simplified Chinese BIP39: the bits of the hanzi set that the list uses (2048 of them), then the swaps that put those glyphs (ascending) in the order of the words
  0x0401  traditional Chinese BIP39: the swaps that put the hanzi the simplified list does not use (ascending; the 773 words that differ use each of them once) in the order of
          those words, then the bits of the 2048 positions, set where the word differs from the simplified one
  0x0402  Monero Chinese: a coded mask (pack_mask) of the positions of the BIP39 simplified list that the Monero list keeps (in the same order)
Esperanto and Lojban are Monero-only lists (ids 13 and 14)."""
import argparse, gzip, hashlib, json, os, struct, sys, unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path[:0] = [HERE, os.path.join(HERE, "refshim"), os.path.join(ROOT, "build", "refpkgs")]
import pkg_pack as P
import wl_pack as W
import ui_strings as U
import ui_ids as I
import mkcard as M

UNIFONT = os.path.join(HERE, "font_dl", "unifont", "unifont-18.0.01.hex.gz")
TERMINUS = os.path.join(HERE, "font_dl_terminus", "src", "terminus-font-4.49.1", "ter-u18b.bdf")

# id, name, BIP39 list, Monero list, glyph sets, Monero checksum prefix length, separator
LANGS = [
    (1, "Japanese", "japanese", "japanese", 4 | 0, 3, 1),
    (2, "Korean", "korean", None, 2, 0, 0),
    (3, "Spanish", "spanish", "spanish", 0, 4, 0),
    (4, "French", "french", "french", 0, 4, 0),
    (5, "Italian", "italian", "italian", 0, 4, 0),
    (6, "Czech", "czech", None, 0, 0, 0),
    (7, "Portuguese", "portuguese", "portuguese", 0, 4, 0),
    (8, "Chinese (simp.)", "chinese_simplified", "chinese_simplified", 1, 1, 0),
    (9, "Chinese (trad.)", "chinese_traditional", None, 1, 0, 0),
    (10, "Dutch", None, "dutch", 0, 4, 0),
    (11, "German", None, "german", 0, 4, 0),
    (12, "Russian", None, "russian", 0, 4, 0),
    (13, "Esperanto", None, "esperanto", 0, 4, 0),
    (14, "Lojban", None, "lojban", 0, 4, 0),
]
GLYPH_IDS = {1: 0x0101, 2: 0x0102, 4: 0x0103}
UI_DIR = os.environ.get("PSXX_UI_DIR") or os.path.join(HERE, "strings")                  # ui_<language id>_<a|b|l>.txt: the translation of the UI texts of that language, per range (tools/ui_ids.py), if there is one


def ui_tables(lid):
    """the tables of the UI texts of language `lid` for the ranges a, b, l, or None when the language has no list for the main card.
    A range without a list is a table of empty texts: everything of it stays English."""
    if not os.path.exists(os.path.join(UI_DIR, "ui_%d_a.txt" % lid)):
        return None
    en = I.load_english()
    out = {}
    for r in I.RANGES:
        path = os.path.join(UI_DIR, "ui_%d_%s.txt" % (lid, r))
        tr = dict(I.read_list(path)) if os.path.exists(path) else {}
        errs = I.problems(en[r], tr)
        if errs:
            raise SystemExit("ui_%d_%s.txt: %s" % (lid, r, "; ".join(errs[:5])))
        out[r] = I.table_for(en[r], tr)
    return out


UI_GROUP = {"a": 0x0600, "b": 0x0700, "l": 0x0800}      # + the language id (core/lang/lang.h LANG_ID_UI)
DATA_NAME = "BESCES-00000PSXXPK02"                     # the file of the data card (the overlay package is ...PK01)


# ---------------------------------------------------------------- glyphs
def unifont(needed):
    g = {}
    with gzip.open(UNIFONT, "rt") as f:
        for line in f:
            cp, hx = line.strip().split(":")
            c = int(cp, 16)
            if c in needed:
                assert len(hx) == 64, "%04X is not a 16 x 16 glyph" % c
                g[c] = [int(hx[i:i + 4], 16) for i in range(0, 64, 4)]
    miss = needed - set(g)
    assert not miss, "Unifont lacks %s" % ", ".join("%04X" % c for c in sorted(miss))
    return g


def terminus(needed):
    g, enc, rows, in_bitmap = {}, None, [], False
    for line in open(TERMINUS, encoding="utf-8", errors="replace").read().splitlines():
        if line.startswith("ENCODING "): enc = int(line.split()[1])
        elif line == "BITMAP": in_bitmap, rows = True, []
        elif line == "ENDCHAR":
            if enc in needed: g[enc] = rows
            enc, in_bitmap = None, False
        elif in_bitmap:
            rows.append(int(line, 16) << (16 - 4 * len(line)))
    miss = needed - set(g)
    assert not miss, "Terminus lacks %s" % ", ".join("%04X" % c for c in sorted(miss))
    return g


def cols16(rows):
    """the 16 columns of a 16 x 16 glyph, each a u16 with the top pixel in bit 15"""
    out = []
    for x in range(16):
        v = 0
        for y in range(16):
            v |= ((rows[y] >> (15 - x)) & 1) << (15 - y)
        out.append(v)
    return out


def glyph_bits(w, h, rows, fmt):
    if fmt == 0:
        return b"".join(struct.pack("<H", r) for r in rows)
    c = cols16(rows)                                            # 16 x 16: the columns, the upper bytes first, then the lower ones (compresses best, tools/data_pack.py history)
    return bytes(v >> 8 for v in c) + bytes(v & 255 for v in c)


def glyph_group(w, h, glyphs, fmt=0):
    cps = sorted(glyphs)
    deltas = bytearray(struct.pack("<H", cps[0]))
    for a, b in zip(cps, cps[1:]):
        d = b - a
        deltas += bytes([d]) if d < 255 else bytes([255]) + struct.pack("<H", d)
    return struct.pack("<BBBBH", w, h, fmt, 0, len(cps)) + bytes(deltas) + b"".join(glyph_bits(w, h, glyphs[c], fmt) for c in cps)


def nfc_chars(words):
    return set("".join(words))


# ---------------------------------------------------------------- masks
def coded_mask(bits, with_length=False):
    """a mask with the coder of the word lists (wl_pack.py pack_mask), checked; with_length: after a u16 of its length (something follows it)"""
    m = W.pack_mask(bits)
    assert W.Decoder(m).bits(len(bits)) == [int(b) for b in bits]
    return (struct.pack("<H", len(m)) if with_length else b"") + m


def is_subset(small, big):
    """every word of `small` is a word of `big`, in the same order"""
    it = iter(big)
    return all(w in it for w in small)


_merged = {}


def xmr_merge(bn, xn, bip, xmr):
    """the mask over the BIP39 list and the other words, if the Monero list is the two merged and that is smaller than a blob of its own; else None"""
    if not (xn and bn) or xn.startswith("chinese"):
        return None
    if (bn, xn) not in _merged:
        _merged[(bn, xn)] = _xmr_merge(bn, xn, bip, xmr)
    return _merged[(bn, xn)]


def _xmr_merge(bn, xn, bip, xmr):
    have, big = set(xmr[xn]), set(bip[bn])
    mask = [w in have for w in bip[bn]]
    extra = [w for w in xmr[xn] if w not in big]
    if not extra or W.merge(bip[bn], mask, extra) != xmr[xn]:
        return None
    blob = W.pack(extra, xn)[0]
    return (mask, extra, blob) if len(coded_mask(mask, True)) + len(blob) < len(W.pack(xmr[xn], xn)[0]) else None


def xmr_kind(name, bn, xn, bip, xmr):
    """how the Monero list of a language is stored: 'zh' (the Chinese mask), 'sub' (a mask over its BIP39 list), 'merge' (that mask and a blob of the other words),
    'blob' (the word list coder)"""
    if xn and xn.startswith("chinese"):
        return "zh"
    if xn and bn and is_subset(xmr[xn], bip[bn]):
        return "sub"
    if xmr_merge(bn, xn, bip, xmr):
        return "merge"
    return "blob" if xn else None


def xmr_group(lid, name, bn, xn, bip, xmr):
    k = xmr_kind(name, bn, xn, bip, xmr)
    return 0 if not k else 0x0402 if k == "zh" else 0x0500 + lid if k in ("sub", "merge") else 0x0300 + lid


# ---------------------------------------------------------------- the package
def hangul_set(bip):
    """the syllables of the Korean list and the compatibility jamo (the letters for typing a syllable)"""
    return sorted(nfc_chars(bip["korean"]) | set(map(chr, range(0x3131, 0x3164))))


def kana_set(bip, xmr):
    """the complete hiragana and katakana (with the marks and the ideographic punctuation of wallet names), and whatever the Japanese lists use"""
    full = [0x3001, 0x3002, 0x300C, 0x300D, 0x30FB] + list(range(0x3041, 0x3097)) + [0x309B, 0x309C, 0x309D, 0x309E] + list(range(0x30A1, 0x30FB)) + [0x30FC, 0x30FD, 0x30FE] \
        + list(range(0x31F0, 0x3200)) + [0xFF01, 0xFF08, 0xFF09, 0xFF0C, 0xFF0E, 0xFF1A, 0xFF1B, 0xFF1F, 0xFF5E]
    return sorted(nfc_chars(bip["japanese"]) | nfc_chars(xmr["japanese"]) | set(map(chr, full)))


def build_groups():
    bip = {n: W.load_bip(n) for n in set(l[2] for l in LANGS if l[2])}
    xmr = {n: W.load_xmr(n) for n in set(l[3] for l in LANGS if l[3])}
    groups, report = [], []

    # glyph sets of the composed characters (the lists are drawn composed; the decoder composes Hangul and kana, wl.c)
    hanzi = sorted(set("".join(bip["chinese_simplified"] + bip["chinese_traditional"])))
    hangul = hangul_set(bip)
    kana = kana_set(bip, xmr)
    assert all(0x4E00 <= ord(c) < 0xA000 for c in hanzi)
    assert all(0xAC00 <= ord(c) <= 0xD7A3 or 0x3131 <= ord(c) <= 0x3163 for c in hangul)
    assert all(0x3000 <= ord(c) <= 0x31FF or 0xFF00 <= ord(c) <= 0xFFEF for c in kana), [c for c in kana if not 0x3000 <= ord(c) <= 0x31FF]
    uf = unifont(set(map(ord, hanzi + hangul + kana)))
    groups.append((0x0101, glyph_group(16, 16, {ord(c): uf[ord(c)] for c in hanzi}, 1), "lzma"))
    groups.append((0x0102, glyph_group(16, 16, {ord(c): uf[ord(c)] for c in hangul}, 0), "lzma"))     # rows: smaller for hangul (see the format above)
    groups.append((0x0103, glyph_group(16, 16, {ord(c): uf[ord(c)] for c in kana}, 1), "lzma"))
    report.append("glyphs: hanzi %d, hangul %d (with the compatibility jamo), kana %d" % (len(hanzi), len(hangul), len(kana)))

    # the word lists
    for lid, name, bn, xn, gs, pre, sep in LANGS:
        if bn and name and not bn.startswith("chinese"):
            blob, _, _, _ = W.pack(bip[bn], bn)
            W.unpack_check(blob, bip[bn])
            groups.append((0x0200 + lid, blob, "stored"))
        kind = xmr_kind(name, bn, xn, bip, xmr)
        if kind == "sub":
            have = set(xmr[xn])
            groups.append((0x0500 + lid, coded_mask([w in have for w in bip[bn]], True), "stored"))
            report.append("%s: the %d Monero words are a mask over the BIP39 list" % (name, len(xmr[xn])))
        elif kind == "merge":
            mask, extra, blob = xmr_merge(bn, xn, bip, xmr)
            W.unpack_check(blob, extra)
            groups.append((0x0500 + lid, coded_mask(mask, True) + blob, "stored"))
            report.append("%s: %d Monero words from the BIP39 list (a mask), %d of their own (%d bytes)" % (name, len(xmr[xn]) - len(extra), len(extra), len(blob)))
        elif kind == "blob":
            blob, _, _, _ = W.pack(xmr[xn], xn)
            W.unpack_check(blob, xmr[xn])
            groups.append((0x0300 + lid, blob, "stored"))

    # the Chinese mappings
    hidx = {c: i for i, c in enumerate(hanzi)}
    zs, zt, mz = bip["chinese_simplified"], bip["chinese_traditional"], xmr["chinese_simplified"]
    zset = set(zs)
    inset = [c in zset for c in hanzi]
    used = [i for i, c in enumerate(hanzi) if c in zset]
    enc = W.Encoder()
    W.enc_bits(enc, inset)
    W.enc_shuffle(enc, used, [hidx[w] for w in zs])
    g400 = enc.finish()
    d = W.Decoder(g400)
    assert d.bits(len(hanzi)) == inset and [hanzi[i] for i in d.shuffle(used)] == zs
    groups.append((0x0400, g400, "stored"))
    diff = [i for i in range(2048) if zs[i] != zt[i]]
    rest = [i for i, c in enumerate(hanzi) if c not in zset]
    assert sorted(hidx[zt[i]] for i in diff) == rest, "the differing traditional words are not the hanzi the simplified list does not use, each once"
    enc = W.Encoder()
    W.enc_shuffle(enc, rest, [hidx[zt[i]] for i in diff])
    W.enc_bits(enc, [zs[i] != zt[i] for i in range(2048)])
    g401 = enc.finish()
    d = W.Decoder(g401)
    assert [hanzi[i] for i in d.shuffle(rest)] == [zt[i] for i in diff] and d.bits(2048) == [zs[i] != zt[i] for i in range(2048)]
    groups.append((0x0401, g401, "stored"))
    pos = [zs.index(w) for w in mz]
    assert pos == sorted(pos)
    groups.append((0x0402, coded_mask([i in set(pos) for i in range(2048)]), "stored"))
    report.append("chinese: %d differing positions, %d Monero words" % (len(diff), len(mz)))

    # the tables of the UI texts (the ranges of the main card, the signer and the language module)
    for lid, name, bn, xn, gs, pre, sep in LANGS:
        tabs = ui_tables(lid)
        if tabs:
            for r in I.RANGES:
                groups.append((UI_GROUP[r] + lid, tabs[r], "lzma"))
            report.append("%s: UI texts of %s texts" % (name, "+".join(str(U.struct.unpack_from("<H", tabs[r], 8)[0] - 1) for r in I.RANGES)))

    # the index of the languages
    idx = bytes([len(LANGS)])
    for lid, name, bn, xn, gs, pre, sep in LANGS:
        flags = (1 if bn else 0) | (2 if xn else 0) | (4 if name.startswith("Chinese") else 0)
        bg = 0x0200 + lid if bn and not bn.startswith("chinese") else (0x0400 if bn == "chinese_simplified" else 0x0401 if bn == "chinese_traditional" else 0)
        xg = xmr_group(lid, name, bn, xn, bip, xmr)
        idx += struct.pack("<BBBBHHBH1x16s4x", lid, flags, gs, pre, bg, xg, sep, 0x0600 + lid if ui_tables(lid) else 0, name.encode()[:16])
    groups.append((0x0001, idx, "stored"))
    groups.sort(key=lambda g: g[0])                                 # the table is in ascending order of id
    groups = [(gid, raw, "lzma_best" if codec == "lzma" and len(P.lzma_best(raw)[0]) < len(raw) else "stored") for gid, raw, codec in groups]   # each its own lc, lp, pb
    return groups, report


def lang_key(mode, w):
    """the key a word is found by when typing (core/lang/langin.c): 0 the letters without accents, 1 the first six kana, 2 the first twelve jamo as codes 1..51"""
    if mode == 0:
        out = b""
        for c in unicodedata.normalize("NFKD", w):
            if 0x300 <= ord(c) < 0x370 or c == "'":                  # (the accents, and Lojban's apostrophe)
                continue
            c = c.lower() if "A" <= c <= "Z" else c
            b = c.encode("utf-8")
            if len(out) + len(b) > 18:
                break
            out += b
        return out
    if mode == 1:
        return w[:6].encode("utf-8")
    codes = []
    for c in unicodedata.normalize("NFD", w):
        n = unicodedata.name(c)
        for kind in ("CHOSEONG", "JUNGSEONG", "JONGSEONG"):
            if n.startswith("HANGUL " + kind + " "):
                codes.append(ord(unicodedata.lookup("HANGUL LETTER " + n[len("HANGUL " + kind + " "):])) - 0x3131 + 1)
    return bytes(codes[:12])


def reference(groups):
    """what tests/test_lang.c has to find after decoding the groups with the C code: the lines of data_ref.txt, from the sources (not from the groups)"""
    lines = []
    sha = lambda b: hashlib.sha256(b).hexdigest()
    bip = {n: W.load_bip(n) for n in set(l[2] for l in LANGS if l[2])}
    xmr = {n: W.load_xmr(n) for n in set(l[3] for l in LANGS if l[3])}
    text = lambda ws: sha(b"".join(w.encode("utf-8") + b"\0" for w in ws))
    for lid, name, bn, xn, gs, pre, sep in LANGS:
        lines.append("lang %d %d %d %d %d %d %d %s" % (lid, (1 if bn else 0) | (2 if xn else 0) | (4 if name.startswith("Chinese") else 0), gs, pre,
                     0x0200 + lid if bn and not bn.startswith("chinese") else (0x0400 if bn == "chinese_simplified" else 0x0401 if bn == "chinese_traditional" else 0),
                     xmr_group(lid, name, bn, xn, bip, xmr), sep, name.replace(" ", "~")))
        if bn and not bn.startswith("chinese"):
            lines.append("list %04x %d %s" % (0x0200 + lid, len(bip[bn]), text(bip[bn])))
        if xn and not xn.startswith("chinese"):
            lines.append("list %04x %d %s" % (xmr_group(lid, name, bn, xn, bip, xmr), len(xmr[xn]), text(xmr[xn])))
    for lid, name, bn, xn, gs, pre, sep in LANGS:                    # the languages with UI texts: the group, the number of texts and the hash of the table of each range
        tabs = ui_tables(lid)
        if tabs:
            for r in I.RANGES:
                lines.append("ui %d %04x %d %s" % (lid, UI_GROUP[r] + lid, U.struct.unpack_from("<H", tabs[r], 8)[0], sha(tabs[r])))
    lines.append("zh 0400 %d %s" % (2048, text(bip["chinese_simplified"])))
    lines.append("zh 0401 %d %s" % (2048, text(bip["chinese_traditional"])))
    lines.append("zh 0402 %d %s" % (len(xmr["chinese_simplified"]), text(xmr["chinese_simplified"])))
    # the glyphs, in the canonical form: the code point and the rows as u16 little endian, ascending code points
    hanzi = sorted(set("".join(bip["chinese_simplified"] + bip["chinese_traditional"])))
    hangul = hangul_set(bip)
    kana = kana_set(bip, xmr)
    uf = unifont(set(map(ord, hanzi + hangul + kana)))
    for gid, chars, src, h in ((0x0101, hanzi, uf, 16), (0x0102, hangul, uf, 16), (0x0103, kana, uf, 16)):
        canon = b"".join(struct.pack("<H", ord(c)) + b"".join(struct.pack("<H", r) for r in src[ord(c)]) for c in chars)
        lines.append("glyphs %04x %d %d %s" % (gid, len(chars), h, sha(canon)))
    # mnemonics of fixed keys in every language: lines  mn39 <language id> <entropy hex> <words joined with |>   and   mnxmr <language id> <key hex> <25 words joined with |>
    # written here from the algorithms (BIP39; Monero's electrum-words.cpp) and checked against bip_utils where that has the language
    from bip_utils import Bip39MnemonicEncoder, Bip39Languages, MoneroMnemonicEncoder, MoneroLanguages
    import zlib
    b39 = {n: getattr(Bip39Languages, n.upper(), None) for n in ("korean", "spanish", "french", "italian", "czech", "portuguese", "chinese_simplified", "chinese_traditional")}
    xm = {n: getattr(MoneroLanguages, n.upper(), None) for n in ("japanese", "spanish", "french", "italian", "portuguese", "chinese_simplified", "dutch", "german", "russian")}
    nfc = lambda w: unicodedata.normalize("NFC", w)

    def bip39_words(lst, e):
        bits = bin(int.from_bytes(e, "big") | (1 << (8 * len(e))))[3:] + bin(hashlib.sha256(e).digest()[0] | 256)[3:][:len(e) * 8 // 32]
        return [lst[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11)]

    def xmr_words(lst, k, prefix):
        n, out = len(lst), []
        for g in range(8):
            v = int.from_bytes(k[4 * g:4 * g + 4], "little")
            w1 = v % n; w2 = (v // n + w1) % n; w3 = (v // n // n + w2) % n
            out += [lst[w1], lst[w2], lst[w3]]
        crc = zlib.crc32("".join(w[:prefix] for w in out).encode("utf-8"))
        return out + [out[crc % 24]]
    ents = [bytes(range(16)), bytes((i * 37 + 11) & 255 for i in range(32)), bytes(24)]
    for lid, name, bn, xn, gs, pre, sep in LANGS:
        if bn:
            for e in ents:
                words = bip39_words(bip[bn], e)
                if b39.get(bn):
                    assert words == [nfc(w) for w in Bip39MnemonicEncoder(b39[bn]).Encode(e).ToList()], "BIP39 reference differs from bip_utils: " + bn
                lines.append("mn39 %d %s %s" % (lid, e.hex(), "|".join(words)))
        if xn:
            for k in (bytes(range(32)), bytes((i * 91 + 5) & 255 for i in range(32))):
                words = xmr_words(xmr[xn], k, pre)
                if xm.get(xn) and xn != "japanese":                      # (bip_utils counts the prefix in decomposed characters, Monero's own lists and wallet in composed ones)
                    assert words == [nfc(w) for w in MoneroMnemonicEncoder(xm[xn]).EncodeWithChecksum(k).ToList()], "Monero reference differs from bip_utils: " + xn
                lines.append("mnxmr %d %s %s" % (lid, k.hex(), "|".join(words)))

    # the typing of the other languages (core/lang/nfkd.c, langin.c): the NFKD of every BIP39 word, the keys the typed letters are matched against, and the seeds of sentences
    # (PBKDF2 of the NFKD sentence, as BIP39 says; the Japanese sentence is joined with U+3000, which the normalisation turns into a space)
    lines.append("hangul %s" % text([unicodedata.normalize("NFKD", chr(c)) for c in range(0xAC00, 0xD7A4)]))
    for lid, name, bn, xn, gs, pre, sep in LANGS:
        if not bn:
            continue
        ws = bip[bn]
        lines.append("nfkd %d %s" % (lid, text([unicodedata.normalize("NFKD", w) for w in ws])))
        mode = 1 if bn == "japanese" else 2 if bn == "korean" else 0 if not bn.startswith("chinese") else -1
        if mode >= 0:
            lines.append("keys %d %d %s" % (lid, mode, sha(b"".join(lang_key(mode, w).ljust(19, b"\0") for w in ws))))
        for e in ents:
            words = bip39_words(ws, e)
            for pw in ("", "TREZOR"):
                sent = unicodedata.normalize("NFKD", ("\u3000" if bn == "japanese" else " ").join(words))
                seed = hashlib.pbkdf2_hmac("sha512", sent.encode("utf-8"), ("mnemonic" + pw).encode("utf-8"), 2048)
                lines.append("seed %d %s %s %s" % (lid, e.hex(), pw if pw else "-", seed.hex()))
    return lines


def build(pub=None):
    groups, report = build_groups()
    pkg, key = P.build(2, groups, pub=pub)                          # signed with the key of tools/sign_key.py (pub: left unsigned for the Nostr signer of that key, see `attach`)
    return pkg, key, groups, report


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build"); b.add_argument("--out", default=os.path.join(ROOT, "build", "release", "m5", "data.pkg"))
    b.add_argument("--pub", help="sign later with a Nostr signer: its x only public key (64 hex digits); writes data_event.json (what to sign) and leaves the signature zero")
    t = sub.add_parser("attach", help="put the signature of the Nostr signer into the package and make the card again"); t.add_argument("pkg"); t.add_argument("--pub", required=True); t.add_argument("--sig", required=True)
    i = sub.add_parser("info"); i.add_argument("pkg")
    args = ap.parse_args()
    if args.cmd == "build":
        ext = bytes.fromhex(args.pub) if args.pub else None
        pkg, pin, groups, report = build(ext)                        # pin: the public key that signed it
        entries = P.parse(pkg, key=pin if not ext else None, kind=2)["entries"]         # the checks of the loader on what was made
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        open(args.out, "wb").write(pkg)
        open(os.path.splitext(args.out)[0] + ".json", "w").write(json.dumps({"key": pin.hex(), "size": len(pkg), "groups": [{"id": "%04x" % e["id"], "len": e["len"], "rawlen": e["rawlen"]} for e in entries]}, indent=1))
        card = M.blank_card()
        M.add_file(card, DATA_NAME, pkg, "PSXX data")
        open(os.path.join(os.path.dirname(args.out), "C-ok.mcd"), "wb").write(card)
        open(os.path.join(os.path.dirname(args.out), "data_ref.txt"), "w", newline="\n", encoding="utf-8").write("\n".join(reference(groups)) + "\n")
        for r in report: print(r)
        for e in entries:
            print("group %04x  %6d bytes stored, %6d raw" % (e["id"], e["len"], e["rawlen"]))
        nb = M.blocks_needed(len(pkg))
        print("package %d bytes (a card holds %d), %d blocks (the last one %d of %d bytes used), pin %s" % (len(pkg), P.MAX_SIZE, nb, len(pkg) - M.capacity(nb - 1), M.BLOCK_DATA, pin.hex()))
        print("wrote", args.out)
        assert len(pkg) <= P.MAX_SIZE, "the package does not fit a card"
        if ext:
            te = P.HEADER + len(entries) * P.ENTRY
            dg = P.digest(pkg[:te]).hex()
            open(os.path.join(os.path.dirname(args.out), "data_event.json"), "w").write(json.dumps({"kind": P.EVENT_KIND, "created_at": P.EVENT_TIME, "tags": [["d", dg]], "content": dg}, separators=(",", ":")))
            print("the package is not signed yet: the signer (key %s) signs data_event.json, then  data_pack.py attach %s --pub %s --sig <128 hex digits>" % (ext.hex(), args.out, ext.hex()))
    elif args.cmd == "attach":
        data = open(args.pkg, "rb").read()
        pub, sig = bytes.fromhex(args.pub), bytes.fromhex(args.sig)
        te = P.HEADER + struct.unpack_from("<H", data, 6)[0] * P.ENTRY
        if len(sig) != P.SIG or not P.bip340.verify(pub, P.message(data[:te], pub), sig):
            sys.exit("the signature is not valid for this package and the key %s" % pub.hex())
        data = data[:te] + sig + data[te + P.SIG:]
        P.parse(data, key=pub, kind=2)
        open(args.pkg, "wb").write(data)
        card = M.blank_card()
        M.add_file(card, DATA_NAME, data, "PSXX data")
        open(os.path.join(os.path.dirname(os.path.abspath(args.pkg)), "C-ok.mcd"), "wb").write(card)
        print("signature attached to %s, C-ok.mcd made again" % args.pkg)
    else:
        data = open(args.pkg, "rb").read()
        for e in P.parse(data, kind=2)["entries"]:
            print("group %04x  %6d stored  %6d raw" % (e["id"], e["len"], e["rawlen"]))


if __name__ == "__main__":
    main()
