#!/usr/bin/env python3
"""Test vectors of the text tables by identifier (hal/psx/ui_text.c, tools/ui_ids.py) for tests/test_uitext.c (tests/uitext_vectors.txt):

  py -3.13 tools/gen_uitext_vectors.py

Lines:  tab <range> <lang> <tab_id hex> <n> <blob hex>    a table that has to be accepted
        bad <range> <lang> <tab_id hex> <n> <blob hex>    a table that has to be refused (nothing changes)
        lang <0|1|2>                                      the language of the screens
        text <id> <answer hex>                            ui_text(id) has to give this (the English one when the language has none, "" for an unknown id)
        en <id> <answer hex>                              ui_text_en(id)
        clear <range>                                     ui_range_clear (English and Hungarian tables of the range; not the language of the data card)
        have <lang> <0|1>                                 ui_lang_have(lang)
        cycle <lang>                                      ui_lang_cycle() has to give this language
        getlang <lang>                                    ui_lang_get()
        extclear                                          ui_ext_clear
The tables are made by the packer of tools/ui_ids.py from lists of their own (the ranges a: 21 texts, b: 9 texts)."""
import os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ui_ids as I

hx = lambda b: b.hex()

EN_A = [("T%d" % i, ("Text number %d" % i).encode()) for i in range(21)]
EN_A[3] = ("T3", b"Hold \x01 to show %d of %d")
EN_A[8] = ("T8", b"Back")
EN_A[16] = ("T16", b"The sixteenth, 100%% sure")
EN_B = [("B%d" % i, ("Signer %d" % i).encode()) for i in range(9)]
EN_B[0] = ("B0", b"Sign it")
EN_B[8] = ("B8", b"%s sends %s")
HU_A = {"T3": "Tartsd: \x01 %d / %d".encode(), "T8": "Vissza".encode(), "T16": "A tizenhatodik, 100%% biztos".encode(), "T20": "Húsz: árvíztűrő tükörfúrógép".encode(), "T0": b"Nulla"}
HU_B = {"B8": "%s küld: %s".encode(), "B0": "Aláírás".encode()}
EXT_A = {"T8": b"Retour", "T9": b"Neuf"}                      # a language that has only two texts

NA, NB = len(EN_A) + 1, len(EN_B) + 1                     # number 0 of every table is the empty text (tools/ui_ids.py)
rows = []
tid_a, tid_b = I.tab_id(EN_A), I.tab_id(EN_B)
en_a, en_b = I.table_for(EN_A, dict(EN_A)), I.table_for(EN_B, dict(EN_B))
hu_a, hu_b = I.table_for(EN_A, HU_A), I.table_for(EN_B, HU_B)
ext_a = I.table_for(EN_A, EXT_A)
for errs in (I.problems(EN_A, HU_A), I.problems(EN_B, HU_B), I.problems(EN_A, EXT_A)):
    assert not errs, errs


def tab(r, lang, tid, n, blob):
    return "tab %d %d %08x %d %s" % (r, lang, tid, n, hx(blob) or "-")


def bad(r, lang, tid, n, blob):
    return "bad %d %d %08x %d %s" % (r, lang, tid, n, hx(blob) or "-")


def uid(r, i):
    return r << 12 | (i + 1)             # i: the place in the list of the fixture


def raw(r, i):
    return r << 12 | i


rows += [tab(0, 0, tid_a, NA, en_a), tab(1, 0, tid_b, NB, en_b)]
# English: every text of both ranges, and what is not there
rows.append("lang 0")
rows += ["text %d %s" % (raw(0, 0), ""), "text %d %s" % (raw(1, 0), "")]
for i, (_, t) in enumerate(EN_A):
    rows.append("text %d %s" % (uid(0, i), hx(t)))
for i, (_, t) in enumerate(EN_B):
    rows.append("text %d %s" % (uid(1, i), hx(t)))
rows += ["text %d %s" % (uid(0, 21), ""), "text %d %s" % (uid(1, 9), ""), "text %d %s" % (raw(1, 4095), ""),
         "text %d %s" % (uid(2, 0), ""), "text %d %s" % (uid(3, 0), ""), "text %d %s" % (uid(15, 7), "")]   # past the end, a range that has no table, no such range
# Hungarian is not there yet: English
rows.append("lang 1")
rows += ["text %d %s" % (raw(0, 0), ""), "text %d %s" % (raw(1, 0), "")]
for i, (_, t) in enumerate(EN_A):
    rows.append("text %d %s" % (uid(0, i), hx(t)))
rows += [tab(0, 1, tid_a, NA, hu_a), tab(1, 1, tid_b, NB, hu_b)]
for i, (n, t) in enumerate(EN_A):
    rows.append("text %d %s" % (uid(0, i), hx(HU_A.get(n) or t)))
for i, (n, t) in enumerate(EN_B):
    rows.append("text %d %s" % (uid(1, i), hx(HU_B.get(n) or t)))
rows.append("en %d %s" % (uid(0, 8), hx(b"Back")))                  # English whatever the language is
rows.append("en %d %s" % (uid(0, 21), ""))
# the language of the data card: only two texts, the rest English (not Hungarian)
rows.append("lang 2")
for i, (n, t) in enumerate(EN_A):
    rows.append("text %d %s" % (uid(0, i), hx(t)))                  # no table yet
rows.append(tab(0, 2, tid_a, NA, ext_a))
for i, (n, t) in enumerate(EN_A):
    rows.append("text %d %s" % (uid(0, i), hx(EXT_A.get(n) or t)))
rows.append("text %d %s" % (uid(1, 8), hx(EN_B[8][1])))             # the range b has no table of this language: English
# a table can be replaced, taken away, a range goes away with its module
rows.append("lang 1")
rows.append(tab(0, 1, tid_a, NA, I.table_for(EN_A, {"T8": "Hátra".encode()})))
rows.append("text %d %s" % (uid(0, 8), hx(b"H\xc3\xa1tra")))
rows.append("text %d %s" % (uid(0, 3), hx(EN_A[3][1])))
rows.append("clear 1")
rows.append("text %d %s" % (uid(1, 0), ""))                         # the range of the signer is gone
rows.append("text %d %s" % (uid(0, 8), hx(b"H\xc3\xa1tra")))        # the main one is not
# the languages that the main card has, the cycle through them, and the language of the data card going away
rows.append("lang 0")
rows += ["have 0 1", "have 1 1", "have 2 1", "have 3 0", "have -1 0"]
rows += ["cycle 1", "cycle 2", "cycle 0", "cycle 1"]
rows += ["lang 2", "extclear", "have 2 0", "getlang 0"]               # the language of the screens was that one: English comes back
rows += ["have 1 1", "cycle 1", "cycle 0", "cycle 1"]                 # without it: English and Hungarian
rows.append("text %d %s" % (uid(0, 8), hx(b"H\xc3\xa1tra")))           # the tables of the other languages are not touched
# refused tables (and the old ones stay)
good = hu_a
bads = [
    (0, 1, tid_a, NA, b""),
    (0, 1, tid_a, NA, good[:11]),
    (0, 1, tid_a, NA, b"UD1\0" + good[4:]),                  # the magic
    (0, 1, tid_a ^ 1, NA, good),                             # a table of another list of texts
    (0, 1, tid_a, NA + 1, good),                             # the number of texts
    (0, 1, tid_a, NA - 1, good),
    (0, 1, tid_a, NA, good[:-1]),                            # the last text is not ended
    (0, 1, tid_a, NA, good + b"x\0"),                        # something after the last text
    (0, 1, tid_a, NA, good[:-2]),                            # a text is missing / cut
    (0, 1, tid_a, NA, good[:12] + struct.pack("<H", 1) + good[14:]),   # an anchor that is wrong
    (0, 1, tid_a, NA, good[:10] + b"\x01\x00" + good[12:]),  # the reserved word
    (0, 3, tid_a, NA, good),                                 # no such language
    (5, 1, tid_a, NA, good),                                 # no such range
    (0, 1, tid_a, 0, good),
]
for b in bads:
    rows.append(bad(*b))
rows.append("text %d %s" % (uid(0, 8), hx(b"H\xc3\xa1tra")))        # nothing changed
rows.append("text %d %s" % (uid(0, 3), hx(EN_A[3][1])))
out = os.path.join(HERE, "..", "tests", "uitext_vectors.txt")
with open(out, "w", newline="\n") as f:
    f.write("# generated by tools/gen_uitext_vectors.py: do not edit\n" + "\n".join(rows) + "\n")
print("%d lines -> %s" % (len(rows), os.path.abspath(out)))
