#!/usr/bin/env python3
"""Moves the texts of a source file into the identifiers: every string literal (adjacent literals and icon macros joined) that is a text of tools/strings/en_<range>.txt
is replaced by T(TXT_<NAME>).

  py -3 tools/ui_convert.py FILE... [--write] [--add]      without --write only reports what would change

  --add     a text that is not in the lists yet is added to the list of the range of the file (tools/ui_ids.py range_of_file) first
  --write   changes the files (and adds #include "tr.h" to a file of core/ that has none)

What it does not touch: literals in the calls that do not show them (LOG, strcmp, the hashes ... as in tools/ui_lint.py), texts that are not in the lists (they are listed). A literal in the
initialiser of a file level variable cannot become a call: it becomes the bare identifier TXT_<NAME> and is listed as "file level": the type of that variable has to be made an identifier
(uint16_t) by hand and T() put where it is used. Other places that the compiler does not accept (a case label, a char array) are found by the compiler."""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import csrc
import ui_ids as I
import ui_lint as L


def name_map():
    m = {}
    en = I.load_english()
    for r in I.RANGES:
        for name, text in en[r]:
            m[text] = name
    return m


def file_level_offsets(src):
    """the start offsets of the string literals that sit in the initialiser of a variable outside every function"""
    toks = csrc.tokens(src)
    out, stack, init, depth_paren = set(), [], False, 0
    prev = None
    for k, v, ln, a, b in toks:
        if k == "p" and v == "{":
            if not stack:
                stack.append("init" if (prev and prev[0] == "p" and prev[1] == "=") or init else "other")
            else:
                stack.append(stack[0])
        elif k == "p" and v == "}":
            if stack: stack.pop()
            if not stack: init = False
        elif k == "p" and v == ";" and not stack:
            init = False
        elif k == "p" and v == "=" and not stack:
            init = True
        elif k == "p" and v == "(":
            depth_paren += 1
        elif k == "p" and v == ")":
            depth_paren -= 1
        if k == "str" and ((stack and stack[0] == "init") or (not stack and init and depth_paren == 0)):
            out.add(a)
        prev = (k, v)
    return out


def with_include(out, rel):
    if rel.startswith("core/") and not re.search(r'#include\s+"(tr|ui_text)\.h"', out):
        lines = out.split("\n")
        last = max((i for i, l in enumerate(lines[:60]) if l.startswith("#include")), default=-1)
        eol = "\r" if lines and lines[0].endswith("\r") else ""
        lines.insert(last + 1, '#include "tr.h"' + eol)
        return "\n".join(lines)
    return out


def add_to_list(text, rng, m, write):
    """append a text to en_<rng>.txt with a new unique name (only with --write); returns the name"""
    names = set(m.values())
    base = I.slug(text)
    name, k = base, 2
    while name in names:
        name = "%s_%d" % (base, k)
        k += 1
    if write:
        with open(I.path_of("en", rng), "a", encoding="utf-8", newline="\n") as f:
            f.write("%s\t%s\n" % (name, I.U.esc(text)))
    m[text] = name
    return name


def convert(path, m, write, add):
    rel = os.path.relpath(os.path.abspath(path), ROOT).replace("\\", "/")
    src = open(path, encoding="utf-8", errors="replace", newline="").read()
    seqs = csrc.sequences(src)
    fl = file_level_offsets(src)
    edits, unknown, filelevel, added = [], [], [], 0
    allow = L.load_allow()
    for ln, text, callee, a, b in seqs:
        if L.ignored_call(callee):
            continue
        if text not in m and L.is_text(text.decode("utf-8", "replace"), allow):
            if add:
                add_to_list(text, I.range_of_file(rel), m, write)
                added += 1
            else:
                unknown.append((ln, text))
                continue
        if text in m and not L.is_text(text.decode("utf-8", "replace"), allow):
            continue                                         # the same in every language: it stays in the code
        if text in m:
            if a in fl:
                edits.append((a, b, "TXT_%s" % m[text]))
                filelevel.append((ln, text))
            else:
                edits.append((a, b, "T(TXT_%s)" % m[text]))
    out = src
    for a, b, rep in sorted(edits, reverse=True):
        out = out[:a] + rep + out[b:]
    if edits:
        out = with_include(out, rel)
    if write and edits:
        open(path, "w", encoding="utf-8", newline="").write(out)
    return len(edits), unknown, filelevel, added


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    write = "--write" in sys.argv
    add = "--add" in sys.argv
    if not args:
        raise SystemExit(__doc__)
    m = name_map()
    for f in args:
        n, unknown, filelevel, added = convert(f, m, write, add)
        print("%s: %d text(s) %s, %d added to the lists, %d not in the lists, %d file level" % (f, n, "replaced" if write else "to replace", added, len(unknown), len(filelevel)))
        for ln, t in unknown:
            print("   not in the lists, %d: %r" % (ln, t.decode("utf-8", "replace")))
        for ln, t in filelevel:
            print("   file level, %d: %r" % (ln, t.decode("utf-8", "replace")))


if __name__ == "__main__":
    main()
