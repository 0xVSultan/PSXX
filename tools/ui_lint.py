#!/usr/bin/env python3
"""No text in the code: looks for the string literals of the sources that are texts of the screens.

  py -3 tools/ui_lint.py                 the files of tools/strings/ui_lint_files.txt (the ones that have been moved to identifiers) must have none: exit 1 when they do
  py -3 tools/ui_lint.py --report        how many every source file has (nothing is an error)
  py -3 tools/ui_lint.py FILE...         those files, listing the literals

A literal is a text of the screens when it is not in a call that does not show it (LOG, printf, strcmp ...), it has a run of 3 letters, and it is not allowed: tools/strings/ui_allow.txt lists
what is the same in every language (names of the coins and of the console, units, formats of numbers); a line is an exact text, or re:<regular expression> for the whole text. Adjacent literals and
the button icons (ICO_CROSS ...) make one text, as the compiler sees it. The check works on the source text (it does not run the preprocessor): a literal that a macro hides is not seen."""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import csrc

ALLOW = os.path.join(HERE, "strings", "ui_allow.txt")
FILES = os.path.join(HERE, "strings", "ui_lint_files.txt")

# calls whose literals are not shown to the user (the TTY log, comparisons, the protocol)
IGNORE_CALLS = {"LOG", "printf", "fprintf", "puts", "assert", "strcmp", "strncmp", "memcmp", "strstr", "strchr", "strcasecmp", "sizeof", "bg_log", "boot_report",
                "__attribute__", "_Static_assert", "static_assert", "fopen", "memcpy", "sscanf", "getenv", "psxx_log", "tty_printf", "dbg", "DBG", "PROF"}
IGNORE_PREFIXES = ("merlin_", "sha256", "sha512", "blake2b", "keccak", "hmac", "ripemd", "hash160", "pbkdf2", "argon2", "chacha")


def ignored_call(c):
    return c in IGNORE_CALLS or c.startswith(IGNORE_PREFIXES)


def literals(path):
    """[(line, text, callee)] of the string literals (adjacent ones, and icon macros between them, joined)"""
    src = open(path, encoding="utf-8", errors="replace").read()
    return [(ln, t.decode("utf-8", "replace"), c) for ln, t, c, _, _ in csrc.sequences(src)]


def load_allow():
    exact, regs = set(), []
    if os.path.exists(ALLOW):
        for line in open(ALLOW, encoding="utf-8"):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            if line.startswith("re:"):
                regs.append(re.compile(line[3:]))
            else:
                exact.add(line)
    return exact, regs


def is_text(s, allow):
    exact, regs = allow
    if re.search(r"[A-Za-z]{3}", s) is None:
        return False
    if re.match(r"^\[[a-z0-9 ]+\]", s):                      # TTY diagnostics
        return False
    if s in exact or any(r.fullmatch(s) for r in regs):
        return False
    if re.fullmatch(r"[A-Za-z0-9_./:%-]+", s) and not s[0].isupper():
        return False                                          # file names, identifiers, option names
    if re.fullmatch(r"[A-Za-z0-9_]+", s) and re.search(r"[a-z][A-Z]|_|\d", s):
        return False                                          # identifiers and tags
    if " " not in s and (len(s) >= 40 or s.endswith("(") or "/" in s):
        return False                                          # alphabets, descriptor pieces, domain separators
    return True


def check(path, allow):
    return [(ln, s, c) for ln, s, c in literals(path) if not ignored_call(c) and is_text(s, allow)]


def sources():
    out = []
    for d in ("hal/psx", "core"):
        for dp, _, fs in os.walk(os.path.join(ROOT, d)):
            out += [os.path.join(dp, f) for f in fs if f.endswith((".c", ".h")) and not any(x in f for x in ("bench", "probe", "hidetest", "kbtest", "bss_test", "ovl_demo", "ovl_base_demo", "main.c"))]
    return sorted(out)


def main():
    args = sys.argv[1:]
    allow = load_allow()
    if args == ["--report"]:
        tot = 0
        for f in sources():
            r = check(f, allow)
            if r:
                print("%4d %s" % (len(r), os.path.relpath(f, ROOT).replace("\\", "/")))
                tot += len(r)
        print("%4d literals that are texts" % tot)
        return 0
    if args:
        bad = 0
        for f in args:
            for ln, s, c in check(f, allow):
                print("%s:%d: %r (in %s)" % (f, ln, s, c or "-"))
                bad += 1
        return 1 if bad else 0
    bad = 0
    files = []
    if os.path.exists(FILES):
        files = [l.strip() for l in open(FILES, encoding="utf-8") if l.strip() and not l.startswith("#")]
    for f in files:
        for ln, s, c in check(os.path.join(ROOT, f), allow):
            print("%s:%d: text in the code, use an identifier: %r (in %s)" % (f, ln, s, c or "-"))
            bad += 1
    print("ui_lint: %d file(s) checked, %d text(s) in the code" % (len(files), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
