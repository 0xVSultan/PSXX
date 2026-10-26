"""Builds the frozen verifier page (spa/): one HTML file, no external requests, the script and the style pinned by hash in a strict Content-Security-Policy.

  py -3.13 tools/build_spa.py [-o build/spa/psxx-verify.html]

The sources are spa/src/*.js in a fixed order, spa/src/style.css and spa/src/page.html; the output is the same bytes every time (no date, no path). Prints its size and SHA-256 (the
value that goes into the release manifest)."""
import argparse, base64, hashlib, os

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SRC = os.path.join(ROOT, "spa", "src")
ORDER = ["core.js", "secp.js", "lzma.js", "fmt.js", "verify.js"]
VERSION = "v1"


def read(n):
    return open(os.path.join(SRC, n), encoding="utf-8", newline="").read().replace("\r\n", "\n")


def b64(s):
    return base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()


def script(with_ui=True):
    return "\n".join(read(n) for n in ORDER + (["ui.js"] if with_ui else []))


def build():
    js, css = "\n" + script() + "\n", "\n" + read("style.css")
    page = read("page.html")
    for k, v in (("@CSS@", css), ("@JS@", js), ("@JSHASH@", b64(js)), ("@CSSHASH@", b64(css)), ("@VERSION@", VERSION)):
        page = page.replace(k, v)
    return page.encode("utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", default=os.path.join(ROOT, "build", "spa", "psxx-verify.html"))
    a = ap.parse_args()
    out = build()
    os.makedirs(os.path.dirname(a.o), exist_ok=True)
    open(a.o, "wb").write(out)
    print("%s: %d bytes, sha256 %s" % (a.o, len(out), hashlib.sha256(out).hexdigest()))


if __name__ == "__main__":
    main()
