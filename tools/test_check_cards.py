"""Tests of the Python card checker (tools/release_manifest.py check_cards) on the trophy release, the same cases as spa/test/run.js; needs build/release/trophy_nostr, trophy_cards
and the test manifest (py -3.13 spa/test/gen_manifest.py, a throwaway key).

  py -3.13 tools/test_check_cards.py"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import release_manifest as RM

ROOT = os.path.normpath(os.path.join(HERE, ".."))
rel, cards = (os.path.join(ROOT, "build", "release", d) for d in ("trophy_nostr", "trophy_cards"))
mf = os.path.join(ROOT, "build", "spa", "test_manifest.json")
rd = lambda d, f: open(os.path.join(d, f), "rb").read()
ev = open(os.path.join(cards, "trophy_event.json"), encoding="utf-8").read()
key = json.load(open(os.path.join(rel, "release.json")))["key"]
bcard, pkg = rd(cards, "trophy_B-ok.mcd"), rd(rel, "overlay.pkg")
acards = sorted(f for f in os.listdir(cards) if f.startswith("trophy_") and f[7].isdigit())
fails = 0


def st(res, title):
    return next((s for s, t, _ in res if t == title), None)


def check(name, cond):
    global fails
    print("%-70s %s" % (name, "ok" if cond else "FAILED"))
    fails += not cond


def run(**kw):
    kw.setdefault("trust", key)
    return RM.check_cards(kw.get("boot"), kw.get("others", []), kw.get("event", ev), kw.get("manifest", ""), kw["trust"], kw.get("size", 0))


nf = lambda res: any(s == "fail" for s, _, _ in res)
r = run(others=[("B", bcard)])
check("B card, event, key: nothing fails", not nf(r) and st(r, "B: signature") == "ok" and st(r, "Event vs package") == "ok")
r = run(others=[("pkg", pkg)])
check("bare package file", not nf(r))
for f in acards:
    r = run(others=[("B", bcard)], boot=rd(cards, f), size=294912)
    check("boot card %s with B" % f, not nf(r) and st(r, "Program vs package") == "ok" and st(r, "Release record key") == "ok" and st(r, "Loader") == "warn")
r = run(others=[("dmg", rd(cards, "trophy_B-damaged.mcd"))])
check("damaged B card refused", st(r, "dmg: groups") == "fail")
r = run(others=[("empty", rd(cards, "trophy_B-empty.mcd"))])
check("empty B card: no package, no error", st(r, "empty") == "info")
r = run(others=[("B", bcard)], trust="00" * 31 + "01")
check("wrong trusted key", st(r, "Package event: key") == "fail")
a = bytearray(rd(cards, acards[0]))
a[0x2300 + 5000] ^= 1
r = run(others=[("B", bcard)], boot=bytes(a), size=294912)
check("changed program byte", nf(r))
p2 = bytearray(pkg)
p2[16] ^= 1
r = run(others=[("p", bytes(p2))])
check("changed package header", nf(r))
e2 = json.loads(ev)
e2["content"] = ("1" if e2["content"][0] == "0" else "0") + e2["content"][1:]
r = run(others=[("pkg", pkg)], event=json.dumps(e2))
check("changed event", nf(r))
if os.path.exists(mf):
    man = open(mf, encoding="utf-8").read()
    mk = json.loads(man)["pubkey"]
    for f in acards:
        r = RM.check_cards(rd(cards, f), [("B", bcard)], "", man, mk)
        check("manifest: whole boot card %s" % f, st(r, "Loader") == "ok" and st(r, "Program vs manifest") == "ok")
        b = bytearray(rd(cards, f))
        off = next(c for c in json.loads(json.loads(man)["content"])["cards"] if c["name"] == f)["payload_offset"]
        b[off - 300] ^= 1
        r = RM.check_cards(bytes(b), [("B", bcard)], "", man, mk)
        check("manifest: changed loader byte %s" % f, st(r, "Loader") == "fail" and st(r, "Program image") == "ok")
    r = RM.check_cards(None, [], "", man, "00" * 31 + "01")
    check("manifest of another key", st(r, "Release manifest: key") == "fail")
print("%d failed" % fails)
sys.exit(1 if fails else 0)
