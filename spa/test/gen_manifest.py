"""A signed test manifest (throwaway key, NOT a release key) over the trophy cards: build/spa/test_manifest.json, to try the manifest paths of spa/test/run.js.

  py -3.13 spa/test/gen_manifest.py"""
import hashlib, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import bip340

rel = os.path.join(ROOT, "build", "release", "trophy_nostr")
cards = os.path.join(ROOT, "build", "release", "trophy_cards")
sk = hashlib.sha256(b"psxx spa test manifest key").digest()
pub = bip340.pubkey(sk)
work = os.path.join(ROOT, "build", "spa", "manifest_try")           # the manifest is made by the release tool itself (tools/release_manifest.py), then signed with the throwaway key
os.makedirs(work, exist_ok=True)
for f in ("release.json", "overlay.pkg", "base_packed.exe", "base.exe"):
    open(os.path.join(work, f), "wb").write(open(os.path.join(rel, f), "rb").read())
subprocess.run([sys.executable, os.path.join(ROOT, "tools", "release.py"), "manifest", work, "--cards", cards, "--name", "test", "--version", "0", "--date", "2026-10-26",
                "--created-at", "1792774136"], check=True, capture_output=True)
mev = json.load(open(os.path.join(work, "manifest_event.json"), encoding="utf-8"))
content = mev["content"]
ev = [0, pub.hex(), 1792774136, 30078, mev["tags"], content]
eid = hashlib.sha256(json.dumps(ev, separators=(",", ":"), ensure_ascii=False).encode()).digest()
out = {"id": eid.hex(), "pubkey": pub.hex(), "created_at": ev[2], "kind": 30078, "tags": ev[4], "content": content, "sig": bip340.sign(sk, eid).hex()}
os.makedirs(os.path.join(ROOT, "build", "spa"), exist_ok=True)
json.dump(out, open(os.path.join(ROOT, "build", "spa", "test_manifest.json"), "w"))
print("test manifest by", pub.hex()[:16], "with", len(json.loads(content)["cards"]), "cards")
