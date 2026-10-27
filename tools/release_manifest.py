"""The release manifest and the independent checker of the cards (section 5, the Python twin of the verifier page spa/).

  py -3.13 tools/release.py manifest <release dir> --cards <cards dir> --name trophy [--version V] [--date YYYY-MM-DD] [--source-rev REV] [--spa FILE]
  py -3.13 tools/release.py attach-manifest <release dir> --sig <128 hex digits>
  py -3.13 tools/release.py check-cards --trust <npub|hex> --manifest manifest_signed.json --event package_event.json --boot <card> [--other <card> ...]

manifest:  <release dir> holds what `release.py build --pub` made (release.json, overlay.pkg, base_packed.exe), --cards the memory card images of the release (every *.mcd). Writes into <release dir>:
           manifest_event.json (the unsigned Nostr event, kind 30078, d = psxx/release/<name>, content = the canonical JSON of the manifest), a card with the request for the signer
           (manifest_request.mcd: a copy of the first B card with the request on it). The manifest lists every card with its SHA-256; a boot card (the one that holds the packed program of
           base_packed.exe) also with the place of the program and the SHA-256 of the card with the program zeroed (loader_sha256): the loader is not part of the base id.
attach-manifest: the signature of the signer goes into the event: manifest_signed.json, and the package event (package_event.json), the two files to publish (tools/nostr_publish.py) and to hand to the verifier.
check-cards: the checks of the verifier page, from files, exit status 1 when one fails. Written separately from the page (own LZMA use, own bech32), so that the two agree only when both are right."""
import hashlib, json, lzma, os, re, struct, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import bip340
import mkcard as M
import pkg_pack as P
import psxx_tx

SCHEMA = "psxx-release/1"
REC_MAGIC = b"PSXXREL1"
PIN_AT, BASE_AT = 8, 40
BIOS_RE = re.compile(r"(\d\.\d-\d{8}-[A-Z])")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True).stdout


def tool_hashes():
    """the build tools by SHA-256"""
    out = {}
    for key, rel in (("gcc", "toolchain/gcc/bin/mipsel-none-elf-gcc.exe"), ("ld", "toolchain/gcc/bin/mipsel-none-elf-ld.exe"), ("objcopy", "toolchain/gcc/bin/mipsel-none-elf-objcopy.exe"),
                     ("freepsxboot_builder", "toolchain/FreePSXBoot/builder/builder.exe")):
        p = os.path.join(ROOT, rel)
        out[key] = {"path": rel, "sha256": sha(open(p, "rb").read())} if os.path.exists(p) else {"path": rel, "sha256": None}
    lib = os.path.join(ROOT, "toolchain", "sdk", "PSn00bSDK-0.24-win32", "lib", "libpsn00b", "release")      # the SDK libraries: one hash over all the files (relative path and SHA-256, sorted)
    if os.path.isdir(lib):
        names = sorted(os.path.relpath(os.path.join(r, f), lib).replace("\\", "/") for r, _, fs in os.walk(lib) for f in fs)
        out["sdk_libs"] = {"path": "toolchain/sdk/PSn00bSDK-0.24-win32/lib/libpsn00b/release", "files": len(names),
                           "sha256": sha("".join("%s %s\n" % (n, sha(open(os.path.join(lib, n), "rb").read())) for n in names).encode())}
    out["python"] = sys.version.split()[0]
    return out


def package_event(pkg, pub):
    """the complete signed Nostr event of a package (the one tools/nostr_publish.py sends)"""
    import nostr_publish
    return nostr_publish.event_of(pkg, pub)


def describe_card(e):
    """a sentence for a person about a card file of the set"""
    n = e["name"]
    if e["role"] == "boot":
        return "Boot card for PlayStation BIOS %s: starts the program from memory card slot 1." % (e.get("bios") or "(see the file name)")
    if "C-ok" in n or n.endswith("_C.mcd"):
        return "Language card (C): holds the signed data package with the extra languages (word lists and glyphs). Goes with the boot card and the signer card of the same release."
    if "damaged" in n:
        return "Test card: the signer package with one changed byte. The console must refuse it; do not use it for real keys."
    if "empty" in n:
        return "Test card: a blank card without a package. The console must say that the signer is missing."
    if n.endswith("B-ok.mcd") or "-ok" in n or "_ok" in n:
        return "Signer card (B): holds the signed overlay package with the signer and the language module. Goes with a boot card of the same release."
    return "Memory card image of the release."


def manifest(a):
    d = os.path.abspath(a.dir)
    cdir = os.path.abspath(a.cards)
    rel = json.load(open(os.path.join(d, "release.json")))
    pub = bytes.fromhex(rel["key"])
    pkg = open(os.path.join(d, "overlay.pkg"), "rb").read()
    package_event(pkg, pub)                                                     # raises when the package is not signed for the key
    payload = open(os.path.join(d, "base_packed.exe"), "rb").read()[2048:]
    cards, boot_n = [], 0
    for f in sorted(os.listdir(cdir)):
        if not f.endswith(".mcd"):
            continue
        data = open(os.path.join(cdir, f), "rb").read()
        e = {"name": f, "size": len(data), "sha256": sha(data), "role": "other"}
        at = data.find(payload[:128])
        if at >= 0 and data[at:at + len(payload)] == payload:
            z = bytearray(data)
            z[at:at + len(payload)] = bytes(len(payload))
            m = BIOS_RE.search(f)
            e.update({"role": "boot", "bios": m.group(1) if m else None, "payload_offset": at, "payload_len": len(payload), "loader_sha256": sha(bytes(z))})
            boot_n += 1
        e["description"] = describe_card(e)
        cards.append(e)
    if not boot_n:
        sys.exit("no boot card in %s holds the packed program of %s" % (cdir, d))
    rev = a.source_rev or "HEAD"
    tree = git("rev-parse", rev + "^{tree}").decode().strip()
    archive = sha(git("archive", "--format=tar", rev))
    dirty = bool(git("status", "--porcelain", "--untracked-files=no").strip()) if rev == "HEAD" else None
    content = {
        "schema": SCHEMA, "description": open(a.description_file, encoding="utf-8").read().strip() if a.description_file else None, "name": a.name, "version": a.version or a.name, "date": a.date, "key": rel["key"], "base_id": rel["base_id"],
        "a": {"image_size": _image_size(d), "lzma": "1,2,2"},
        "package": {"name": "overlay.pkg", "size": len(pkg), "sha256": sha(pkg), "digest": P.digest(pkg[:P.HEADER + struct.unpack_from("<H", pkg, 6)[0] * P.ENTRY]).hex(),
                    "event_id": rel.get("event_id")},
        "source": {"git_tree": tree, "git_archive_tar_sha256": archive, "tree_dirty": dirty},
        "tools": tool_hashes(),
        "cards": cards,
    }
    dp = os.path.join(d, "data.pkg")
    if os.path.exists(dp):
        db = open(dp, "rb").read()
        dte = P.HEADER + struct.unpack_from("<H", db, 6)[0] * P.ENTRY
        package_event(db, pub)                                                  # raises when the data package is not signed for the key
        content["data_package"] = {"name": "data.pkg", "size": len(db), "sha256": sha(db), "digest": P.digest(db[:dte]).hex(), "event_id": P.message(db[:dte], pub).hex()}
    if a.spa:
        s = open(a.spa, "rb").read()
        content["verifier"] = {"name": os.path.basename(a.spa), "size": len(s), "sha256": sha(s)}
    ev = {"kind": P.EVENT_KIND, "created_at": a.created_at or int(__import__("time").time()),
          "tags": [["d", "psxx/release/" + a.name], ["alt", a.alt or "PSXX release manifest %s: the signed list of the memory card files of this release of the PSXX crypto multitool (description inside)" % a.name]], "content": canon(content)}
    open(os.path.join(d, "manifest_event.json"), "w", encoding="utf-8").write(json.dumps(ev, separators=(",", ":"), ensure_ascii=False))
    try:
        req = psxx_tx.make_request("nostr", 0, "m/44'/1237'/0'/0/0", json.dumps(ev, separators=(",", ":"), ensure_ascii=False).encode())
    except SystemExit as e:                                                       # many boot cards: the event is longer than a request file of the signer (7936 bytes); sign manifest_event.json with another Nostr signer
        print("manifest of %s: %d cards (%d boot), %d bytes of content; no request card for the console signer (%s)" % (a.name, len(cards), boot_n, len(ev["content"]), e))
        req = None
    if req:
        bcard = next((c for c in cards if c["role"] == "other" and c["name"].endswith("B-ok.mcd")), None)
        card = bytearray(open(os.path.join(cdir, bcard["name"]), "rb").read()) if bcard else M.blank_card()
        psxx_tx.add_file(card, psxx_tx.REQ_TAG, req)
        open(os.path.join(d, "manifest_request.mcd"), "wb").write(card)
        print("manifest of %s: %d cards (%d boot), %d bytes of content (the request holds %d of 7936 bytes)" % (a.name, len(cards), boot_n, len(ev["content"]), len(req)))
    print("source tree %s%s" % (tree, " (the working tree has uncommitted changes)" if dirty else ""))
    print("wrote manifest_event.json and manifest_request.mcd in %s; sign it with the signer (key %s), then" % (d, rel["key"][:16]))
    print("  release.py attach-manifest %s --sig <128 hex digits>" % a.dir)


def _image_size(d):
    b = open(os.path.join(d, "base.exe"), "rb").read(0x20)
    return struct.unpack_from("<I", b, 0x1C)[0]


def attach_manifest(a):
    d = os.path.abspath(a.dir)
    rel = json.load(open(os.path.join(d, "release.json")))
    pub = bytes.fromhex(rel["key"])
    ev = json.load(open(os.path.join(d, "manifest_event.json"), encoding="utf-8"))
    body = json.dumps([0, pub.hex(), ev["created_at"], ev["kind"], ev["tags"], ev["content"]], separators=(",", ":"), ensure_ascii=False)
    eid = hashlib.sha256(body.encode()).digest()
    sig = bytes.fromhex(a.sig)
    if len(sig) != 64 or not bip340.verify(pub, eid, sig):
        sys.exit("the signature is not valid for this manifest and the key %s" % pub.hex())
    full = {"id": eid.hex(), "pubkey": pub.hex(), "created_at": ev["created_at"], "kind": ev["kind"], "tags": ev["tags"], "content": ev["content"], "sig": sig.hex()}
    open(os.path.join(d, "manifest_signed.json"), "w", encoding="utf-8").write(json.dumps(full, separators=(",", ":"), ensure_ascii=False))
    pkg = open(os.path.join(d, "overlay.pkg"), "rb").read()
    open(os.path.join(d, "package_event.json"), "w").write(json.dumps(package_event(pkg, pub), separators=(",", ":")))
    if os.path.exists(os.path.join(d, "data.pkg")):
        open(os.path.join(d, "data_package_event.json"), "w").write(json.dumps(package_event(open(os.path.join(d, "data.pkg"), "rb").read(), pub), separators=(",", ":")))
    print("signed manifest %s (event id %s) and package_event.json written in %s" % ("manifest_signed.json", eid.hex(), d))


# ------------------------------------------------------------------ check-cards
CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def npub_key(s):
    s = s.strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", s):
        return bytes.fromhex(s)
    s = s.lower()
    hrp, _, rest = s.rpartition("1")
    vals = [CH.index(c) for c in rest]
    gen = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    chk = 1
    for v in [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + vals:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for k in range(5):
            if (b >> k) & 1:
                chk ^= gen[k]
    if hrp != "npub" or chk != 1:
        raise ValueError("not a valid npub")
    acc, bits, out = 0, 0, bytearray()
    for v in vals[:-6]:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 255)
            acc &= (1 << bits) - 1
    return bytes(out)


def check_event(txt, what, trust, out):
    ev = json.loads(txt)
    body = json.dumps([0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]], separators=(",", ":"), ensure_ascii=False)
    eid = hashlib.sha256(body.encode()).digest()
    if eid.hex() != ev["id"]:
        out("fail", what + ": id", "the id is not the hash of the event")
        return None
    pub = bytes.fromhex(ev["pubkey"])
    if not bip340.verify(pub, eid, bytes.fromhex(ev["sig"])):
        out("fail", what + ": signature", "not valid for " + ev["pubkey"])
        return None
    out("ok", what + ": signature", "valid, signed by " + ev["pubkey"])
    if trust is not None:
        if pub != trust:
            out("fail", what + ": key", "signed by another key than the trusted one")
            return None
        out("ok", what + ": key", "it is the trusted key")
    return ev


def find_package(card):
    if card[:4] == b"PSXP":
        return card
    if len(card) != M.FRAME * 1024 or card[:2] != b"MC":
        return None
    for b in range(1, 16):
        e = M.entry(card, b)
        if e[0] == 0x51:
            try:
                data, _ = M.find_file(card, bytes(e[10:30]).rstrip(b"\0").decode())
            except ValueError:
                continue
            if data[:4] == b"PSXP":
                return data
    return None


def check_cards(boot, others, event, manifest_txt, trust_s, image_size=0, lzma_s="1,2,2"):
    """returns the list of (status, title, detail); `others` is a list of (name, bytes)"""
    res = []
    out = lambda s, t, d="": res.append((s, t, d))
    trust = None
    if trust_s:
        try:
            trust = npub_key(trust_s)
            out("info", "Trusted public key", trust.hex())
        except (ValueError, IndexError) as e:
            out("fail", "Trusted public key", str(e))
    else:
        out("warn", "Trusted public key", "none given: the results only say which key signed the release")
    man = None
    if manifest_txt:
        ev = check_event(manifest_txt, "Release manifest", trust, out)
        if ev:
            man = json.loads(ev["content"])
            out("info", "Release manifest", "%s %s" % (man.get("name"), man.get("version")))

    def listed(data, what):
        h = sha(data)
        out("info", what + " SHA-256", h)
        if not man:
            return None
        c = next((x for x in man["cards"] if x["sha256"] == h), None)
        out("ok" if c else "warn", what + " vs manifest", ("identical to the listed file " + c["name"]) if c else "no listed file has this hash")
        return c

    pkgs = []
    for name, data in others:
        listed(data, name)
        raw = find_package(data)
        if raw is None:
            out("info", name, "a card without a package")
            continue
        try:
            p = P.parse(raw)
        except P.PkgError as e:
            out("fail", name + ": package", str(e))
            continue
        out("ok", name + ": package", "%d groups, %d bytes, %s" % (len(p["entries"]), p["total"], "overlay" if p["kind"] == 1 else "data"))
        bad = [e["id"] for e in p["entries"] if not P.group_ok(raw, e)]
        out("fail" if bad else "ok", name + ": groups", ("wrong hash in group %s" % bad) if bad else "every group matches its hash in the table")
        pkgs.append((name, p, raw))
    main = next(((n, p, r) for n, p, r in pkgs if p["kind"] == 1), None)
    key = trust
    if event:
        ev = check_event(event, "Package event", trust, out)
        if ev:
            key = key or bytes.fromhex(ev["pubkey"])
            if main:
                te = P.HEADER + len(main[1]["entries"]) * P.ENTRY
                dg = P.digest(main[2][:te]).hex()
                dtag = next((t[1] for t in ev["tags"] if t[0] == "d"), None)
                good = ev["kind"] == P.EVENT_KIND and dtag == dg and ev["content"] == dg
                out("ok" if good else "fail", "Event vs package", "the event carries the digest of " + main[0] if good else "the digest in the event is not the digest of " + main[0])
                same = bytes.fromhex(ev["sig"]) == main[2][te:te + P.SIG]
                out("ok" if same else "fail", "Event vs package signature", "the package holds the signature of the event" if same else "the signature in the package differs from the event's")
    else:
        out("skip", "Package event", "no event given")
    for name, p, raw in pkgs:
        if key is None:
            out("warn", name + ": signature", "no key to check it against")
            continue
        te = P.HEADER + len(p["entries"]) * P.ENTRY
        good = bip340.verify(key, P.message(raw[:te], key), raw[te:te + P.SIG])
        out("ok" if good else "fail", name + ": signature", "valid" if good else "not valid (not signed, or signed by another key)")

    if boot:
        entry = listed(boot, "Boot card")
        lc, lp, pb = (int(x) for x in lzma_s.split(","))
        size = image_size or (man or {}).get("a", {}).get("image_size", 0)
        target = main[1]["base_id"] if main else None
        found = None
        offsets = [c["payload_offset"] for c in (man or {}).get("cards", []) if c.get("payload_offset")] + list(range(0x2000, 0x3000, 128))
        for off in dict.fromkeys(offsets):
            if boot[off] != 0 or not size:
                continue
            try:
                dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": 1 << 18}])
                img = dec.decompress(boot[off:off + 125000], size)
            except lzma.LZMAError:
                continue
            if len(img) == size and img.count(REC_MAGIC) == 1:
                found = (off, img)
                break
        if not size:
            out("warn", "Program image", "give the image size (the Python checker does not search for it)")
        elif not found:
            out("fail", "Program image", "cannot unpack an image of %d bytes with a release record from this card" % size)
        else:
            off, img = found
            out("ok", "Program image", "unpacked %d bytes at card offset 0x%x" % (len(img), off))
            rec = img.find(REC_MAGIC)
            z = bytearray(img)
            z[rec + PIN_AT:rec + PIN_AT + 96] = bytes(96)
            bid = hashlib.sha256(z).digest()
            out("info", "Program base id", bid.hex())
            out("ok" if bid == img[rec + BASE_AT:rec + BASE_AT + 32] else "fail", "Release record", "the base id in the record is the hash of the image")
            pin = img[rec + PIN_AT:rec + PIN_AT + 32]
            if key:
                out("ok" if pin == key else "fail", "Release record key", "the key in the record is the release key" if pin == key else "the key in the record is another one")
            dpin = img[rec + 72:rec + 104]
            if any(p[1]["kind"] == 2 for p in pkgs):
                if key is None:
                    out("warn", "Release record data key", "the record holds " + dpin.hex())
                else:
                    out("ok" if dpin == key else "fail", "Release record data key", ("the data key in the record is the release key") if dpin == key else "the program would refuse the data card: the data key in the record is " + (dpin.hex()[:16] if any(dpin) else "empty"))
            elif any(dpin):
                out("info", "Release record data key", dpin.hex())
            if target is not None:
                out("ok" if bid == target else "fail", "Program vs package", "the overlay package was made for this program" if bid == target else "made for another program")
            if man:
                out("ok" if bid.hex() == man["base_id"] else "fail", "Program vs manifest", "the base id is the one in the manifest" if bid.hex() == man["base_id"] else "differs from the manifest's")
            if entry:
                out("ok", "Loader", "covered: the whole boot card is the listed file")
            elif man:
                hit = None
                for c in man["cards"]:
                    if c.get("loader_sha256") and c["payload_offset"] == off:
                        z = bytearray(boot)
                        z[off:off + c["payload_len"]] = bytes(c["payload_len"])
                        if sha(bytes(z)) == c["loader_sha256"]:
                            hit = c
                            break
                out("ok" if hit else "fail", "Loader", ("the part around the program is the listed loader of " + hit["name"]) if hit else "the part around the program matches no listed loader")
            else:
                out("warn", "Loader", "not covered: only a signed manifest that lists this card covers the exploit and first stage code")
    else:
        out("skip", "Boot card", "not given")
    return res


def check_main(a):
    rd = lambda p: open(p, "rb").read()
    txt = lambda p: open(p, encoding="utf-8").read() if p else ""
    res = check_cards(rd(a.boot) if a.boot else None, [(os.path.basename(p), rd(p)) for p in a.other], txt(a.event), txt(a.manifest), a.trust, a.image_size)
    mark = {"ok": "OK  ", "fail": "FAIL", "warn": "WARN", "info": "    ", "skip": "--  "}
    for s, t, d in res:
        print("%s %s%s" % (mark[s], t, (": " + d) if d else ""))
    nf = sum(s == "fail" for s, _, _ in res)
    nw = sum(s == "warn" for s, _, _ in res)
    print("\n%s" % ("%d check(s) FAILED: do not trust these files." % nf if nf else "no check failed" + ("; %d point(s) not covered (WARN)" % nw if nw else "")))
    sys.exit(1 if nf else 0)
