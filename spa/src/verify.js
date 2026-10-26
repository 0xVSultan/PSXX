// The chain of the release, from the files only. X.verify(input) returns {results: [{status, title, detail}], ok}.
// status: "ok" (checked), "fail" (does not match), "warn" (cannot say / not covered), "info" (a fact), "skip" (not given).
// input: {trust: npub or hex, boot: bytes of the boot card, others: [{name, data}] the other cards or package files (any number: B, C, later ones),
//         event: JSON text of the signed package event, manifest: JSON text of a signed release event, imageSize: bytes of the unpacked program image (0 = look for it), lzma: "lc,lp,pb"}
// The manifest (content JSON): {name, version, date, base_id, a: {image_size}, cards: [{name, sha256, bios, role, payload_offset, payload_len, loader_sha256}]}. A boot card differs per BIOS:
// its loader (exploit, first stage code: everything outside the packed program) is not part of the base id, so only the manifest covers it: by the hash of the whole file, or by the hash of
// the card with the packed program zeroed (loader_sha256), the latter for a card whose program is another one.
X.verify = (inp) => {
  const R = [];
  const add = (status, title, detail) => R.push({ status, title, detail: detail || "" });
  const short = (u) => X.hex(u).slice(0, 16) + "…";
  let trust = null;
  if (inp.trust && inp.trust.trim()) {
    try { trust = X.pubkeyOf(inp.trust); add("info", "Trusted public key", X.hex(trust)); } catch (e) { add("fail", "Trusted public key", "cannot read it: " + e.message); }
  } else add("warn", "Trusted public key", "none given: the results only say which key signed the release, not that it is the project's key");

  // a Nostr event: the id is the hash of its serialisation, the signature is BIP340 of the id
  const checkEvent = (txt, what) => {
    let ev;
    try { ev = JSON.parse(txt); } catch (e) { add("fail", what, "not valid JSON"); return null; }
    try {
      const body = JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
      const id = X.sha256(X.utf8(body));
      if (X.hex(id) !== ev.id) { add("fail", what + ": id", "the id is not the hash of the event"); return null; }
      const pub = X.unhex(ev.pubkey);
      if (!X.bip340verify(pub, id, X.unhex(ev.sig))) { add("fail", what + ": signature", "the signature is not valid for " + ev.pubkey); return null; }
      add("ok", what + ": signature", "valid, signed by " + ev.pubkey);
      if (trust) {
        if (X.eq(pub, trust)) add("ok", what + ": key", "it is the trusted key");
        else { add("fail", what + ": key", "signed by another key than the trusted one"); return null; }
      }
      return { ev, pub };
    } catch (e) { add("fail", what, "cannot check: " + e.message); return null; }
  };

  // optional signed release manifest: lists the exact files of the release
  let man = null;
  if (inp.manifest && inp.manifest.trim()) {
    const m = checkEvent(inp.manifest, "Release manifest");
    if (m) {
      try {
        man = JSON.parse(m.ev.content);
        add("info", "Release manifest", `${man.name || "?"} ${man.version || ""}`.trim() + (man.date ? ", " + man.date : ""));
        if (man.description) add("info", "Release description", String(man.description));
      } catch (e) { add("fail", "Release manifest", "the content is not JSON"); }
    }
  }
  const listed = (data, what) => {
    const h = X.hex(X.sha256(data));
    add("info", what + " SHA-256", h);
    if (!man || !man.cards) return null;
    const c = man.cards.find((x) => x.sha256 === h);
    if (c) add("ok", what + " vs manifest", "identical to the listed file " + c.name + (c.description ? ": " + c.description : ""));
    else add("warn", what + " vs manifest", "no listed file has this hash (modified, saved to, or another release); the checks below say what still holds");
    return c || null;
  };

  // the other cards: any number; a package inside a card (or a bare package file) is checked
  const pkgs = [];
  const others = inp.others || [];
  if (!others.length) add("skip", "Other cards", "none given");
  for (const o of others) {
    const what = o.name || "card";
    listed(o.data, what);
    try {
      let bytes = null;
      if (String.fromCharCode(...o.data.subarray(0, 4)) === "PSXP") bytes = o.data;
      else {
        const f = X.card.files(o.data).find((x) => { try { return String.fromCharCode(...X.card.data(o.data, x.block).subarray(0, 4)) === "PSXP"; } catch (e) { return false; } });
        if (!f) { add("info", what, "a card without a package (empty or other data)"); continue; }
        bytes = X.card.data(o.data, f.block);
        add("info", what, "package file " + f.name);
      }
      const p = X.pkgParse(bytes);
      add("ok", what + ": package", `${p.n} groups, ${p.total} bytes, ${p.kind === 1 ? "overlay" : "data"}`);
      const bad = p.entries.filter((e) => !X.eq(X.sha256(bytes.subarray(e.offset, e.offset + e.len)), e.sha));
      if (bad.length) add("fail", what + ": groups", "wrong hash in group " + bad.map((e) => e.id).join(", "));
      else add("ok", what + ": groups", "every group matches its hash in the table");
      add("info", what + ": digest", X.hex(X.pkgDigest(p.head)));
      pkgs.push({ name: what, p, bytes });
    } catch (e) { add("fail", what + ": package", e.message); }
  }
  const main = pkgs.find((x) => x.p.kind === 1) || null;          // the overlay package: made for the boot card's program
  const pkg = main && main.p;

  // the package event (of the overlay package)
  let key = trust;
  if (inp.event && inp.event.trim()) {
    const r = checkEvent(inp.event, "Package event");
    if (r) {
      if (!key) key = r.pub;
      if (pkg) {
        const dig = X.hex(X.pkgDigest(pkg.head));
        const dtag = (r.ev.tags.find((t) => t[0] === "d") || [])[1];
        if (r.ev.kind === X.PKG.EVENT_KIND && dtag === dig && r.ev.content === dig) add("ok", "Event vs package", "the event carries the digest of " + main.name);
        else add("fail", "Event vs package", "the digest in the event is not the digest of " + main.name);
        if (X.eq(X.unhex(r.ev.sig), pkg.sig)) add("ok", "Event vs package signature", "the package holds the signature of the event");
        else add("fail", "Event vs package signature", "the signature in the package differs from the event's");
      }
    }
  } else add("skip", "Package event", "no event given");

  // the signature in every package against the key (what the console does)
  for (const x of pkgs) {
    if (!key) { add("warn", x.name + ": signature", "no key to check it against"); continue; }
    const msg = X.sha256(X.utf8(X.pkgEventText(X.hex(key), x.p.head)));
    if (X.bip340verify(key, msg, x.p.sig)) add("ok", x.name + ": signature", "valid for " + short(key));
    else add("fail", x.name + ": signature", "not valid for " + short(key) + " (not signed, or signed by another key)");
  }

  // the boot card: the packed program and the release record in it; the loader around it
  if (inp.boot && inp.boot.length) {
    const a = inp.boot;
    const entry = listed(a, "Boot card");
    const [lc, lp, pb] = (inp.lzma || "1,2,2").split(",").map(Number);
    const size = inp.imageSize || (man && man.a && man.a.image_size) || 0;
    const target = pkg ? pkg.baseId : null;
    let found = null;
    for (let off = 0x2000; off < 0x3000 && !found; off += 128) {
      if (a[off] !== 0) continue;
      const img = X.lzmaRaw(a.subarray(off, off + 125000), size || (1 << 20), lc, lp, pb, true);
      const rec = X.recordAt(img);
      if (rec < 0) continue;
      if (size) {
        if (img.length === size) found = { off, img, rec, size };
        continue;
      }
      if (!target) { found = { off, img, rec, size: 0 }; continue; }       // size unknown and nothing to look for
      const z = img.slice();
      z.fill(0, rec + X.REC.PIN, rec + X.REC.PIN + 96);
      const h = new X.Sha256();
      for (let k = 0; (k + 1) * 2048 <= img.length; k++) {                 // the size of an image is a multiple of 2048: one pass, a digest at every step
        h.update(z.subarray(k * 2048, (k + 1) * 2048));
        if ((k + 1) * 2048 >= rec + X.REC.PIN + 96 && X.eq(h.digest(), target)) { found = { off, img: img.subarray(0, (k + 1) * 2048), rec, size: (k + 1) * 2048 }; break; }
      }
    }
    if (!found) add("fail", "Program image", size ? "cannot unpack an image of " + size + " bytes with a release record from this card" : "cannot find the program image in this card (give its size, or the overlay package it belongs to)");
    else if (!found.size) add("warn", "Program image", "unpacked, but its size is unknown: give the image size to compute its id");
    else {
      add("ok", "Program image", `unpacked ${found.img.length} bytes from the packed program at card offset 0x${found.off.toString(16)}`);
      const rec = found.rec, img = found.img;
      const id = X.baseIdOf(img, rec);
      add("info", "Program base id", X.hex(id));
      if (X.eq(id, img.subarray(rec + X.REC.BASE, rec + X.REC.BASE + 32))) add("ok", "Release record", "the base id in the release record is the hash of the image");
      else add("fail", "Release record", "the base id in the release record is not the hash of the image");
      const pin = img.subarray(rec + X.REC.PIN, rec + X.REC.PIN + 32);
      if (key) {
        if (X.eq(pin, key)) add("ok", "Release record key", "the key in the record is " + short(key));
        else add("fail", "Release record key", "the key in the record is " + short(pin) + ", not " + short(key));
      } else add("warn", "Release record key", "the record holds " + X.hex(pin));
      const dpin = img.subarray(rec + X.REC.DATA, rec + X.REC.DATA + 32);
      if (pkgs.some((x) => x.p.kind === 2)) {                          // a data (language) card is among the files: the record has to name the key that signed it
        if (!key) add("warn", "Release record data key", "the record holds " + X.hex(dpin));
        else if (X.eq(dpin, key)) add("ok", "Release record data key", "the data key in the record is " + short(key));
        else add("fail", "Release record data key", "the program would refuse the data card: the data key in the record is " + (dpin.some(Boolean) ? short(dpin) : "empty"));
      } else if (dpin.some(Boolean)) add("info", "Release record data key", X.hex(dpin));
      if (pkg) {
        if (X.eq(id, pkg.baseId)) add("ok", "Program vs package", "the overlay package was made for this program");
        else add("fail", "Program vs package", "the overlay package was made for another program");
      }
      if (man && man.base_id) {
        if (X.hex(id) === man.base_id) add("ok", "Program vs manifest", "the base id is the one in the manifest");
        else add("fail", "Program vs manifest", "the base id differs from the manifest's");
      }
    }
    // the loader: outside the base id
    if (entry) add("ok", "Loader", "covered: the whole boot card is the listed file");
    else if (man && man.cards && found) {
      const cand = man.cards.filter((c) => c.loader_sha256 && c.payload_len);
      const z = a.slice();
      let hit = null;
      for (const c of cand) {
        z.set(new Uint8Array(c.payload_len), c.payload_offset);
        if (c.payload_offset === found.off && X.hex(X.sha256(z)) === c.loader_sha256) { hit = c; break; }
        z.set(a.subarray(c.payload_offset, c.payload_offset + c.payload_len), c.payload_offset);
      }
      if (hit) add("ok", "Loader", "the part around the program is the listed loader of " + hit.name + (hit.bios ? " (BIOS " + hit.bios + ")" : ""));
      else add("fail", "Loader", "the part around the program (exploit, first stage) matches no listed loader: it may run code that is not the program");
    } else add("warn", "Loader", "not covered: the exploit and first stage code around the program are outside the base id; only a signed manifest that lists this card (per BIOS) covers them");
  } else add("skip", "Boot card", "not given");

  const ok = !R.some((r) => r.status === "fail") && R.some((r) => r.status === "ok");
  return { results: R, ok };
};
