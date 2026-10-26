// The formats: PlayStation memory card (tools/mkcard.py), card package (tools/pkg_pack.py, core/pkg/pkg.c), the release record in the A image (tools/release.py).
X.PKG = { HEADER: 48, ENTRY: 48, SIG: 64, VERSION: 3, EVENT_TIME: 1792774136, EVENT_KIND: 30078, ALIGN: 16, MAX_GROUPS: 48 };

// ---- memory card ----
X.card = {
  SIZE: 131072,
  files(d) {                                              // the first blocks of the files: [{block, name}]
    const out = [];
    if (d.length !== X.card.SIZE || d[0] !== 0x4D || d[1] !== 0x43) return out;
    for (let b = 1; b < 16; b++) {
      const e = d.subarray(b * 128, b * 128 + 128);
      if (e[0] !== 0x51) continue;
      let n = "";
      for (let i = 10; i < 30 && e[i]; i++) n += String.fromCharCode(e[i]);
      out.push({ block: b, name: n });
    }
    return out;
  },
  data(d, first) {                                        // all the data of a file: its chain of blocks, the first block without its header and icon frames
    const blocks = [first];
    for (let cur = first; ;) {
      const nxt = X.u16(d, cur * 128 + 8);
      if (nxt === 0xFFFF) break;
      cur = nxt + 1;
      if (blocks.includes(cur) || cur < 1 || cur > 15 || ![0x52, 0x53].includes(d[cur * 128])) throw new Error("damaged block chain");
      blocks.push(cur);
    }
    return X.cat(...blocks.map((b, i) => d.subarray(b * 8192 + (i ? 0 : 256), b * 8192 + 8192)));
  },
};

// ---- package ----
X.pkgDigest = (head) => X.tagged("PSXX/package", head);
X.pkgEventText = (pubHex, head) => {
  const d = X.hex(X.pkgDigest(head));
  return `[0,"${pubHex}",${X.PKG.EVENT_TIME},${X.PKG.EVENT_KIND},[["d","${d}"]],"${d}"]`;
};
X.pkgParse = (d) => {                                     // throws Error("CODE: ...") like core/pkg/pkg.c; returns the parts
  const { HEADER, ENTRY, SIG, ALIGN, MAX_GROUPS } = X.PKG;
  const up = (n) => Math.ceil(n / ALIGN) * ALIGN;
  if (d.length < HEADER + ENTRY) throw new Error("SIZE: too short");
  if (String.fromCharCode(...d.subarray(0, 4)) !== "PSXP") throw new Error("MAGIC: not a package");
  if (d[4] !== X.PKG.VERSION) throw new Error("VERSION: " + d[4]);
  const kind = d[5], n = X.u16(d, 6), total = X.u32(d, 8);
  if (kind !== 1 && kind !== 2) throw new Error("KIND: " + kind);
  if (!n || n > MAX_GROUPS || X.u32(d, 12) !== 0) throw new Error("HEADER");
  const te = HEADER + n * ENTRY;
  if (total < te + SIG || total > d.length) throw new Error("HEADER: bad total length");
  const entries = [];
  let prevId = -1, prevEnd = up(te + SIG);
  for (let i = 0; i < n; i++) {
    const o = HEADER + i * ENTRY, id = X.u16(d, o), fl = X.u16(d, o + 2), off = X.u32(d, o + 4), len = X.u32(d, o + 8), raw = X.u32(d, o + 12);
    if (id <= prevId || off % ALIGN || off < prevEnd || !len || off + len > total || fl >> 12) throw new Error("TABLE: group " + id);
    entries.push({ id, flags: fl, offset: off, len, rawlen: raw, sha: d.subarray(o + 16, o + 48) });
    prevId = id; prevEnd = off + up(len);
  }
  return { kind, baseId: d.subarray(16, 48), total, n, entries, head: d.subarray(0, te), sig: d.subarray(te, te + SIG) };
};

// ---- release record in the A image ----
X.REC = { MAGIC: "PSXXREL1", PIN: 8, BASE: 40, DATA: 72 };
X.recordAt = (img) => {                                   // offset of the (unique) record, or -1
  const m = X.utf8(X.REC.MAGIC);
  let at = -1;
  outer: for (let i = 0; i + m.length <= img.length; i++) {
    for (let k = 0; k < m.length; k++) if (img[i + k] !== m[k]) continue outer;
    if (at >= 0) return -1;
    at = i;
  }
  return at;
};
X.baseIdOf = (img, rec) => { const z = img.slice(); z.fill(0, rec + X.REC.PIN, rec + X.REC.PIN + 96); return X.sha256(z); };
