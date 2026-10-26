// Raw LZMA1 decoder (no header, no end marker needed: the output size is given), the format of tools/packexe.py (liblzma FORMAT_RAW).
X.lzmaRaw = (inp, outSize, lc, lp, pb, soft) => {         // soft: a damaged or over-long stream ends the output instead of throwing
  const out = new Uint8Array(outSize);
  let ip = 1, range = 0xFFFFFFFF, code = 0;                  // the first byte of a stream is always 0
  for (let i = 0; i < 4; i++) code = ((code * 256) + (inp[ip++] | 0)) >>> 0;
  const mk = (n) => new Uint16Array(n).fill(1024);
  const isMatch = mk(12 << 4), isRep = mk(12), isRepG0 = mk(12), isRepG1 = mk(12), isRepG2 = mk(12), isRep0Long = mk(12 << 4);
  const posSlot = mk(4 << 6), posSpec = mk(115), align = mk(16), lit = mk(0x300 << (lc + lp));
  const lenC = { ch: mk(2), low: mk(16 << 3), mid: mk(16 << 3), high: mk(256) };
  const repC = { ch: mk(2), low: mk(16 << 3), mid: mk(16 << 3), high: mk(256) };
  const bit = (p, i) => {
    const v = p[i], bound = (range >>> 11) * v;
    let b;
    if (code < bound) { range = bound; p[i] = v + ((2048 - v) >> 5); b = 0; }
    else { range -= bound; code -= bound; p[i] = v - (v >> 5); b = 1; }
    if (range < 0x1000000) { range = (range * 256) >>> 0; code = ((code * 256) + (inp[ip++] | 0)) >>> 0; }
    return b;
  };
  const tree = (p, base, n) => { let m = 1; for (let i = 0; i < n; i++) m = (m << 1) | bit(p, base + m); return m - (1 << n); };
  const rtree = (p, base, n) => { let m = 1, r = 0; for (let i = 0; i < n; i++) { const b = bit(p, base + m); m = (m << 1) | b; r |= b << i; } return r; };
  const len = (c, ps) => {
    if (!bit(c.ch, 0)) return tree(c.low, ps << 3, 3);
    if (!bit(c.ch, 1)) return 8 + tree(c.mid, ps << 3, 3);
    return 16 + tree(c.high, 0, 8);
  };
  let state = 0, rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0, pos = 0;
  const pbMask = (1 << pb) - 1, lpMask = (1 << lp) - 1;
  const run = () => {
  while (pos < outSize) {
    const ps = pos & pbMask;
    if (!bit(isMatch, (state << 4) + ps)) {
      const prev = pos ? out[pos - 1] : 0;
      const base = 0x300 * (((pos & lpMask) << lc) + (prev >> (8 - lc)));
      let sym = 1;
      if (state >= 7) {
        if (rep0 >= pos) throw new Error("bad distance");
        let mb = out[pos - rep0 - 1];
        while (sym < 0x100) {
          const mbit = (mb >> 7) & 1; mb = (mb << 1) & 255;
          const b = bit(lit, base + ((1 + mbit) << 8) + sym);
          sym = (sym << 1) | b;
          if (mbit !== b) break;
        }
      }
      while (sym < 0x100) sym = (sym << 1) | bit(lit, base + sym);
      out[pos++] = sym & 255;
      state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6;
      continue;
    }
    let n;
    if (!bit(isRep, state)) {
      rep3 = rep2; rep2 = rep1; rep1 = rep0;
      n = len(lenC, ps);
      state = state < 7 ? 7 : 10;
      const slot = tree(posSlot, Math.min(n, 3) << 6, 6);
      if (slot < 4) rep0 = slot;
      else {
        const nb = (slot >> 1) - 1;
        let d = (2 | (slot & 1)) * 2 ** nb;
        if (slot < 14) d += rtree(posSpec, d - slot - 1, nb);
        else {
          let direct = 0;
          for (let i = 0; i < nb - 4; i++) {
            range >>>= 1;
            let b = 0;
            if (code >= range) { code -= range; b = 1; }
            direct = direct * 2 + b;
            if (range < 0x1000000) { range = (range * 256) >>> 0; code = ((code * 256) + (inp[ip++] | 0)) >>> 0; }
          }
          d += direct * 16 + rtree(align, 0, 4);
        }
        rep0 = d;
        if (rep0 === 0xFFFFFFFF) break;                      // end marker
      }
    } else {
      if (!bit(isRepG0, state)) {
        if (!bit(isRep0Long, (state << 4) + ps)) {
          if (rep0 >= pos) throw new Error("bad distance");
          state = state < 7 ? 9 : 11;
          out[pos] = out[pos - rep0 - 1]; pos++;
          continue;
        }
      } else {
        let d;
        if (!bit(isRepG1, state)) d = rep1;
        else { if (!bit(isRepG2, state)) d = rep2; else { d = rep3; rep3 = rep2; } rep2 = rep1; }
        rep1 = rep0; rep0 = d;
      }
      n = len(repC, ps);
      state = state < 7 ? 8 : 11;
    }
    n += 2;
    if (rep0 >= pos) throw new Error("bad distance");
    for (let i = 0; i < n && pos < outSize; i++, pos++) out[pos] = out[pos - rep0 - 1];
  }
  };
  if (soft) { try { run(); } catch (e) { /* ends here */ } } else run();
  return out.subarray(0, pos);
};
