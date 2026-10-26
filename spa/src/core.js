// Byte helpers and SHA-256 (written from FIPS 180-4; no library, no WebCrypto, so it runs the same everywhere, also from file://).
const X = {};

X.hex = (u) => Array.from(u, (b) => b.toString(16).padStart(2, "0")).join("");
X.unhex = (s) => {
  if (!/^([0-9a-fA-F]{2})*$/.test(s)) throw new Error("not hex");
  const u = new Uint8Array(s.length / 2);
  for (let i = 0; i < u.length; i++) u[i] = parseInt(s.substr(2 * i, 2), 16);
  return u;
};
X.cat = (...a) => {
  const u = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of a) { u.set(x, o); o += x.length; }
  return u;
};
X.utf8 = (s) => new TextEncoder().encode(s);
X.eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
X.u32 = (u, o) => (u[o] | (u[o + 1] << 8) | (u[o + 2] << 16) | (u[o + 3] << 24)) >>> 0;
X.u16 = (u, o) => u[o] | (u[o + 1] << 8);

(function () {
  const K = new Uint32Array(64);
  const H0 = new Uint32Array(8);
  const primes = [];
  for (let n = 2; primes.length < 64; n++) if (primes.every((p) => n % p)) primes.push(n);
  const frac = (x) => Math.floor((x - Math.floor(x)) * 4294967296) >>> 0;
  for (let i = 0; i < 64; i++) K[i] = frac(Math.cbrt(primes[i]));
  for (let i = 0; i < 8; i++) H0[i] = frac(Math.sqrt(primes[i]));
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));

  // incremental SHA-256: update() any number of times, digest() does not disturb the state (it works on a copy)
  class Sha256 {
    constructor() { this.h = H0.slice(); this.buf = new Uint8Array(64); this.fill = 0; this.len = 0; this.w = new Uint32Array(64); }
    clone() { const c = new Sha256(); c.h = this.h.slice(); c.buf = this.buf.slice(); c.fill = this.fill; c.len = this.len; return c; }
    block(b, o) {
      const w = this.w, h = this.h;
      for (let i = 0; i < 16; i++) w[i] = (b[o + 4 * i] << 24) | (b[o + 4 * i + 1] << 16) | (b[o + 4 * i + 2] << 8) | b[o + 4 * i + 3];
      for (let i = 16; i < 64; i++) {
        const a = w[i - 15], c = w[i - 2];
        w[i] = (w[i - 16] + (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) + w[i - 7] + (rotr(c, 17) ^ rotr(c, 19) ^ (c >>> 10))) | 0;
      }
      let a = h[0], b1 = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (let i = 0; i < 64; i++) {
        const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
        const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b1) ^ (a & c) ^ (b1 & c))) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b1; b1 = a; a = (t1 + t2) | 0;
      }
      h[0] += a; h[1] += b1; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    update(u) {
      let o = 0;
      this.len += u.length;
      if (this.fill) {
        const n = Math.min(64 - this.fill, u.length);
        this.buf.set(u.subarray(0, n), this.fill);
        this.fill += n; o = n;
        if (this.fill < 64) return this;
        this.block(this.buf, 0); this.fill = 0;
      }
      for (; o + 64 <= u.length; o += 64) this.block(u, o);
      this.buf.set(u.subarray(o), 0);
      this.fill = u.length - o;
      return this;
    }
    digest() {
      const c = this.clone();
      const pad = new Uint8Array(((c.fill < 56 ? 56 : 120) - c.fill) + 8);
      pad[0] = 0x80;
      const bits = c.len * 8;
      const dv = new DataView(pad.buffer);
      dv.setUint32(pad.length - 8, Math.floor(bits / 4294967296));
      dv.setUint32(pad.length - 4, bits >>> 0);
      const len = c.len;
      c.update(pad);
      c.len = len;
      const out = new Uint8Array(32), ov = new DataView(out.buffer);
      for (let i = 0; i < 8; i++) ov.setUint32(4 * i, c.h[i] >>> 0);
      return out;
    }
  }
  X.Sha256 = Sha256;
  X.sha256 = (u) => new Sha256().update(u).digest();
  X.tagged = (tag, data) => { const t = X.sha256(X.utf8(tag)); return X.sha256(X.cat(t, t, data)); };
})();
