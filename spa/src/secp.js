// BIP340 verification over secp256k1 (BigInt, affine points; one verification takes a few tens of milliseconds) and the bech32 of npub.
(function () {
  const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
  const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  const G = [0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n];
  const mod = (a) => { const r = a % P; return r >= 0n ? r : r + P; };
  const inv = (a) => {                                   // extended Euclid
    let r0 = P, r1 = mod(a), s0 = 0n, s1 = 1n;
    while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
    return mod(s0);
  };
  const add = (a, b) => {
    if (!a) return b;
    if (!b) return a;
    if (a[0] === b[0] && a[1] !== b[1]) return null;
    const lam = a[0] === b[0] ? mod(3n * a[0] * a[0] * inv(2n * a[1])) : mod((b[1] - a[1]) * inv(b[0] - a[0]));
    const x = mod(lam * lam - a[0] - b[0]);
    return [x, mod(lam * (a[0] - x) - a[1])];
  };
  const mul = (pt, k) => { let r = null; for (; k > 0n; k >>= 1n) { if (k & 1n) r = add(r, pt); pt = add(pt, pt); } return r; };
  const big = (u) => BigInt("0x" + (X.hex(u) || "0"));
  const powmod = (b, e) => { let r = 1n; b = mod(b); for (; e > 0n; e >>= 1n) { if (e & 1n) r = mod(r * b); b = mod(b * b); } return r; };
  const lift = (x) => {
    if (x >= P) return null;
    const y2 = mod(x * x * x + 7n), y = powmod(y2, (P + 1n) / 4n);
    if (mod(y * y) !== y2) return null;
    return [x, y % 2n === 0n ? y : P - y];
  };

  // pub: 32 bytes (x only), msg: 32 bytes, sig: 64 bytes
  X.bip340verify = (pub, msg, sig) => {
    if (pub.length !== 32 || msg.length !== 32 || sig.length !== 64) return false;
    const Pt = lift(big(pub)), r = big(sig.subarray(0, 32)), s = big(sig.subarray(32));
    if (!Pt || r >= P || s >= N) return false;
    const e = big(X.tagged("BIP0340/challenge", X.cat(sig.subarray(0, 32), pub, msg))) % N;
    const R = add(mul(G, s), mul(Pt, (N - e) % N));
    return !!R && R[1] % 2n === 0n && R[0] === r;
  };

  const CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  X.bech32decode = (s) => {                               // [hrp, data bytes]; throws with the reason
    s = s.trim();
    if (s !== s.toLowerCase() && s !== s.toUpperCase()) throw new Error("mixed case");
    s = s.toLowerCase();
    const i = s.lastIndexOf("1");
    if (i < 1 || s.length - i < 7) throw new Error("not a bech32 string");
    const hrp = s.slice(0, i), d = [];
    for (const c of s.slice(i + 1)) { const v = CH.indexOf(c); if (v < 0) throw new Error("bad character"); d.push(v); }
    const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    const feed = (v) => { const b = chk >>> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (let k = 0; k < 5; k++) if ((b >>> k) & 1) chk ^= gen[k]; };
    for (const c of hrp) feed(c.charCodeAt(0) >> 5);
    feed(0);
    for (const c of hrp) feed(c.charCodeAt(0) & 31);
    for (const v of d) feed(v);
    if (chk !== 1) throw new Error("invalid checksum");
    const five = d.slice(0, -6), out = [];
    let acc = 0, bits = 0;
    for (const v of five) { acc = (acc << 5) | v; bits += 5; if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 255); acc &= (1 << bits) - 1; } }
    return [hrp, Uint8Array.from(out)];
  };
  // a public key as the user gives it: npub1..., or 64 hex characters
  X.pubkeyOf = (s) => {
    s = s.trim();
    if (/^[0-9a-fA-F]{64}$/.test(s)) return X.unhex(s.toLowerCase());
    const [hrp, d] = X.bech32decode(s);
    if (hrp !== "npub" || d.length !== 32) throw new Error("not an npub");
    return d;
  };
})();
