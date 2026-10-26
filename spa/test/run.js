// Tests of the verifier page: node spa/test/run.js [release-dir] [cards-dir]
// The modules are loaded exactly as the page gets them (tools/build_spa.py order), without ui.js.
const fs = require("fs"), path = require("path"), vm = require("vm"), crypto = require("crypto");
const ROOT = path.join(__dirname, "..", "..");
const ORDER = ["core.js", "secp.js", "lzma.js", "fmt.js", "verify.js"];
const code = ORDER.map((n) => fs.readFileSync(path.join(ROOT, "spa", "src", n), "utf8")).join("\n") + "\n;X;";
const X = vm.runInNewContext(code, { TextEncoder, TextDecoder, BigInt, Uint8Array, Uint16Array, Uint32Array, DataView, Math, Error, JSON, parseInt, String, Array, Number });
let fails = 0, n = 0;
const check = (c, what) => { n++; if (!c) { fails++; console.log("FAIL", what); } };
const V = JSON.parse(fs.readFileSync(path.join(__dirname, "vectors.json"), "utf8"));
const u = (h) => new Uint8Array(Buffer.from(h, "hex"));

for (const t of V.sha256) {
  const m = u(t.msg);
  check(X.hex(X.sha256(m)) === t.digest, "sha256 " + m.length);
  check(crypto.createHash("sha256").update(m).digest("hex") === t.digest, "sha256 node " + m.length);
  check(X.hex(X.tagged("PSXX/package", m)) === t.tagged, "tagged " + m.length);
  const h = new X.Sha256();                                 // split updates give the same digest, digest() leaves the state alone
  h.update(m.subarray(0, 37)); h.digest(); h.update(m.subarray(37));
  check(X.hex(h.digest()) === t.digest, "sha256 split " + m.length);
}
for (const t of V.bip340) check(X.bip340verify(u(t.pub), u(t.msg), u(t.sig)) === t.ok, "bip340 " + t.sig.slice(0, 8) + " " + t.ok);
// the BIP340 test vector 0 of the BIP itself
check(X.bip340verify(u("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"), new Uint8Array(32),
  u("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")), "bip340 BIP vector 0");
for (const t of V.lzma) {
  const out = X.lzmaRaw(u(t.stream), t.size, t.lc, t.lp, t.pb);
  check(out.length === t.size && X.hex(X.sha256(out)) === t.raw_sha256, `lzma ${t.lc},${t.lp},${t.pb}`);
}
for (const t of V.bech32) {
  check(X.hex(X.pubkeyOf(t.npub)) === t.key, "npub " + t.npub.slice(0, 12));
  check((() => { try { X.pubkeyOf(t.npub.slice(0, -1) + (t.npub.endsWith("q") ? "p" : "q")); return false; } catch (e) { return true; } })(), "npub checksum");
}
check(X.hex(X.pubkeyOf("ab".repeat(32))) === "ab".repeat(32), "hex key");

// ---- the trophy release, if it is built here ----
const rel = process.argv[2] || path.join(ROOT, "build", "release", "trophy_nostr");
const cards = process.argv[3] || path.join(ROOT, "build", "release", "trophy_cards");
const rd = (d, f) => new Uint8Array(fs.readFileSync(path.join(d, f)));
if (fs.existsSync(path.join(rel, "overlay.pkg")) && fs.existsSync(path.join(cards, "trophy_event.json"))) {
  const rj = JSON.parse(fs.readFileSync(path.join(rel, "release.json"), "utf8"));
  const ev = fs.readFileSync(path.join(cards, "trophy_event.json"), "utf8");
  const bcard = rd(cards, "trophy_B-ok.mcd"), pkg = rd(rel, "overlay.pkg");
  const acards = fs.readdirSync(cards).filter((f) => /^trophy_[0-9].*\.mcd$/.test(f));
  const names = (r) => r.results.map((x) => x.status[0].toUpperCase() + ":" + x.title).join(" | ");
  const run = (o) => X.verify(Object.assign({ trust: rj.key, event: ev }, o));
  const st = (r, t) => (r.results.find((x) => x.title === t) || {}).status;

  let r = run({ others: [{ name: "B", data: bcard }] });
  check(r.ok && st(r, "B: signature") === "ok" && st(r, "Event vs package") === "ok", "B card ok: " + names(r));
  r = run({ others: [{ name: "pkg", data: pkg }] });
  check(r.ok, "package file ok");
  for (const f of acards) {
    r = run({ others: [{ name: "B", data: bcard }], boot: rd(cards, f) });
    check(r.ok && st(r, "Program vs package") === "ok" && st(r, "Release record key") === "ok", "A+B " + f + ": " + names(r));
  }
  r = run({ boot: rd(cards, acards[0]), imageSize: 294912 });
  check(r.ok && st(r, "Release record") === "ok", "A with the size only: " + names(r));
  r = run({ boot: rd(cards, acards[0]) });
  check(st(r, "Program image") === "warn" && st(r, "Release record") === undefined, "A alone without a size: no verdict on the image");
  // the damaged B card of the release set
  r = run({ others: [{ name: "dmg", data: rd(cards, "trophy_B-damaged.mcd") }] });
  check(!r.ok && st(r, "dmg: groups") === "fail", "damaged B: " + names(r));
  // the empty B card
  r = run({ others: [{ name: "empty", data: rd(cards, "trophy_B-empty.mcd") }] });
  check(st(r, "empty") === "info" && st(r, "empty: package") === undefined, "empty B card: no package, no error");
  // another key
  r = X.verify({ trust: "00".repeat(31) + "01", others: [{ name: "B", data: bcard }], event: ev });
  check(!r.ok && st(r, "Package event: key") === "fail", "wrong trusted key: " + names(r));
  // a changed byte in the A card payload, in the record region of the stream and in the stub region
  for (const at of [0x2300 + 5000, 0x2300 + 60000]) {
    const a = rd(cards, acards[0]).slice();
    a[at] ^= 1;
    r = run({ others: [{ name: "B", data: bcard }], boot: a });
    check(!r.ok, "changed A byte at 0x" + at.toString(16) + ": " + names(r));
  }
  // a package of another base, an event of another package
  const p2 = pkg.slice(); p2[16] ^= 1;
  r = run({ others: [{ name: "p2", data: p2 }] });
  check(!r.ok, "changed package header");
  const ev2 = JSON.parse(ev); ev2.content = ev2.content.replace(/^./, (c) => (c === "0" ? "1" : "0"));
  r = run({ others: [{ name: "pkg", data: pkg }], event: JSON.stringify(ev2) });
  check(!r.ok, "changed event");
  r = run({ boot: rd(cards, acards[0]) });
  check(st(r, "Loader") === "warn", "no manifest: the loader is not covered");
  // a signed manifest of the cards (spa/test/gen_manifest.py, throwaway key: the record key and the package signature are of the release key, so only the manifest lines are checked here)
  const mf = path.join(ROOT, "build", "spa", "test_manifest.json");
  if (fs.existsSync(mf)) {
    const man = fs.readFileSync(mf, "utf8"), mk = JSON.parse(man).pubkey;
    const all = acards.map((f) => ({ name: f, data: rd(cards, f) }));
    const runm = (o) => X.verify(Object.assign({ trust: mk, manifest: man }, o));
    for (const f of acards) {
      r = runm({ boot: rd(cards, f), others: [{ name: "B", data: bcard }] });
      check(st(r, "Loader") === "ok" && st(r, "Program vs manifest") === "ok" && st(r, "Release manifest: key") === "ok", "manifest, whole card " + f + ": " + names(r));
      const a = rd(cards, f).slice();
      const off = JSON.parse(JSON.parse(man).content).cards.find((c) => c.name === f).payload_offset;
      a[off - 300] ^= 1;                                   // a byte of the loader, the program is untouched
      r = runm({ boot: a, others: [{ name: "B", data: bcard }] });
      check(st(r, "Loader") === "fail" && st(r, "Program image") === "ok", "manifest, changed loader byte " + f + ": " + names(r));
      const b = rd(cards, f).slice();
      b[off + 7000] ^= 1;                                  // a byte of the program
      r = runm({ boot: b, others: [{ name: "B", data: bcard }] });
      check(st(r, "Program vs manifest") !== "ok" && st(r, "Boot card vs manifest") === "warn", "manifest, changed program byte " + f);
    }
    r = runm({ others: [{ name: "B2", data: bcard }, { name: "B3", data: (() => { const x = bcard.slice(); x[9000] ^= 1; return x; })() }] });
    check(st(r, "B2 vs manifest") === "ok" && st(r, "B3 vs manifest") === "warn", "listed and changed B against the manifest");
    r = X.verify({ trust: "00".repeat(31) + "01", manifest: man });
    check(st(r, "Release manifest: key") === "fail", "manifest of another key");
  } else console.log("(no test manifest: run spa/test/gen_manifest.py)");
} else console.log("(no trophy release here: card tests skipped)");

console.log(n + " checks, " + fails + " failed");
process.exit(fails ? 1 : 0);
