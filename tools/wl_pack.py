"""Packs the BIP39 and Monero word lists with front coding and an adaptive order-2 arithmetic coder (decoder: core/wordlist/wl.c).

  py -3.13 tools/wl_pack.py                  pack every list found in tools/wordlist_dl, check the round trip, write tests/wordlists.bin, print the sizes

The words keep their order (the position is the index of the word).  A word is coded as the length of the prefix it shares with the
previous word, then the new letters, then an end symbol.  Symbols: 0..nsym-2 are the prefix lengths and the letters (letter i has the number
i, 1-based, in the alphabet of the list), nsym-1 is the end of a word.  The model blends order 0, 1 and 2 counts (all integers, so the C decoder
gets the same numbers); order 1 knows if the symbol is the first after a prefix length; order 2 is the previous two symbols.  A context of order 1 or 2
with counts c (n in all, d different symbols) turns the probability p of the order below into (2 c SCALE + w p) / (2 n + w), w = 4 + 3 d (order 1) or
4 + 6 d (order 2): the more different symbols a context has seen, the more it leaves to the lower order.  The coder is the
range coder of LZMA, with a total of up to 16448 instead of a bit.  The lists of Korean and Japanese are coded in the decomposed form
(jamo, kana + dakuten mark): the decoder puts the syllables together again (Hangul by formula, kana by a table in the header).

Blob (little endian):  u16 nwords, u8 nsym, u8 flags (bit 0: Hangul jamo), u8 nalpha, u8 ncomp, u16 rows, u16 datalen,
                       u16 alpha[nalpha] (code points), u16 comp[ncomp][3] (base, mark, composed), data[datalen] (the first byte of the range coder, always 0, is left out, the zero bytes at the end too)
Container of the test file:  repeated  u8 namelen, name, u32 bloblen, blob, u8 sha256 of the words (each followed by a 0 byte, UTF-8, composed)[32]."""
import hashlib, os, re, struct, sys, unicodedata

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
WL = os.path.join(ROOT, "tools", "wordlist_dl")
BIP = ["english", "japanese", "korean", "spanish", "chinese_simplified", "chinese_traditional", "french", "italian", "czech", "portuguese"]
XMR = ["chinese_simplified", "dutch", "english", "english_old", "esperanto", "french", "german", "italian", "japanese", "lojban", "portuguese", "russian", "spanish"]
ONE_CHAR = ("chinese_simplified", "chinese_traditional")          # one glyph per word: stored as indexes into the glyph table, not here
SCALE = 65536
TOP = 1 << 24


class Model:
    """The integer model; wl.c does the same arithmetic step by step."""

    def __init__(self, nsym):
        self.n = nsym
        self.c0 = [0] * nsym
        self.n0 = 0
        self.c1 = {}
        self.c2 = {}
        self.rows = 0                         # rows of order 2 allocated
        self.h1 = self.h2 = nsym - 1
        self.pos = 0

    def _row(self, table, key):
        r = table.get(key)
        if r is None:
            r = table[key] = [[0] * self.n, 0]
            if table is self.c2:
                self.rows += 1
        return r

    def ctx1(self):
        return 64 + self.h1 if self.pos == 1 else self.h1

    def freqs(self):
        n = self.n
        r1 = self.c1.get(self.ctx1())
        r2 = self.c2.get(self.h2 * 128 + self.ctx1())
        w1 = 4 + 3 * sum(1 for c in r1[0] if c) if r1 else 0          # the weight of the lower orders: Witten-Bell, grows with the symbols seen in the context
        w2 = 4 + 6 * sum(1 for c in r2[0] if c) if r2 else 0
        f = []
        for s in range(n):
            p = ((self.c0[s] + 1) * SCALE) // (self.n0 + n)
            if r1:
                p = (r1[0][s] * 2 * SCALE + w1 * p) // (2 * r1[1] + w1)
            if r2:
                p = (r2[0][s] * 2 * SCALE + w2 * p) // (2 * r2[1] + w2)
            f.append((p >> 2) + 1)
        return f

    @staticmethod
    def _bump(row, s):
        row[0][s] += 1
        row[1] += 1
        if row[0][s] > 254:
            row[0] = [c >> 1 for c in row[0]]
            row[1] = sum(row[0])

    def update(self, s):
        k1 = self.ctx1()
        self._bump(self._row(self.c1, k1), s)
        self._bump(self._row(self.c2, self.h2 * 128 + k1), s)
        self.c0[s] += 1
        self.n0 += 1
        if self.c0[s] > 254:
            self.c0 = [c >> 1 for c in self.c0]
            self.n0 = sum(self.c0)
        self.pos = 0 if s == self.n - 1 else self.pos + 1
        self.h2, self.h1 = self.h1, s


class Encoder:
    def __init__(self):
        self.low = 0
        self.range = 0xFFFFFFFF
        self.cache = 0
        self.cache_size = 1
        self.out = bytearray()

    def _shift(self):
        if self.low < 0xFF000000 or self.low >= 1 << 32:
            carry = self.low >> 32
            c = self.cache
            while True:
                self.out.append((c + carry) & 0xFF)
                c = 0xFF
                self.cache_size -= 1
                if self.cache_size == 0:
                    break
            self.cache = (self.low >> 24) & 0xFF
        self.cache_size += 1
        self.low = (self.low & 0x00FFFFFF) << 8

    def encode(self, cum, f, total):
        r = self.range // total
        self.low += r * cum
        self.range = r * f
        while self.range < TOP:
            self.range = (self.range << 8) & 0xFFFFFFFF
            self._shift()

    def finish(self):
        for _ in range(5):
            self._shift()
        d = bytes(self.out[1:])                   # the first byte is always 0
        return d.rstrip(b"\0")


# ---- masks and permutations with the same coder

def enc_bits(enc, bits):
    """bits, each by the counts of the bits before it: (2 c + 1) / (2 n + 2)"""
    c = [0, 0]
    for b in bits:
        f0, total = 2 * c[0] + 1, 2 * (c[0] + c[1]) + 2
        enc.encode(f0 if b else 0, total - f0 if b else f0, total)
        c[b] += 1


def enc_shuffle(enc, start, target):
    """the swaps that put `start` in the order of `target` (the same items): from the end, a[k] with a[j], j < k + 1, each as likely"""
    a = list(start)
    pos = {v: i for i, v in enumerate(a)}
    assert sorted(pos) == sorted(target) and len(pos) == len(a)
    for k in range(len(a) - 1, 0, -1):
        j = pos[target[k]]
        enc.encode(j, 1, k + 1)
        a[k], a[j] = a[j], a[k]
        pos[a[j]], pos[a[k]] = j, k
    assert a == list(target)


def pack_mask(bits):
    enc = Encoder()
    enc_bits(enc, bits)
    return enc.finish()


class Decoder:
    """the decoder of wl.c in Python, for the round trips"""
    def __init__(self, data):
        self.data, self.pos, self.code, self.range = data, 0, 0, 0xFFFFFFFF
        for _ in range(4):
            self.code = (self.code << 8) | self._next()

    def _next(self):
        b = self.data[self.pos] if self.pos < len(self.data) else 0
        self.pos += 1
        return b

    def value(self, total):
        self.range //= total
        return min(self.code // self.range, total - 1)

    def take(self, cum, f):
        self.code -= cum * self.range
        self.range *= f
        while self.range < TOP:
            self.code = ((self.code << 8) | self._next()) & 0xFFFFFFFF
            self.range = (self.range << 8) & 0xFFFFFFFF

    def bits(self, n):
        c, out = [0, 0], []
        for _ in range(n):
            f0, total = 2 * c[0] + 1, 2 * (c[0] + c[1]) + 2
            b = int(self.value(total) >= f0)
            self.take(f0 if b else 0, total - f0 if b else f0)
            c[b] += 1
            out.append(b)
        return out

    def shuffle(self, a):
        a = list(a)
        for k in range(len(a) - 1, 0, -1):
            j = self.value(k + 1)
            self.take(j, 1)
            a[k], a[j] = a[j], a[k]
        return a


def decode_stream(data, model, nwords):
    pos = 0

    def nxt():
        nonlocal pos
        b = data[pos] if pos < len(data) else 0
        pos += 1
        return b

    code = 0
    for _ in range(4):
        code = (code << 8) | nxt()
    rng = 0xFFFFFFFF
    ends = 0
    while ends < nwords:
        f = model.freqs()
        total = sum(f)
        r = rng // total
        v = min(code // r, total - 1)
        cum = 0
        s = 0
        while cum + f[s] <= v:
            cum += f[s]
            s += 1
        code -= cum * r
        rng = r * f[s]
        while rng < TOP:
            code = ((code << 8) | nxt()) & 0xFFFFFFFF
            rng = (rng << 8) & 0xFFFFFFFF
        model.update(s)
        ends += s == model.n - 1
        yield s


def pack(words, name):
    form = [unicodedata.normalize("NFKD", w) for w in words] if name in ("korean", "japanese") else list(words)
    alpha = sorted(set("".join(form)))
    amap = {c: i + 1 for i, c in enumerate(alpha)}
    stream = []
    prev = ""
    for w in form:
        k = 0
        while k < min(len(w), len(prev)) and w[k] == prev[k]:
            k += 1
        stream.append(("L", k))
        stream += [("A", amap[c]) for c in w[k:]]
        stream.append(("E", 0))
        prev = w
    maxsym = max(len(alpha), max(v for t, v in stream if t == "L"))
    nsym = maxsym + 2
    assert nsym <= 64, (name, nsym)
    end = nsym - 1
    m = Model(nsym)
    enc = Encoder()
    syms = [end if t == "E" else v for t, v in stream]
    for s in syms:
        f = m.freqs()
        enc.encode(sum(f[:s]), f[s], sum(f))
        m.update(s)
    data = enc.finish()
    hangul = int(any(0x1100 <= ord(c) <= 0x11FF for c in alpha))
    comp = []
    if name == "japanese":
        pairs = set()
        for w in form:
            for a, b in zip(w, w[1:]):
                if b in "゙゚":
                    pairs.add((a, b))
        comp = sorted((ord(a), ord(b), ord(unicodedata.normalize("NFC", a + b))) for a, b in pairs)
    assert max(m.c2.__len__(), 0) == m.rows
    blob = struct.pack("<HBBBBHH", len(words), nsym, hangul, len(alpha), len(comp), m.rows, len(data))
    blob += b"".join(struct.pack("<H", ord(c)) for c in alpha) + b"".join(struct.pack("<HHH", *t) for t in comp) + data
    return blob, syms, nsym, m.rows


def unpack_check(blob, words):
    """independent decoder in Python (the model is shared, the grammar and the composition are done here again)"""
    nwords, nsym, hangul, nalpha, ncomp, rows, dlen = struct.unpack_from("<HBBBBHH", blob, 0)
    o = struct.calcsize("<HBBBBHH")
    alpha = [chr(struct.unpack_from("<H", blob, o + 2 * i)[0]) for i in range(nalpha)]
    o += 2 * nalpha
    comp = {}
    for i in range(ncomp):
        a, b, c = struct.unpack_from("<HHH", blob, o + 6 * i)
        comp[(chr(a), chr(b))] = chr(c)
    o += 6 * ncomp
    data = blob[o:o + dlen]
    m = Model(nsym)
    out, cur, prev = [], None, ""
    state = 0
    for s in decode_stream(data, m, nwords):
        if state == 0:
            k = s
            cur = prev[:k]
            state = 1
        elif s == nsym - 1:
            w = cur
            prev = w
            if hangul:
                w = compose_hangul(w)
            t = ""
            for ch in w:
                if t and (t[-1], ch) in comp:
                    t = t[:-1] + comp[(t[-1], ch)]
                else:
                    t += ch
            out.append(t)
            state = 0
        else:
            cur += alpha[s - 1]
    assert out == words, "round trip failed"
    return rows


def compose_hangul(w):
    out, i = "", 0
    while i < len(w):
        c = ord(w[i])
        if 0x1100 <= c <= 0x1112 and i + 1 < len(w) and 0x1161 <= ord(w[i + 1]) <= 0x1175:
            s = 0xAC00 + ((c - 0x1100) * 21 + ord(w[i + 1]) - 0x1161) * 28
            i += 2
            if i < len(w) and 0x11A8 <= ord(w[i]) <= 0x11C2:
                s += ord(w[i]) - 0x11A7
                i += 1
            out += chr(s)
        else:
            out += w[i]
            i += 1
    return out


def merge(big, mask, extra):
    """the words of `big` that the mask keeps and the words of `extra`, merged in the order of their UTF-8 bytes (core/wordlist/wl.c wl_merge)"""
    keep = [w for w, m in zip(big, mask) if m]
    out, i, j = [], 0, 0
    while i < len(keep) or j < len(extra):
        if j == len(extra) or (i < len(keep) and keep[i].encode() < extra[j].encode()):
            out.append(keep[i]); i += 1
        else:
            out.append(extra[j]); j += 1
    return out


def load_bip(n):
    return [unicodedata.normalize("NFC", w) for w in open(os.path.join(WL, n + ".txt"), encoding="utf-8").read().split()]


def load_xmr(n):
    t = open(os.path.join(WL, "monero", n + ".h"), encoding="utf-8").read()
    return [unicodedata.normalize("NFC", w) for w in re.findall(r'^\s*"([^"]+)"', t[t.index("words[NWORDS]"):], re.M)]


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    cont = bytearray()
    total = {"bip39": 0, "monero": 0}
    print("%-8s %-20s %6s %5s %6s %6s %6s" % ("family", "list", "words", "nsym", "rows", "data", "blob"))
    for fam, names, loader in (("bip39", BIP, load_bip), ("monero", XMR, load_xmr)):
        for n in names:
            if n in ONE_CHAR:
                continue
            words = loader(n)
            blob, _, nsym, rows = pack(words, n)
            unpack_check(blob, words)
            print("%-8s %-20s %6d %5d %6d %6d %6d" % (fam, n, len(words), nsym, rows, struct.unpack_from("<H", blob, 8)[0], len(blob)))
            total[fam] += len(blob)
            name = (fam + ":" + n).encode()
            cont += bytes([len(name)]) + name + struct.pack("<I", len(blob)) + blob
            cont += hashlib.sha256(b"".join(w.encode("utf-8") + b"\0" for w in words)).digest()
    print("totals (the blobs with their headers): bip39 %d, monero %d, both %d" % (total["bip39"], total["monero"], sum(total.values())))
    open(os.path.join(ROOT, "tests", "wordlists.bin"), "wb").write(bytes(cont))


if __name__ == "__main__":
    main()
