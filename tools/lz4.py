#!/usr/bin/env python3
"""LZ4 block format compressor/decompressor for the self-extracting PS-X EXE packer (tools/packexe.py).

Format (lz4.org block format): a sequence of [token][literal length ext.][literals][offset u16 LE][match length ext.],
the last sequence has literals only. Rules: minimum match 4, the last match must start at least 12 bytes before the end
of the block and the last 5 bytes are always literals.

The compressor uses hash chains and lazy matching and is meant to make the output small, not to be fast.
"""
import sys

MIN_MATCH = 4
MF_LIMIT = 12          # no match may start in the last 12 bytes
LAST_LITERALS = 5      # the last 5 bytes are literals
WINDOW = 65535


def _emit(out, data, lit_start, lit_end, offset, mlen):
    ll = lit_end - lit_start
    token = (min(ll, 15) << 4) | (min(mlen - MIN_MATCH, 15) if mlen else 0)
    out.append(token)
    if ll >= 15:
        r = ll - 15
        while r >= 255: out.append(255); r -= 255
        out.append(r)
    out += data[lit_start:lit_end]
    if mlen:
        out += offset.to_bytes(2, "little")
        if mlen - MIN_MATCH >= 15:
            r = mlen - MIN_MATCH - 15
            while r >= 255: out.append(255); r -= 255
            out.append(r)


def compress(data, depth=512):
    data = bytes(data)
    n = len(data)
    out = bytearray()
    if n < MF_LIMIT + 1:
        _emit(out, data, 0, n, 0, 0)
        return bytes(out)

    head = {}                  # 4 byte key -> most recent position
    prev = [0] * n             # chain: previous position with the same key (+1; 0 = none)

    def insert(i):
        if i + 4 <= n:
            k = data[i:i + 4]
            prev[i] = head.get(k, -1) + 1
            head[k] = i

    def find(i):
        """Longest match at i: (length, offset)."""
        best_len, best_off = 0, 0
        if i > n - MF_LIMIT: return 0, 0
        maxlen = n - LAST_LITERALS - i
        cand = head.get(data[i:i + 4], -1)
        tries = depth
        while cand >= 0 and i - cand <= WINDOW and tries:
            if data[cand + best_len] == data[i + best_len] if best_len < maxlen else False:
                l = 0
                while l < maxlen and data[cand + l] == data[i + l]: l += 1
                if l > best_len:
                    best_len, best_off = l, i - cand
                    if l >= maxlen: break
            cand = prev[cand] - 1
            tries -= 1
        return (best_len, best_off) if best_len >= MIN_MATCH else (0, 0)

    i = anchor = 0
    while i < n - MF_LIMIT + 1:
        ml, off = find(i)
        if ml:
            # lazy matching: a clearly better match one or two bytes later wins
            insert(i)
            while True:
                better = False
                for d in (1, 2):
                    if i + d <= n - MF_LIMIT:
                        l2, o2 = find(i + d)
                        if l2 > ml + d:               # gain must pay for the extra literals
                            for k in range(d): insert(i + 1 + k) if i + 1 + k < i + d else None
                            i += d; ml, off = l2, o2
                            insert(i)
                            better = True
                            break
                if not better: break
            _emit(out, data, anchor, i, off, ml)
            for k in range(i + 1, min(i + ml, n - 3)): insert(k)
            i += ml
            anchor = i
        else:
            insert(i)
            i += 1
    _emit(out, data, anchor, n, 0, 0)
    return bytes(out)


def decompress(comp, size_hint=None):
    out = bytearray()
    i, n = 0, len(comp)
    while i < n:
        token = comp[i]; i += 1
        ll = token >> 4
        if ll == 15:
            while True:
                b = comp[i]; i += 1; ll += b
                if b != 255: break
        out += comp[i:i + ll]; i += ll
        if i >= n: break                               # last sequence: literals only
        off = comp[i] | comp[i + 1] << 8; i += 2
        ml = token & 15
        if ml == 15:
            while True:
                b = comp[i]; i += 1; ml += b
                if b != 255: break
        ml += MIN_MATCH
        assert 0 < off <= len(out), "bad offset"
        for _ in range(ml): out.append(out[-off])      # may overlap: byte by byte
    return bytes(out)


def inplace_margin(comp, usize):
    """Smallest m >= 0 such that the compressed block can sit at [usize + m - len(comp), usize + m) in the output
    buffer and be decoded forward in place (the decoder of core/lz4_unpack.h copies byte by byte, forward).

    Rules, with a = address of an input byte and d = address of the output byte being written:
      literal copy: d <= a of the byte being read;
      match copy:   all written bytes must lie below the next unread input byte.
    """
    c = len(comp)
    need = 0                                           # max over (output position - input index) conditions
    i = out = 0
    while i < c:
        token = comp[i]; i += 1
        ll = token >> 4
        if ll == 15:
            while True:
                b = comp[i]; i += 1; ll += b
                if b != 255: break
        need = max(need, out - i)                       # literals start here
        i += ll; out += ll
        if i >= c: break
        i += 2
        ml = token & 15
        if ml == 15:
            while True:
                b = comp[i]; i += 1; ml += b
                if b != 255: break
        out += ml + MIN_MATCH
        need = max(need, out - i)                       # the match must end before the next unread byte
    return max(0, need + c - usize)


if __name__ == "__main__":
    data = open(sys.argv[1], "rb").read()
    c = compress(data)
    assert decompress(c) == data
    print("%d -> %d (%.1f%%)" % (len(data), len(c), 100.0 * len(c) / max(1, len(data))))
