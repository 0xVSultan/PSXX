#!/usr/bin/env python3
"""QR generator test: encode with the C core (qr_dump), decode with OpenCV (an independent decoder), and check that
the smallest version chosen matches the standard byte-mode capacity table.

Usage: python tests/test_qr.py path/to/qr_dump[.exe]      (needs opencv-python, numpy)
"""
import random, subprocess, sys
import cv2, numpy as np

# ISO 18004 byte-mode capacities, versions 1..10, per error correction level
CAP = {0: [17, 32, 53, 78, 106, 134, 154, 192, 230, 271],     # L
       1: [14, 26, 42, 62, 84, 106, 122, 152, 180, 213],      # M
       2: [11, 20, 32, 46, 60, 74, 86, 108, 130, 151],        # Q
       3: [7, 14, 24, 34, 44, 58, 64, 84, 98, 119]}           # H

rnd = random.Random(1)
ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:/.-_ "

def rand_text(n): return "".join(rnd.choice(ALPHA) for _ in range(n))

cases = []   # (ecc, text, expected_version or None)
for ecc in range(4):
    for v, cap in enumerate(CAP[ecc], start=1):
        cases.append((ecc, rand_text(cap), v))                        # exactly fills version v
        cases.append((ecc, rand_text(cap + 1), v + 1 if v < 10 else -1))  # one more byte: next version (or too long)
cases += [(1, "4" + rand_text(94), 6), (0, "4" + rand_text(94), 5)]   # a 95 character Monero-sized string
cases += [(ecc, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", None) for ecc in range(4)]
cases += [(1, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", None), (1, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", None),
          (1, "nostr:npub1" + rand_text(52), None), (1, "", None), (1, "a", 1)]

inp = "".join("%d %s\n" % (ecc, t.encode().hex() or "-") for ecc, t, _ in cases)
out = subprocess.run([sys.argv[1]], input=inp, capture_output=True, text=True, check=True).stdout.split("\n")

# Two independent OpenCV decoders: the classic detector occasionally fails to *locate* very large symbols,
# the Aruco based one is more robust. A code passes if either decodes it.
dets = [cv2.QRCodeDetector()]
if hasattr(cv2, "QRCodeDetectorAruco"): dets.append(cv2.QRCodeDetectorAruco())
fails = total = 0
pos = 0
for ecc, text, want_ver in cases:
    hdr = out[pos].split(); pos += 1
    ver = int(hdr[1])
    total += 1
    if want_ver is not None and ver != want_ver:
        fails += 1; print("FAIL version: ecc %d len %d got %d want %d" % (ecc, len(text), ver, want_ver))
    if ver < 0:
        continue
    size = int(hdr[2])
    rows = out[pos:pos + size]; pos += size
    assert size == 17 + 4 * ver and all(len(r) == size for r in rows)
    m = np.array([[int(c) for c in r] for r in rows], dtype=np.uint8)
    total += 1
    if not text:
        continue
    ok = False
    for det in dets:
        for scale in (8, 6, 10):                  # quiet zone of 4 modules, light background
            img = np.pad(1 - m, 4, constant_values=1) * 255
            img = np.kron(img, np.ones((scale, scale))).astype(np.uint8)
            got, _, _ = det.detectAndDecode(img)
            if got == text:
                ok = True; break
        if ok: break
    if not ok:
        fails += 1; print("FAIL decode: ecc %d ver %d len %d text %r got %r" % (ecc, ver, len(text), text[:40], got[:40]))
print("QR %s: %d checks, %d failed" % ("FAILED" if fails else "OK", total, fails))
sys.exit(1 if fails else 0)
