"""BIP340 Schnorr signatures over secp256k1, written from the BIP (the reference algorithms), for the packages of the cards (tools/pkg_pack.py) and the vectors of the C verifier.

  py -3.13 tools/bip340.py selftest
"""
import hashlib

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def tagged(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and a[1] != b[1]:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def mul(pt, k):
    r = None
    for i in range(256):
        if (k >> i) & 1:
            r = add(r, pt)
        pt = add(pt, pt)
    return r


def lift_x(x):
    if x >= P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if pow(y, 2, P) != y2:
        return None
    return x, y if y % 2 == 0 else P - y


def pubkey(sk):
    d = int.from_bytes(sk, "big")
    assert 1 <= d < N
    return mul(G, d)[0].to_bytes(32, "big")


def sign(sk, msg, aux=b"\0" * 32):
    d0 = int.from_bytes(sk, "big")
    assert 1 <= d0 < N
    pt = mul(G, d0)
    d = d0 if pt[1] % 2 == 0 else N - d0
    t = (d ^ int.from_bytes(tagged("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(tagged("BIP0340/nonce", t + pt[0].to_bytes(32, "big") + msg), "big") % N
    assert k0
    r = mul(G, k0)
    k = k0 if r[1] % 2 == 0 else N - k0
    e = int.from_bytes(tagged("BIP0340/challenge", r[0].to_bytes(32, "big") + pt[0].to_bytes(32, "big") + msg), "big") % N
    sig = r[0].to_bytes(32, "big") + ((k + e * d) % N).to_bytes(32, "big")
    assert verify(pt[0].to_bytes(32, "big"), msg, sig)
    return sig


def verify(pub, msg, sig):
    if len(pub) != 32 or len(sig) != 64:
        return False
    pt = lift_x(int.from_bytes(pub, "big"))
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if pt is None or r >= P or s >= N:
        return False
    e = int.from_bytes(tagged("BIP0340/challenge", sig[:32] + pub + msg), "big") % N
    rp = add(mul(G, s), mul(pt, N - e))
    return rp is not None and rp[1] % 2 == 0 and rp[0] == r


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["selftest"]:
        # vector 0 of the BIP (bip-0340/test-vectors.csv)
        sk = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
        pub = bytes.fromhex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
        sig = bytes.fromhex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
        assert pubkey(sk) == pub and sign(sk, b"\0" * 32) == sig and verify(pub, b"\0" * 32, sig)
        print("BIP340 vector 0: ok")
