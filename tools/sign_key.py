"""The key that signs the card packages (tools/pkg_pack.py: format version 2, core/pkg/pkg.c checks the signature against the public key in the release record of the main card).

The secret key is a file with 64 hex digits: PSXX_SIGN_KEY, else build/keys/psxx_sign.key. A build without that file makes a DEVELOPMENT key there (random, never committed:
build/ is not in the repository) and says so; the release of the project is signed with the permanent project key, kept off line, the same way:
point PSXX_SIGN_KEY at it. Cards built with one key only work with a main card built with the same public key.

  py -3.13 tools/sign_key.py            the public key (x only, hex) of the key in use
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bip340

DEFAULT = os.path.join(HERE, "..", "build", "keys", "psxx_sign.key")


def key_path():
    return os.environ.get("PSXX_SIGN_KEY") or DEFAULT


def secret(create=True):
    p = key_path()
    if not os.path.exists(p):
        if not create or os.environ.get("PSXX_SIGN_KEY"):
            raise SystemExit("no signing key: %s" % p)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        while True:
            k = os.urandom(32)
            if 1 <= int.from_bytes(k, "big") < bip340.N:
                break
        open(p, "w").write(k.hex() + "\n")
        print("sign_key: made a DEVELOPMENT signing key %s (public %s)" % (os.path.normpath(p), bip340.pubkey(k).hex()), file=sys.stderr)
    return bytes.fromhex(open(p).read().strip())


def public():
    return bip340.pubkey(secret())


if __name__ == "__main__":
    print(public().hex())
