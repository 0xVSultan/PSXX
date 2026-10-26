"""A stand-in for the chacha20poly1305 package that the Zcash reference code imports, on top of the cryptography package."""
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as _C
from cryptography.exceptions import InvalidTag


class ChaCha20Poly1305:
    def __init__(self, key, *args):
        self._c = _C(bytes(key))

    def encrypt(self, nonce, data, aad=None):
        return bytearray(self._c.encrypt(bytes(nonce), bytes(data), aad))

    def decrypt(self, nonce, data, aad=None):
        try:
            return bytearray(self._c.decrypt(bytes(nonce), bytes(data), aad))
        except InvalidTag:
            return None
