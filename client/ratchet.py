# ratchet.py
import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_HASH_LEN = hashlib.sha256().digest_size  # 32


def hkdf(ikm: bytes, info: bytes = b"ratchet", *, salt: bytes = b"", length: int = 32) -> bytes:
    """RFC5869 HKDF using HMAC-SHA256 (extract + expand)."""
    if length <= 0:
        raise ValueError("HKDF length must be positive")
    if length > 255 * _HASH_LEN:
        raise ValueError("HKDF length too large for SHA256")

    # RFC5869: if salt is not provided, use HashLen zeros.
    if salt is None or salt == b"":
        salt = b"\x00" * _HASH_LEN

    # Extract: PRK = HMAC(salt, IKM)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    # Expand: OKM = T(1) | T(2) | ... where T(i)=HMAC(PRK, T(i-1) | info | i)
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1

    return okm[:length]


class DoubleRatchet:
    def __init__(self, shared_secret: bytes, initiator: bool):
        # Root key material
        root = hkdf(shared_secret, b"ratchet", length=32)

        # Symmetric chain keys
        if initiator:
            self.send_chain = hkdf(root, b"send", length=32)
            self.recv_chain = hkdf(root, b"recv", length=32)
        else:
            self.send_chain = hkdf(root, b"recv", length=32)
            self.recv_chain = hkdf(root, b"send", length=32)

    def _next(self, chain: bytes):
        chain = hkdf(chain, b"chain", length=32)
        msg_key = hkdf(chain, b"msg", length=32)
        return chain, msg_key

    def encrypt(self, plaintext: bytes):
        self.send_chain, key = self._next(self.send_chain)
        nonce = os.urandom(12)
        return nonce, AESGCM(key).encrypt(nonce, plaintext, None)

    def decrypt(self, nonce: bytes, ciphertext: bytes):
        self.recv_chain, key = self._next(self.recv_chain)
        return AESGCM(key).decrypt(nonce, ciphertext, None)
