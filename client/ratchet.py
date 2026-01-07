import os, hashlib, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hkdf(key: bytes, info=b"ratchet"):
    return hmac.new(key, info, hashlib.sha256).digest()

class DoubleRatchet:
    def __init__(self, shared_secret: bytes, initiator: bool):
        root = hkdf(shared_secret)
        if initiator:
            self.send_chain = hkdf(root, b"send")
            self.recv_chain = hkdf(root, b"recv")
        else:
            self.send_chain = hkdf(root, b"recv")
            self.recv_chain = hkdf(root, b"send")

    def _next(self, chain):
        chain = hkdf(chain, b"chain")
        return chain, hkdf(chain, b"msg")[:32]

    def encrypt(self, plaintext: bytes):
        self.send_chain, key = self._next(self.send_chain)
        nonce = os.urandom(12)
        return nonce, AESGCM(key).encrypt(nonce, plaintext, None)

    def decrypt(self, nonce: bytes, ciphertext: bytes):
        self.recv_chain, key = self._next(self.recv_chain)
        return AESGCM(key).decrypt(nonce, ciphertext, None)
