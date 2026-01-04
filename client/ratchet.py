import os, hashlib, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hkdf(key: bytes, info=b"ratchet"):
    return hmac.new(key, info, hashlib.sha256).digest()

class DoubleRatchet:
    def __init__(self, shared_secret: bytes):
        self.root_key = hkdf(shared_secret)
        self.chain_key = self.root_key

    def next_message_key(self):
        self.chain_key = hkdf(self.chain_key, b"chain")
        return hkdf(self.chain_key, b"msg")

    def encrypt(self, plaintext: bytes):
        key = self.next_message_key()[:32]
        nonce = os.urandom(12)
        aes = AESGCM(key)
        return nonce, aes.encrypt(nonce, plaintext, None)

    def decrypt(self, nonce: bytes, ciphertext: bytes):
        key = self.next_message_key()[:32]
        aes = AESGCM(key)
        return aes.decrypt(nonce, ciphertext, None)
