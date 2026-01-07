# ratchet.py
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.public import PrivateKey, PublicKey, Box

_HASH_LEN = hashlib.sha256().digest_size


def hkdf(ikm: bytes, info: bytes, *, salt: bytes = b"", length: int = 32) -> bytes:
    if salt in (b"", None):
        salt = b"\x00" * _HASH_LEN
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


class DoubleRatchet:
    def __init__(self, shared_secret: bytes, initiator: bool):
        # Root key
        self.root = hkdf(shared_secret, b"root")

        # DH state
        self.dh_priv = PrivateKey.generate()
        self.dh_pub = self.dh_priv.public_key
        self.peer_dh_pub = None

        # Chain keys
        if initiator:
            self.send_chain = hkdf(self.root, b"send")
            self.recv_chain = hkdf(self.root, b"recv")
        else:
            self.send_chain = hkdf(self.root, b"recv")
            self.recv_chain = hkdf(self.root, b"send")

        # Ratchet control
        self.needs_dh_send = False
        self.recv_index = 0

    # ---------- DH ratchet (recv side only) ----------
    def _dh_ratchet_recv(self, peer_pub_bytes: bytes):
        peer_pub = PublicKey(peer_pub_bytes)
        dh_out = Box(self.dh_priv, peer_pub).shared_key()

        # Advance root
        self.root = hkdf(dh_out, b"root", salt=self.root)

        # Reset recv chain for new sending epoch
        self.recv_chain = hkdf(self.root, b"recv")
        self.recv_index = 0

        self.peer_dh_pub = peer_pub_bytes
        self.needs_dh_send = True

    # ---------- symmetric ratchet ----------
    def _next(self, chain: bytes):
        chain = hkdf(chain, b"chain")
        msg_key = hkdf(chain, b"msg")
        return chain, msg_key

    # ---------- send ----------
    def encrypt(self, plaintext: bytes):
        if self.needs_dh_send:
            # rotate DH
            self.dh_priv = PrivateKey.generate()
            self.dh_pub = self.dh_priv.public_key

            if self.peer_dh_pub is not None:
                dh_out = Box(self.dh_priv, PublicKey(self.peer_dh_pub)).shared_key()
                self.root = hkdf(dh_out, b"root", salt=self.root)

            self.send_chain = hkdf(self.root, b"send")
            self.needs_dh_send = False

        self.send_chain, key = self._next(self.send_chain)
        nonce = os.urandom(12)

        return {
            "dh_pub": bytes(self.dh_pub),
            "nonce": nonce,
            "ciphertext": AESGCM(key).encrypt(nonce, plaintext, None),
        }

    # ---------- recv ----------
    def decrypt(self, packet: dict):
        peer_dh = packet["dh_pub"]

        if self.peer_dh_pub is None:
            # First contact: record peer DH only, DO NOT ratchet
            self.peer_dh_pub = peer_dh
            self.needs_dh_send = True
        elif self.peer_dh_pub != peer_dh:
            # New sending epoch from peer
            self._dh_ratchet_recv(peer_dh)

        self.recv_chain, key = self._next(self.recv_chain)
        self.recv_index += 1

        return AESGCM(key).decrypt(
            packet["nonce"],
            packet["ciphertext"],
            None,
        )
