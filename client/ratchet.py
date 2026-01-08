import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.public import PrivateKey, PublicKey, Box

_HASH_LEN = hashlib.sha256().digest_size
_MAX_SKIP = 1000


def hkdf(ikm: bytes, info: bytes, *, salt: bytes = b"", length: int = 32) -> bytes:
    if not salt:
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
        self.root = hkdf(shared_secret, b"root")

        self.dh_priv = PrivateKey.generate()
        self.dh_pub = self.dh_priv.public_key
        self.peer_dh_pub = None

        self.send_chain = hkdf(self.root, b"send" if initiator else b"recv")
        self.recv_chain = hkdf(self.root, b"recv" if initiator else b"send")

        self.send_epoch = 0
        self.recv_epoch = 0
        self.send_index = 0
        self.recv_index = 0

        self.skipped = {}  # (epoch, index) -> key

    # ---------- internal ----------
    def _next_chain(self, chain: bytes):
        chain = hkdf(chain, b"chain")
        key = hkdf(chain, b"msg")
        return chain, key

    def _dh_ratchet(self, peer_pub_bytes: bytes):
        peer_pub = PublicKey(peer_pub_bytes)
        dh_out = Box(self.dh_priv, peer_pub).shared_key()

        self.root = hkdf(dh_out, b"root", salt=self.root)

        self.dh_priv = PrivateKey.generate()
        self.dh_pub = self.dh_priv.public_key

        self.send_chain = hkdf(self.root, b"send")
        self.recv_chain = hkdf(self.root, b"recv")

        self.peer_dh_pub = peer_pub_bytes
        self.send_epoch += 1
        self.recv_epoch += 1
        self.send_index = 0
        self.recv_index = 0

    # ---------- send ----------
    def encrypt(self, plaintext: bytes, aad: bytes):
        self.send_chain, key = self._next_chain(self.send_chain)
        nonce = os.urandom(12)

        packet = {
            "dh_pub": bytes(self.dh_pub),
            "dh_epoch": self.send_epoch,
            "msg_index": self.send_index,
            "nonce": nonce,
            "ciphertext": AESGCM(key).encrypt(nonce, plaintext, aad),
        }

        self.send_index += 1
        return packet

    # ---------- recv ----------
    def decrypt(self, packet: dict, aad: bytes):
        epoch = packet["dh_epoch"]
        index = packet["msg_index"]

        if epoch > self.recv_epoch:
            self._skip_until(epoch, index)
            self._dh_ratchet(packet["dh_pub"])

        key_id = (epoch, index)
        if key_id in self.skipped:
            key = self.skipped.pop(key_id)
        else:
            self._skip_until(epoch, index)
            self.recv_chain, key = self._next_chain(self.recv_chain)
            self.recv_index += 1

        return AESGCM(key).decrypt(
            packet["nonce"],
            packet["ciphertext"],
            aad,
        )

    def _skip_until(self, epoch, index):
        while self.recv_epoch == epoch and self.recv_index < index:
            if len(self.skipped) > _MAX_SKIP:
                raise RuntimeError("too many skipped keys")
            self.recv_chain, key = self._next_chain(self.recv_chain)
            self.skipped[(epoch, self.recv_index)] = key
            self.recv_index += 1
