from nacl.public import PublicKey, Box
from ratchet import DoubleRatchet
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

class RatchetStore:
    def __init__(self, identity, transport, control_queue, self_id):
        self.identity = identity
        self.transport = transport
        self.control_queue = control_queue
        self.self_id = self_id
        self._ratchets = {}

    def get(self, peer_id: str) -> DoubleRatchet:
        if peer_id in self._ratchets:
            return self._ratchets[peer_id]
        self.transport.send({
            "type": "get_key",
            "target": peer_id
        })

        while True:
            msg = self.control_queue.get()
            if msg.get("type") == "error":
                raise RuntimeError(msg["error"])
            if msg.get("client_id") == peer_id and "dh_pub" in msg:
                break

        try:
            vk = VerifyKey(msg["sign_pub"])
            vk.verify(msg["dh_pub"], msg["dh_sig"])
        except BadSignatureError:
            raise RuntimeError("DH public key signature verification failed")

        peer_pub = PublicKey(msg["dh_pub"])
        box = Box(self.identity.dh_private, peer_pub)

        shared = box.shared_key()

        initiator = self.self_id < peer_id

        ratchet = DoubleRatchet(shared, initiator=initiator)
        self._ratchets[peer_id] = ratchet
        return ratchet
