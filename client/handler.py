import threading
import queue
import socket

from protocol import FramedSocket
from state import RatchetStore
from config import SERVER_PORT
from log import log

class ClientHandler:
    def __init__(self, server_addr, identity, client_id):
        sock = socket.socket()
        sock.connect((server_addr, SERVER_PORT))

        self.transport = FramedSocket(sock)
        self.identity = identity
        self.client_id = client_id

        self.control_queue = queue.Queue()
        self.relay_queue = queue.Queue()

        self.state = RatchetStore(
            identity,
            self.transport,
            self.control_queue
        )

        self._register()
        threading.Thread(target=self._listen_loop, daemon=True).start()

    def _register(self):
        self.transport.send({
            "client_id": self.client_id,
            "keys": {
                "sign_pub": bytes(self.identity.verify_key),
                "dh_pub": self.identity.dh_public.encode(),
            }
        })
        log("registered")

    def _listen_loop(self):
        while True:
            msg = self.transport.recv()
            if msg is None:
                log("connection closed")
                break

            if msg.get("type") == "relay":
                self.relay_queue.put(msg)
            else:
                self.control_queue.put(msg)

    def send_message(self, peer_id: str, plaintext: bytes):
        ratchet = self.state.get(peer_id)
        nonce, ciphertext = ratchet.encrypt(plaintext)

        self.transport.send({
            "type": "relay",
            "from": self.client_id,
            "target": peer_id,
            "nonce": nonce,
            "ciphertext": ciphertext,
        })
