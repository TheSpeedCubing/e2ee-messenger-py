import pickle
import struct
import socket

_LEN_FMT = ">I"
_LEN_SIZE = 4

class FramedSocket:
    def __init__(self, sock: socket.socket):
        self.sock = sock

    def send(self, obj):
        data = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
        self.sock.sendall(struct.pack(_LEN_FMT, len(data)) + data)

    def recv(self):
        raw_len = self._recv_exact(_LEN_SIZE)
        if not raw_len:
            return None

        msg_len = struct.unpack(_LEN_FMT, raw_len)[0]
        payload = self._recv_exact(msg_len)
        if payload is None:
            return None

        return pickle.loads(payload)

    def _recv_exact(self, n: int):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf
