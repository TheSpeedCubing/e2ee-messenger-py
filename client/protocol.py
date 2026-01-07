# protocol.py
import struct
import socket
import cbor2

_LEN_FMT = ">I"
_LEN_SIZE = 4

# 防止惡意或錯誤封包導致 OOM / DoS
_MAX_FRAME_SIZE = 4 * 1024 * 1024  # 4 MB，上層訊息量遠低於此值


class FramedSocket:
    def __init__(self, sock: socket.socket):
        self.sock = sock

    def send(self, obj: dict):
        # 僅允許 CBOR 可表示的純資料結構
        data = cbor2.dumps(obj)
        self.sock.sendall(struct.pack(_LEN_FMT, len(data)) + data)

    def recv(self):
        raw_len = self._recv_exact(_LEN_SIZE)
        if raw_len is None:
            return None

        msg_len = struct.unpack(_LEN_FMT, raw_len)[0]

        if msg_len <= 0 or msg_len > _MAX_FRAME_SIZE:
            raise ValueError(f"Invalid frame size: {msg_len}")

        payload = self._recv_exact(msg_len)
        if payload is None:
            return None

        # CBOR 反序列化（無 RCE 風險）
        return cbor2.loads(payload)

    def _recv_exact(self, n: int):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf
