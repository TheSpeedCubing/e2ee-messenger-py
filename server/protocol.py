import struct
import cbor2
from log import log

_LEN_FMT = ">I"
_LEN_SIZE = 4
_MAX_FRAME_SIZE = 4 * 1024 * 1024  # 4MB


def recv_exact(conn, size):
    buf = b""
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_msg(conn):
    raw_len = recv_exact(conn, _LEN_SIZE)
    if raw_len is None:
        log("recv_msg: connection closed (no length)")
        return None

    msg_len = struct.unpack(_LEN_FMT, raw_len)[0]

    if msg_len <= 0 or msg_len > _MAX_FRAME_SIZE:
        raise ValueError(f"Invalid frame size: {msg_len}")

    payload = recv_exact(conn, msg_len)
    if payload is None:
        log("recv_msg: connection closed mid-packet")
        return None

    obj = cbor2.loads(payload)
    log(f"recv_msg: {list(obj.keys())}")
    return obj


def send_msg(conn, obj):
    data = cbor2.dumps(obj)
    conn.sendall(struct.pack(_LEN_FMT, len(data)) + data)
    log(f"send_msg: {obj.get('type', 'key_response')}")

