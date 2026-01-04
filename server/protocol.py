import pickle
import struct
from log import log

_LEN_FMT = ">I"
_LEN_SIZE = 4

def recv_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def recv_msg(conn):
    raw_len = recv_exact(conn, _LEN_SIZE)
    if not raw_len:
        log("recv_msg: connection closed (no length)")
        return None

    msg_len = struct.unpack(_LEN_FMT, raw_len)[0]
    payload = recv_exact(conn, msg_len)
    if payload is None:
        log("recv_msg: connection closed mid-packet")
        return None

    obj = pickle.loads(payload)
    log(f"recv_msg: {list(obj.keys())}")
    return obj

def send_msg(conn, obj):
    data = pickle.dumps(obj)
    conn.sendall(struct.pack(_LEN_FMT, len(data)) + data)
    log(f"send_msg: {obj.get('type', 'key_response')}")
