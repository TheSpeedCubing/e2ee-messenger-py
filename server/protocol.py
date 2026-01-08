import struct
import cbor2

_LEN_FMT = ">I"
_LEN_SIZE = 4
_MAX_FRAME_SIZE = 4 * 1024 * 1024


def recv_msg(conn):
    raw = conn.recv(_LEN_SIZE)
    if not raw:
        return None
    size = struct.unpack(_LEN_FMT, raw)[0]
    if size <= 0 or size > _MAX_FRAME_SIZE:
        raise ValueError("bad frame size")
    buf = b""
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            return None
        buf += chunk
    return cbor2.loads(buf)


def send_msg(conn, obj):
    data = cbor2.dumps(obj)
    conn.sendall(struct.pack(_LEN_FMT, len(data)) + data)
