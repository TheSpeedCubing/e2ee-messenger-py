from protocol import recv_msg, send_msg
from state import register, unregister, get_client, get_keys


def handle(conn):
    cid = None
    try:
        msg = recv_msg(conn)
        if msg["type"] != "register":
            return

        cid = msg["client_id"]
        register(cid, conn, msg["keys"])

        while True:
            msg = recv_msg(conn)
            if msg is None:
                break

            if msg["type"] == "get_key":
                keys = get_keys(msg["target"])
                if not keys:
                    send_msg(conn, {"type": "error", "error": "not_found"})
                else:
                    send_msg(conn, {"client_id": msg["target"], **keys})

            elif msg["type"] == "relay":
                dst = get_client(msg["target"])
                if dst:
                    send_msg(dst, msg)

    finally:
        if cid:
            unregister(cid)
        conn.close()
