import traceback
from protocol import recv_msg, send_msg
from state import (
    register, unregister,
    get_client, get_keys, list_clients
)
from log import log

def handle(conn):
    client_id = None
    try:
        log("new connection")

        msg = recv_msg(conn)
        if msg is None:
            log("registration failed (no msg)")
            return

        client_id = msg["client_id"]
        register(client_id, conn, msg["keys"])

        log(f"registered client: {client_id}")
        log(f"current clients: {list_clients()}")

        while True:
            msg = recv_msg(conn)
            if msg is None:
                log(f"{client_id} disconnected")
                break

            msg_type = msg.get("type")
            log(f"{client_id} -> {msg_type}")

            if msg_type == "get_key":
                target = msg["target"]
                keys = get_keys(target)
                if keys is None:
                    send_msg(conn, {
                        "type": "error",
                        "error": "client_not_found",
                        "target": target
                    })
                    continue

                send_msg(conn, { "client_id": target, **keys })

            elif msg_type == "relay":
                target = msg["target"]
                target_conn = get_client(target)
                if target_conn is None:
                    send_msg(conn, {
                        "type": "error",
                        "error": "client_not_connected",
                        "target": target
                    })
                    continue

                send_msg(target_conn, msg)
                log(f"relayed message {client_id} -> {target}")

    except Exception:
        log("EXCEPTION in handle()")
        traceback.print_exc()

    finally:
        if client_id:
            unregister(client_id)
        conn.close()
        log("connection closed")
