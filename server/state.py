import threading

CLIENTS = {}
KEYS = {}
_LOCK = threading.RLock()


def register(cid, conn, keys):
    with _LOCK:
        CLIENTS[cid] = conn
        KEYS[cid] = keys


def unregister(cid):
    with _LOCK:
        CLIENTS.pop(cid, None)
        KEYS.pop(cid, None)


def get_client(cid):
    with _LOCK:
        return CLIENTS.get(cid)


def get_keys(cid):
    with _LOCK:
        return KEYS.get(cid)
