import threading

CLIENTS = {}
KEYS = {}

_LOCK = threading.RLock()

def register(client_id, conn, keys):
    with _LOCK:
        CLIENTS[client_id] = conn
        KEYS[client_id] = keys

def unregister(client_id):
    with _LOCK:
        CLIENTS.pop(client_id, None)
        KEYS.pop(client_id, None)

def get_client(client_id):
    with _LOCK:
        return CLIENTS.get(client_id)

def get_keys(client_id):
    with _LOCK:
        return KEYS.get(client_id)

def list_clients():
    with _LOCK:
        return list(CLIENTS.keys())
