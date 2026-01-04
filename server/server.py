import socket
import threading
from config import HOST, PORT
from handler import handle
from log import log

def main():
    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen()

    log(f"server listening on port {PORT}")

    while True:
        conn, addr = s.accept()
        log(f"accept from {addr}")
        threading.Thread(
            target=handle,
            args=(conn,),
            daemon=True
        ).start()

if __name__ == "__main__":
    main()
