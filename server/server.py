import socket
import threading
from handler import handle

HOST = "0.0.0.0"
PORT = 12345


def main():
    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen()
    print("Listening on {}:{}".format(HOST, PORT))

    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
