import threading
from identity import Identity
from handler import ClientHandler


def main():
    server = input("server address: ").strip()
    cid = input("client id: ").strip()

    client = ClientHandler(server, Identity(), cid)

    def recv_loop():
        while True:
            msg = client.relay_queue.get()
            peer = msg["from"]

            ratchet = client.state.get(peer)
            aad = f"{peer}->{cid}".encode()

            pt = ratchet.decrypt(msg, aad)
            print(f"\n[{peer}] {pt.decode()}\n> ", end="")

    threading.Thread(target=recv_loop, daemon=True).start()

    print("format: <peer> <msg>")
    while True:
        peer, text = input("> ").split(" ", 1)
        client.send_message(peer, text.encode())


if __name__ == "__main__":
    main()
