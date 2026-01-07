import threading
from identity import Identity

def main():
    server_addr = input("relay server address?\n: ").strip()
    client_id = input("what's your name?\n: ").strip()

    identity = Identity()

    from handler import ClientHandler
    client = ClientHandler(
        server_addr=server_addr,
        identity=identity,
        client_id=client_id
    )

    def incoming_loop():
        while True:
            msg = client.relay_queue.get()
            peer = msg["from"]
            ratchet = client.state.get(peer)
            plaintext = ratchet.decrypt({
                "dh_pub": msg["dh_pub"],
                "nonce": msg["nonce"],
                "ciphertext": msg["ciphertext"],
            })
            print(f"\n[{peer}] {plaintext.decode()}\n> ", end="", flush=True)

    threading.Thread(target=incoming_loop, daemon=True).start()

    print(f"[{client_id}] ready")
    print("Format: <target_id> <message>")

    while True:
        try:
            line = input("> ")
            if not line:
                continue

            peer, text = line.split(" ", 1)
            client.send_message(peer, text.encode())

        except KeyboardInterrupt:
            print("\nbye")
            break

        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    main()
