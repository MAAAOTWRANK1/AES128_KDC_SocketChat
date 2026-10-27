# kdc.py
# Key Distribution Center (KDC) untuk Skenario Distribusi Kunci Simetris
import socket
import threading
import random
import string
import argparse
import aes
import chat

keys = {
    "ALICE": "master_key_alice",
    "BOB": "master_key_bob00"
}
running = True


def generate_session_key() -> str:
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=16))


def handle_client(conn: socket.socket, addr):
    with conn:
        try:
            data = chat.recv_msg(conn)
            if not data:
                return

            print(f"\n[Langkah 1] Request dari {addr[0]}: {data}")
            parts = data.split('|')
            if len(parts) != 3:
                print("[!] Format request tidak valid.")
                return

            id_a, id_b, n1 = parts
            ka = keys.get(id_a, "master_key_alice")
            kb = keys.get(id_b, "master_key_bob00")
            ks = generate_session_key()

            # Tiket untuk Bob: E(Kb, [Ks || ID_A])
            ticket_plain = f"{ks}|{id_a}"
            ticket_hex = aes.encrypt(ticket_plain, kb)

            # Paket untuk Alice: E(Ka, [Ks || ID_B || N1 || Tiket_Bob])
            alice_plain = f"{ks}|{id_b}|{n1}|{ticket_hex}"
            alice_hex = aes.encrypt(alice_plain, ka)

            print(f"[Langkah 2] Distribusi Kunci ({id_a} & {id_b})")
            print(f"  KA: {ka} | KB: {kb} | KS: {ks}")
            print(f"  Tiket Bob   : {ticket_hex}")
            print(f"  Paket Alice : {alice_hex}")

            chat.send_msg(conn, alice_hex)
        except Exception as e:
            print(f"[!] Error KDC: {e}")


def server_loop(host: str, port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)
        server.settimeout(1.0)

        while running:
            try:
                conn, addr = server.accept()
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break


def input_key(prompt: str) -> str:
    val = input(prompt).strip()
    if len(val.encode('utf-8')) != 16:
        print(f"[!] Ditolak: Kunci harus tepat 16 karakter ASCII (diberikan {len(val)})!")
        return ""
    return val


def main():
    global running
    parser = argparse.ArgumentParser(description="KDC Server")
    parser.add_argument("--host", default="0.0.0.0", help="IP address untuk listen (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Port untuk listen (default: 5000)")
    args = parser.parse_args()

    threading.Thread(target=server_loop, args=(args.host, args.port), daemon=True).start()
    print(f"KDC aktif mendengarkan di {args.host}:{args.port}")

    while True:
        print("\n--- MENU KDC ---")
        print(f"1. Lihat Master Key (KA: {keys['ALICE']}, KB: {keys['BOB']})")
        print("2. Ubah Master Key Alice (KA)")
        print("3. Ubah Master Key Bob (KB)")
        print("4. Keluar")

        choice = input("Pilihan > ").strip()
        if choice == "1":
            print(f"KA : {keys['ALICE']}")
            print(f"KB : {keys['BOB']}")
        elif choice == "2":
            val = input_key("KA Baru (16 karakter ASCII): ")
            if val:
                keys["ALICE"] = val
                print(f"[OK] KA diubah: {keys['ALICE']}")
        elif choice == "3":
            val = input_key("KB Baru (16 karakter ASCII): ")
            if val:
                keys["BOB"] = val
                print(f"[OK] KB diubah: {keys['BOB']}")
        elif choice == "4":
            running = False
            break


if __name__ == "__main__":
    main()