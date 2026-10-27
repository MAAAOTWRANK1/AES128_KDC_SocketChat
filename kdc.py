# kdc.py
# Key Distribution Center (KDC) untuk Skenario Distribusi Kunci Simetris
import socket
import threading
import random
import string
import aes

KDC_IP = "192.168.100.1"
KDC_PORT = 5000

keys = {
    "ALICE": "master_key_alice",
    "BOB": "master_key_bob00"
}
running = True


def generate_session_key() -> str:
    # Bangkitkan 16 karakter acak ASCII untuk session key AES-128
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=16))


def handle_client(conn: socket.socket, addr):
    try:
        data = conn.recv(4096).decode('utf-8').strip()
        if not data:
            return

        print(f"\n[Langkah 1] Request dari {addr[0]}: {data}")
        parts = data.split('|')
        if len(parts) != 3:
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

        conn.sendall(alice_hex.encode('utf-8'))
    except Exception as e:
        print(f"[!] Error KDC: {e}")
    finally:
        conn.close()


def server_loop():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((KDC_IP, KDC_PORT))
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
    server.close()


def main():
    global running
    threading.Thread(target=server_loop, daemon=True).start()
    print(f"KDC aktif di {KDC_IP}:{KDC_PORT}")

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
            val = input("KA Baru (ASCII): ").strip()
            if val:
                keys["ALICE"] = val
                print(f"[OK] KA diubah: {keys['ALICE']}")
        elif choice == "3":
            val = input("KB Baru (ASCII): ").strip()
            if val:
                keys["BOB"] = val
                print(f"[OK] KB diubah: {keys['BOB']}")
        elif choice == "4":
            running = False
            break


if __name__ == "__main__":
    main()