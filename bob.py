# bob.py
# Entitas Bob (Penerima Tiket dan Penantang Handshake)
import socket
import random
import aes
import chat

BOB_IP = "192.168.100.3"
BOB_PORT = 5002

config = {
    "ID": "BOB",
    "KB": "master_key_bob00"
}


def wait_for_handshake():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BOB_IP, BOB_PORT))
    server.listen(1)

    print(f"\n[MENUNGGU] Bob siaga di {BOB_IP}:{BOB_PORT}...")
    try:
        conn, addr = server.accept()
        # Langkah 3: Terima dan buka Tiket dari Alice
        ticket_hex = conn.recv(4096).decode('utf-8').strip()
        ticket_plain = aes.decrypt(ticket_hex, config["KB"])
        ks, id_a = ticket_plain.split('|')

        print(f"\n[Langkah 3] Terima Tiket dari {id_a} ({addr[0]})")
        print(f"  Tiket Masuk (Hex) : {ticket_hex}")
        print(f"  Session Key (KS)  : {ks}")

        # Langkah 4: Kirim tantangan N2 terenkripsi KS
        n2 = random.randint(100000, 999999)
        step4_hex = aes.encrypt(str(n2), ks)
        print(f"[Langkah 4] Kirim tantangan N2 ke {id_a}: {n2} (Hex: {step4_hex})")
        conn.sendall(step4_hex.encode('utf-8'))

        # Langkah 5: Verifikasi balasan f(N2) = N2 - 1
        step5_hex = conn.recv(4096).decode('utf-8').strip()
        step5_plain = aes.decrypt(step5_hex, ks)
        expected = str(n2 - 1)

        print(f"[Langkah 5] Terima balasan f(N2): {step5_plain} (Harapan: {expected})")
        if step5_plain == expected:
            print("[OK] Verifikasi sukses! Masuk ke ruang chat.")
            conn.sendall("OK".encode('utf-8'))
            chat.start_chat(conn, id_a, ks, "Bob")
        else:
            print("[!] Verifikasi gagal. Nonce tidak cocok.")
            conn.sendall("FAIL".encode('utf-8'))
            conn.close()
    except Exception as e:
        print(f"[!] Error handshake Bob: {e}")
    finally:
        server.close()


def main():
    print(f"Bob aktif (KB: {config['KB']})")
    while True:
        print("\n--- MENU BOB ---")
        print("1. Siaga Terima Koneksi & Chat dari Alice")
        print(f"2. Ubah Master Key Bob (KB) [Saat ini: {config['KB']}]")
        print("3. Keluar")

        c = input("Pilihan > ").strip()
        if c == "1":
            wait_for_handshake()
        elif c == "2":
            val = input("KB Baru (ASCII): ").strip()
            if val:
                config["KB"] = val
                print(f"[OK] KB diubah: {config['KB']}")
        elif c == "3":
            break


if __name__ == "__main__":
    main()