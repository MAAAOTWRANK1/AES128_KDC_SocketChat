# bob.py
# Entitas Bob (Penerima Tiket dan Penantang Handshake)
import socket
import random
import argparse
import aes
import chat

config = {
    "ID": "BOB",
    "KB": "master_key_bob00",
    "MODE": "ECB"
}


def wait_for_handshake(host: str, port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)

        print(f"\n[MENUNGGU] Bob siaga di {host}:{port}...")
        conn = None
        try:
            conn, addr = server.accept()
            # Langkah 3: Terima dan buka Tiket dari Alice
            ticket_hex = chat.recv_msg(conn)
            if not ticket_hex:
                print("[!] Koneksi terputus saat menerima tiket.")
                return

            ticket_plain = aes.decrypt(ticket_hex, config["KB"])
            ks, id_a = ticket_plain.split('|')

            print(f"\n[Langkah 3] Terima Tiket dari {id_a} ({addr[0]})")
            print(f"  Tiket Masuk (Hex) : {ticket_hex}")
            print(f"  Session Key (KS)  : {ks}")

            # Langkah 4: Kirim tantangan N2 terenkripsi KS
            n2 = random.randint(100000, 999999)
            step4_hex = aes.encrypt(str(n2), ks)
            print(f"[Langkah 4] Kirim tantangan N2 ke {id_a}: {n2} (Hex: {step4_hex})")
            chat.send_msg(conn, step4_hex)

            # Langkah 5: Verifikasi balasan f(N2) = N2 - 1
            step5_hex = chat.recv_msg(conn)
            if not step5_hex:
                print("[!] Koneksi terputus saat menerima balasan Langkah 5.")
                return

            step5_plain = aes.decrypt(step5_hex, ks)
            expected = str(n2 - 1)

            print(f"[Langkah 5] Terima balasan f(N2): {step5_plain} (Harapan: {expected})")
            if step5_plain == expected:
                print("[OK] Verifikasi sukses! Masuk ke ruang chat.")
                chat.send_msg(conn, "OK")
                chat.start_chat(conn, id_a, ks, "Bob", mode=config["MODE"])
            else:
                print("[!] Verifikasi gagal. Nonce tidak cocok.")
                chat.send_msg(conn, "FAIL")
                conn.close()
        except ValueError as ve:
            print(f"[!] Data/kunci tidak valid: {ve}")
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
        except Exception as e:
            print(f"[!] Error handshake Bob: {e}")
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass


def input_key(prompt: str) -> str:
    val = input(prompt).strip()
    if len(val.encode('utf-8')) != 16:
        print(f"[!] Ditolak: Kunci harus tepat 16 karakter ASCII (diberikan {len(val)})!")
        return ""
    return val


def main():
    parser = argparse.ArgumentParser(description="Bob Entity")
    parser.add_argument("--host", default="0.0.0.0", help="IP address untuk listen (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5002, help="Port untuk listen (default: 5002)")
    args = parser.parse_args()

    print(f"Bob aktif mendengarkan di {args.host}:{args.port} (KB: {config['KB']})")
    while True:
        print("\n--- MENU BOB ---")
        print("1. Siaga Terima Koneksi & Chat dari Alice")
        print(f"2. Ubah Master Key Bob (KB) [Saat ini: {config['KB']}]")
        print(f"3. Ganti Mode Operasi AES [Saat ini: {config['MODE']}] (1: ECB, 2: CBC)")
        print(f"4. Toggle Mode Verbose AES [Saat ini: {'Aktif' if aes.VERBOSE else 'Nonaktif'}]")
        print("5. Keluar")

        c = input("Pilihan > ").strip()
        if c == "1":
            wait_for_handshake(args.host, args.port)
        elif c == "2":
            val = input_key("KB Baru (16 karakter ASCII): ")
            if val:
                config["KB"] = val
                print(f"[OK] KB diubah: {config['KB']}")
        elif c == "3":
            m = input("Pilih mode (1 = ECB, 2 = CBC): ").strip()
            if m == "1":
                config["MODE"] = "ECB"
            elif m == "2":
                config["MODE"] = "CBC"
            print(f"[OK] Mode operasi diatur ke: {config['MODE']}")
        elif c == "4":
            aes.VERBOSE = not aes.VERBOSE
            print(f"[OK] Mode Verbose AES diatur ke: {'Aktif' if aes.VERBOSE else 'Nonaktif'}")
        elif c == "5":
            break


if __name__ == "__main__":
    main()