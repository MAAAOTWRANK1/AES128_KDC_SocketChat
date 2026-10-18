# bob.py
import socket
import threading
import random
import aes

BOB_IP = "192.168.100.3"
BOB_PORT = 5002

ALICE_IP = "192.168.100.2"
ALICE_PORT = 5001

state = {
    "ID": "BOB",
    "KB": "master_key_bob00",  # Harus sama dengan KB di KDC
    "KS": None,                # Akan terisi otomatis setelah Langkah 4-5
    "chat_sock": None,
    "in_chat": False,
    "running": True
}


def start_chat_session(conn: socket.socket, peer_name: str):
    """Menjalankan komunikasi 2 arah terenkripsi AES menggunakan Session Key (KS)"""
    state["chat_sock"] = conn
    state["in_chat"] = True

    print("\n==================================================")
    print(f" SESI KOMUNIKASI 2 ARAH DENGAN {peer_name} AKTIF")
    print(f" Session Key (KS) ASCII : {state['KS']}")
    print(" Ketik pesan lalu tekan Enter untuk mengirim.")
    print(" Ketik '/menu' untuk keluar dari ruang chat ke menu utama.")
    print("==================================================\n")

    def receive_messages():
        while state["in_chat"]:
            try:
                data = conn.recv(4096).decode('utf-8').strip()
                if not data:
                    print(f"\n[!] {peer_name} memutus koneksi chat.")
                    state["in_chat"] = False
                    break
                if data == "CMD_LEAVE_CHAT":
                    print(f"\n[INFO] {peer_name} keluar dari sesi chat. Tekan Enter untuk kembali ke menu.")
                    state["in_chat"] = False
                    break

                print(f"\n--- PESAN MASUK DARI {peer_name} ---")
                print(f"  Ciphertext (Hex)  : {data}")
                decrypted = aes.decrypt(data, state["KS"])
                print(f"  Plaintext (ASCII) : {decrypted}")
                print("Bob (Ketik pesan / '/menu') > ", end="", flush=True)
            except Exception as e:
                if state["in_chat"]:
                    print(f"\n[!] Gagal mendekripsi / koneksi terputus: {e}")
                    state["in_chat"] = False
                break

    recv_thread = threading.Thread(target=receive_messages, daemon=True)
    recv_thread.start()

    while state["in_chat"]:
        try:
            msg = input("Bob (Ketik pesan / '/menu') > ")
            if not state["in_chat"]:
                break
            if msg.strip() == "/menu":
                conn.sendall("CMD_LEAVE_CHAT".encode('utf-8'))
                state["in_chat"] = False
                break
            if not msg:
                continue

            cipher_hex = aes.encrypt(msg, state["KS"])
            print(f"  -> Mengirim Plaintext (ASCII) : {msg}")
            print(f"  -> Mengirim Ciphertext (Hex)  : {cipher_hex}")
            conn.sendall(cipher_hex.encode('utf-8'))
        except Exception as e:
            print(f"[!] Gagal mengirim pesan: {e}")
            state["in_chat"] = False
            break

    try:
        conn.close()
    except Exception:
        pass
    print("\n[INFO] Kembali ke Menu Utama Bob.")


def wait_for_alice_handshake():
    """Menunggu Langkah 3 dari Alice, menjalankan Langkah 4 & 5, lalu masuk ke Chat"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BOB_IP, BOB_PORT))
    server.listen(1)

    print(f"\n[MENUNGGU] Bob mendengarkan di {BOB_IP}:{BOB_PORT}...")
    print("Silakan jalankan menu 'Mulai Skenario KDC' di terminal Alice.")

    try:
        conn, addr = server.accept()
        print(f"\n[LANGKAH 3] Menerima koneksi dan Tiket dari Alice ({addr[0]}:{addr[1]})")

        ticket_hex = conn.recv(4096).decode('utf-8').strip()
        print(f"  -> Tiket Masuk (Hex)       : {ticket_hex}")
        print(f"  -> Mendekripsi dengan KB   : {state['KB']}")

        ticket_plain = aes.decrypt(ticket_hex, state["KB"])
        print(f"  -> Hasil Dekripsi Tiket    : {ticket_plain}")

        ks, id_a = ticket_plain.split('|')
        state["KS"] = ks
        print(f"  [OK] Session Key (KS) diperoleh : {state['KS']} (dari {id_a})")

        # LANGKAH 4: Bob membuat Nonce N2, mengenkripsi dengan KS, kirim ke Alice
        n2 = random.randint(100000, 999999)
        step4_cipher_hex = aes.encrypt(str(n2), state["KS"])
        print(f"\n[LANGKAH 4] Mengirim tantangan Nonce N2 ke Alice")
        print(f"  -> Nonce N2 (ASCII)        : {n2}")
        print(f"  -> E(KS, N2) (Hex)         : {step4_cipher_hex}")
        conn.sendall(step4_cipher_hex.encode('utf-8'))

        # LANGKAH 5: Terima balasan E(KS, f(N2)) dari Alice
        step5_cipher_hex = conn.recv(4096).decode('utf-8').strip()
        print(f"\n[LANGKAH 5] Menerima respons verifikasi dari Alice")
        print(f"  -> Ciphertext Masuk (Hex)  : {step5_cipher_hex}")

        step5_plain = aes.decrypt(step5_cipher_hex, state["KS"])
        expected_fn2 = str(n2 - 1)
        print(f"  -> Hasil Dekripsi f(N2)    : {step5_plain} (Harapan: {expected_fn2})")

        if step5_plain == expected_fn2:
            print("  [SUKSES] Verifikasi Nonce N2 berhasil! Alice terautentikasi.")
            conn.sendall("OK".encode('utf-8'))
            start_chat_session(conn, id_a)
        else:
            print("  [GAGAL] Verifikasi Nonce N2 tidak cocok!")
            conn.sendall("FAIL".encode('utf-8'))
            conn.close()

    except Exception as e:
        print(f"\n[!] Terjadi kesalahan saat proses handshake/dekripsi: {e}")
        print("    Pastikan Master Key Bob (KB) di Bob sama dengan KB di KDC!")
    finally:
        server.close()


def main():
    print("==================================================")
    print(f"   ENTITAS BOB AKTIF                              ")
    print(f"   IP Address : {BOB_IP} | Port : {BOB_PORT}       ")
    print("==================================================")

    while True:
        print("\n--- MENU INTERAKTIF BOB ---")
        print(f"1. Siaga Terima Koneksi & Tiket dari Alice (Langkah 3-5 & Chat)")
        print(f"2. Ubah Master Key Bob (KB) [Saat ini: {state['KB']}]")
        print(f"3. Ubah Session Key (KS) Manual [Saat ini: {state['KS']}]")
        print(f"4. Uji Enkripsi / Dekripsi AES Mandiri")
        print("5. Keluar")

        choice = input("Pilihan menu Bob (1/2/3/4/5): ").strip()

        if choice == "1":
            wait_for_alice_handshake()
        elif choice == "2":
            new_kb = input("Masukkan Master Key Bob (KB) baru (ASCII): ").strip()
            if new_kb:
                state["KB"] = new_kb
                print(f"[OK] KB Bob diperbarui menjadi: {state['KB']}")
        elif choice == "3":
            new_ks = input("Masukkan Session Key (KS) secara manual (ASCII): ").strip()
            if new_ks:
                state["KS"] = new_ks
                print(f"[OK] KS Bob diatur menjadi: {state['KS']}")
        elif choice == "4":
            key_test = input("Masukkan Key (ASCII): ").strip()
            pt_test = input("Masukkan Plaintext (ASCII): ").strip()
            ct_hex = aes.encrypt(pt_test, key_test)
            dt_ascii = aes.decrypt(ct_hex, key_test)
            print(f"  -> Ciphertext (Hex) : {ct_hex}")
            print(f"  -> Dekripsi (ASCII) : {dt_ascii}")
        elif choice == "5":
            print("Menutup program Bob...")
            break
        else:
            print("[!] Pilihan tidak valid.")


if __name__ == "__main__":
    main()