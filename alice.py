# alice.py
import socket
import threading
import random
import aes

ALICE_IP = "192.168.100.2"
ALICE_PORT = 5001

KDC_IP = "192.168.100.1"
KDC_PORT = 5000

BOB_IP = "192.168.100.3"
BOB_PORT = 5002

state = {
    "ID": "ALICE",
    "TARGET_ID": "BOB",
    "KA": "master_key_alice",  # Harus sama dengan KA di KDC
    "KS": None,                # Akan diperoleh dari KDC
    "in_chat": False
}


def start_chat_session(conn: socket.socket, peer_name: str):
    """Menjalankan komunikasi 2 arah terenkripsi AES menggunakan Session Key (KS)"""
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
                print("Alice (Ketik pesan / '/menu') > ", end="", flush=True)
            except Exception as e:
                if state["in_chat"]:
                    print(f"\n[!] Gagal mendekripsi / koneksi terputus: {e}")
                    state["in_chat"] = False
                break

    recv_thread = threading.Thread(target=receive_messages, daemon=True)
    recv_thread.start()

    while state["in_chat"]:
        try:
            msg = input("Alice (Ketik pesan / '/menu') > ")
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
    print("\n[INFO] Kembali ke Menu Utama Alice.")


def initiate_kdc_and_handshake():
    """Menjalankan Langkah 1 ke KDC, Langkah 2 dari KDC, dan Langkah 3-5 ke Bob"""
    n1 = str(random.randint(100000, 999999))
    req_msg = f"{state['ID']}|{state['TARGET_ID']}|{n1}"

    # LANGKAH 1 & 2: Komunikasi dengan KDC
    try:
        kdc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind ke IP Alice agar di Wireshark Source IP tercatat sebagai 192.168.100.2
        kdc_sock.bind((ALICE_IP, 0))
        kdc_sock.connect((KDC_IP, KDC_PORT))

        print(f"\n[LANGKAH 1] Mengirim request Session Key ke KDC ({KDC_IP}:{KDC_PORT})")
        print(f"  -> Payload Request (ASCII) : {req_msg}")
        kdc_sock.sendall(req_msg.encode('utf-8'))

        step2_cipher_hex = kdc_sock.recv(4096).decode('utf-8').strip()
        kdc_sock.close()

        print(f"\n[LANGKAH 2] Menerima balasan terenkripsi dari KDC")
        print(f"  -> Ciphertext Masuk (Hex)  : {step2_cipher_hex}")
        print(f"  -> Mendekripsi dengan KA   : {state['KA']}")

        step2_plain = aes.decrypt(step2_cipher_hex, state["KA"])
        print(f"  -> Hasil Dekripsi (ASCII)  : {step2_plain}")

        ks, id_b, recv_n1, ticket_hex = step2_plain.split('|')

        if recv_n1 != n1:
            print(f"  [GAGAL] Nonce N1 tidak cocok! ({recv_n1} != {n1})")
            return

        state["KS"] = ks
        print(f"  [OK] Nonce N1 terverifikasi ({n1}).")
        print(f"  [OK] Session Key (KS) diperoleh : {state['KS']}")
        print(f"  [OK] Tiket untuk Bob (Hex)      : {ticket_hex}")

    except Exception as e:
        print(f"\n[!] Gagal pada tahap KDC (Langkah 1-2): {e}")
        print("    Pastikan kdc.py sudah jalan dan Master Key Alice (KA) cocok!")
        return

    # LANGKAH 3, 4, & 5: Menghubungi Bob
    try:
        bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bob_sock.bind((ALICE_IP, 0))
        print(f"\n[LANGKAH 3] Menghubungi Bob ({BOB_IP}:{BOB_PORT}) dan mengirim Tiket...")
        bob_sock.connect((BOB_IP, BOB_PORT))
        bob_sock.sendall(ticket_hex.encode('utf-8'))

        # LANGKAH 4: Terima tantangan E(KS, N2) dari Bob
        step4_cipher_hex = bob_sock.recv(4096).decode('utf-8').strip()
        print(f"\n[LANGKAH 4] Menerima tantangan Nonce N2 dari Bob")
        print(f"  -> Ciphertext Masuk (Hex)  : {step4_cipher_hex}")

        n2_str = aes.decrypt(step4_cipher_hex, state["KS"])
        n2_val = int(n2_str)
        print(f"  -> Hasil Dekripsi Nonce N2 : {n2_val}")

        # LANGKAH 5: Hitung f(N2) = N2 - 1, enkripsi dengan KS, kirim ke Bob
        fn2_val = n2_val - 1
        step5_cipher_hex = aes.encrypt(str(fn2_val), state["KS"])
        print(f"\n[LANGKAH 5] Mengirim balasan f(N2) = N2 - 1 ke Bob")
        print(f"  -> Plaintext f(N2) (ASCII) : {fn2_val}")
        print(f"  -> E(KS, f(N2)) (Hex)      : {step5_cipher_hex}")
        bob_sock.sendall(step5_cipher_hex.encode('utf-8'))

        status = bob_sock.recv(1024).decode('utf-8').strip()
        if status == "OK":
            print("  [SUKSES] Bob mengonfirmasi verifikasi Langkah 5!")
            start_chat_session(bob_sock, state["TARGET_ID"])
        else:
            print("  [GAGAL] Bob menolak verifikasi Langkah 5.")
            bob_sock.close()

    except Exception as e:
        print(f"\n[!] Gagal saat menghubungi Bob (Langkah 3-5): {e}")
        print("    Pastikan di terminal Bob sudah memilih menu 1 (Siaga Terima Koneksi)!")


def main():
    print("==================================================")
    print(f"   ENTITAS ALICE AKTIF                            ")
    print(f"   IP Address : {ALICE_IP} | Port : {ALICE_PORT}     ")
    print("==================================================")

    while True:
        print("\n--- MENU INTERAKTIF ALICE ---")
        print(f"1. Mulai Skenario KDC (Langkah 1-5) & Masuk Chat dengan Bob")
        print(f"2. Ubah Master Key Alice (KA) [Saat ini: {state['KA']}]")
        print(f"3. Ubah Session Key (KS) Manual [Saat ini: {state['KS']}]")
        print(f"4. Uji Enkripsi / Dekripsi AES Mandiri")
        print("5. Keluar")

        choice = input("Pilihan menu Alice (1/2/3/4/5): ").strip()

        if choice == "1":
            initiate_kdc_and_handshake()
        elif choice == "2":
            new_ka = input("Masukkan Master Key Alice (KA) baru (ASCII): ").strip()
            if new_ka:
                state["KA"] = new_ka
                print(f"[OK] KA Alice diperbarui menjadi: {state['KA']}")
        elif choice == "3":
            new_ks = input("Masukkan Session Key (KS) secara manual (ASCII): ").strip()
            if new_ks:
                state["KS"] = new_ks
                print(f"[OK] KS Alice diatur menjadi: {state['KS']}")
        elif choice == "4":
            key_test = input("Masukkan Key (ASCII): ").strip()
            pt_test = input("Masukkan Plaintext (ASCII): ").strip()
            ct_hex = aes.encrypt(pt_test, key_test)
            dt_ascii = aes.decrypt(ct_hex, key_test)
            print(f"  -> Ciphertext (Hex) : {ct_hex}")
            print(f"  -> Dekripsi (ASCII) : {dt_ascii}")
        elif choice == "5":
            print("Menutup program Alice...")
            break
        else:
            print("[!] Pilihan tidak valid.")


if __name__ == "__main__":
    main()