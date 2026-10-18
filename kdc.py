# kdc.py
import socket
import threading
import random
import string
import aes

KDC_IP = "192.168.100.1"
KDC_PORT = 5000

# State penyimpanan kunci di KDC (Bisa diubah lewat menu interaktif)
state = {
    "KA": "master_key_alice",  # Master Key KDC - Alice (16 char ASCII)
    "KB": "master_key_bob00",  # Master Key KDC - Bob (16 char ASCII)
    "KS_MODE": "AUTO",         # AUTO (acak) atau MANUAL (ditentukan pengguna)
    "KS_MANUAL": "session_key_1234",
    "running": True
}


def generate_session_key() -> str:
    if state["KS_MODE"] == "MANUAL":
        return state["KS_MANUAL"]
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=16))


def handle_client(conn: socket.socket, addr):
    try:
        data = conn.recv(4096).decode('utf-8').strip()
        if not data:
            return

        print(f"\n[LANGKAH 1] Menerima request dari {addr[0]}:{addr[1]}")
        print(f"  -> Data masuk (ASCII) : {data}")

        parts = data.split('|')
        if len(parts) != 3:
            print("  [!] Format request tidak valid. Harus: IDA|IDB|N1")
            return

        id_a, id_b, n1 = parts
        ks = generate_session_key()

        print(f"\n[LANGKAH 2] Memproses distribusi kunci untuk {id_a} & {id_b}")
        print(f"  -> Master Key Alice (KA) : {state['KA']}")
        print(f"  -> Master Key Bob   (KB) : {state['KB']}")
        print(f"  -> Session Key baru (KS) : {ks}")

        # Buat Tiket untuk Bob: E(KB, [KS || IDA])
        ticket_plain = f"{ks}|{id_a}"
        ticket_cipher_hex = aes.encrypt(ticket_plain, state["KB"])
        print(f"  -> Tiket Bob Plaintext   : {ticket_plain}")
        print(f"  -> Tiket Bob Cipher (Hex): {ticket_cipher_hex}")

        # Buat Paket untuk Alice: E(KA, [KS || IDB || N1 || Tiket_Hex])
        alice_plain = f"{ks}|{id_b}|{n1}|{ticket_cipher_hex}"
        alice_cipher_hex = aes.encrypt(alice_plain, state["KA"])
        print(f"  -> Paket Alice Plaintext : {alice_plain}")
        print(f"  -> Paket Alice (Hex)     : {alice_cipher_hex}")

        conn.sendall(alice_cipher_hex.encode('utf-8'))
        print(f"  [OK] Paket Langkah 2 berhasil dikirim ke {id_a} ({addr[0]})")
        print("Pilihan menu KDC (1/2/3/4/5): ", end="", flush=True)

    except Exception as e:
        print(f"\n  [!] Error saat memproses KDC: {e}")
    finally:
        conn.close()


def server_loop():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((KDC_IP, KDC_PORT))
    server.listen(5)
    server.settimeout(1.0)

    while state["running"]:
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception as e:
            if state["running"]:
                print(f"\n[!] Server error: {e}")
            break
    server.close()


def main():
    t = threading.Thread(target=server_loop, daemon=True)
    t.start()

    print("==================================================")
    print(f"   KEY DISTRIBUTION CENTER (KDC) AKTIF            ")
    print(f"   IP Address : {KDC_IP} | Port : {KDC_PORT}       ")
    print("==================================================")

    while True:
        print("\n--- MENU INTERAKTIF KDC ---")
        print(f"1. Lihat Konfigurasi Kunci Saat Ini")
        print(f"2. Ubah Master Key Alice (KA) [Saat ini: {state['KA']}]")
        print(f"3. Ubah Master Key Bob   (KB) [Saat ini: {state['KB']}]")
        print(f"4. Atur Session Key (KS)      [Mode: {state['KS_MODE']}]")
        print("5. Keluar")

        choice = input("Pilihan menu KDC (1/2/3/4/5): ").strip()

        if choice == "1":
            print(f"\n[INFO KUNCI KDC]")
            print(f"  KA (Master Key Alice) : {state['KA']}")
            print(f"  KB (Master Key Bob)   : {state['KB']}")
            print(f"  Mode Session Key (KS) : {state['KS_MODE']}")
            if state["KS_MODE"] == "MANUAL":
                print(f"  KS Manual             : {state['KS_MANUAL']}")
        elif choice == "2":
            new_ka = input("Masukkan Master Key Alice (KA) baru (ASCII): ").strip()
            if new_ka:
                state["KA"] = new_ka
                print(f"[OK] KA diperbarui menjadi: {state['KA']}")
        elif choice == "3":
            new_kb = input("Masukkan Master Key Bob (KB) baru (ASCII): ").strip()
            if new_kb:
                state["KB"] = new_kb
                print(f"[OK] KB diperbarui menjadi: {state['KB']}")
        elif choice == "4":
            mode = input("Pilih mode KS (1 = Otomatis Acak, 2 = Input Manual): ").strip()
            if mode == "1":
                state["KS_MODE"] = "AUTO"
                print("[OK] Session Key diatur ke mode Otomatis (Acak 16 karakter).")
            elif mode == "2":
                ks_man = input("Masukkan Session Key (KS) manual (ASCII): ").strip()
                if ks_man:
                    state["KS_MODE"] = "MANUAL"
                    state["KS_MANUAL"] = ks_man
                    print(f"[OK] Session Key manual diatur ke: {state['KS_MANUAL']}")
        elif choice == "5":
            state["running"] = False
            print("Menutup KDC...")
            break
        else:
            print("[!] Pilihan tidak valid.")


if __name__ == "__main__":
    main()