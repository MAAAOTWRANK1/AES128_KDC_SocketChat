# chat.py
# Modul sesi chat dua arah terenkripsi AES-128
import socket
import threading
import aes

def start_chat(conn: socket.socket, peer: str, key: str, my_name: str):
    """Menjalankan sesi chat dua arah (full duplex) menggunakan AES-128."""
    active = [True]

    print(f"\n[CHAT] Sesi aman dengan {peer} aktif (Key: {key})")
    print("[CHAT] Ketik '/menu' untuk keluar ke menu utama.\n")

    def recv_loop():
        while active[0]:
            try:
                data = conn.recv(4096).decode('utf-8').strip()
                if not data or data == "CMD_LEAVE":
                    print(f"\n[INFO] {peer} keluar dari chat. Tekan Enter untuk kembali.")
                    active[0] = False
                    break
                plain = aes.decrypt(data, key)
                print(f"\n[{peer}] {plain} (Hex: {data})")
                print(f"{my_name} > ", end="", flush=True)
            except Exception:
                active[0] = False
                break

    threading.Thread(target=recv_loop, daemon=True).start()

    while active[0]:
        try:
            msg = input(f"{my_name} > ")
            if not active[0]:
                break
            if msg.strip() == "/menu":
                conn.sendall("CMD_LEAVE".encode('utf-8'))
                active[0] = False
                break
            if not msg:
                continue
            cipher_hex = aes.encrypt(msg, key)
            conn.sendall(cipher_hex.encode('utf-8'))
        except Exception:
            active[0] = False
            break

    try:
        conn.close()
    except Exception:
        pass
