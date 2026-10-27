# chat.py
# Modul sesi chat dua arah dan framing pesan TCP
import socket
import threading
import aes


def send_msg(sock: socket.socket, msg: str):
    """Kirim pesan berbingkai dengan penutup newline '\\n'."""
    sock.sendall((msg.strip() + "\n").encode('utf-8'))


def recv_msg(sock: socket.socket) -> str:
    """Membaca aliran TCP byte-per-byte hingga karakter '\\n' atau EOF."""
    buf = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            break
        if chunk == b'\n':
            break
        buf.extend(chunk)
    return buf.decode('utf-8').strip()


def start_chat(conn: socket.socket, peer: str, key: str, my_name: str):
    """Menjalankan sesi chat dua arah (full duplex) menggunakan AES-128."""
    active = [True]

    print(f"\n[CHAT] Sesi aman dengan {peer} aktif (Key: {key})")
    print("[CHAT] Ketik '/menu' untuk keluar ke menu utama.\n")

    def recv_loop():
        while active[0]:
            try:
                data = recv_msg(conn)
                if not data or data == "CMD_LEAVE":
                    print(f"\n[INFO] {peer} keluar dari chat. Tekan Enter untuk kembali.")
                    active[0] = False
                    break
                plain = aes.decrypt(data, key)
                print(f"\n[{peer}] {plain} (Hex: {data})")
                print(f"{my_name} > ", end="", flush=True)
            except ValueError as ve:
                print(f"\n[!] Pesan hex rusak dari {peer}: {ve}")
                print(f"{my_name} > ", end="", flush=True)
            except Exception:
                active[0] = False
                break

    threading.Thread(target=recv_loop, daemon=True).start()

    try:
        while active[0]:
            msg = input(f"{my_name} > ")
            if not active[0]:
                break
            if msg.strip() == "/menu":
                send_msg(conn, "CMD_LEAVE")
                active[0] = False
                break
            if not msg.strip():
                continue
            cipher_hex = aes.encrypt(msg, key)
            send_msg(conn, cipher_hex)
    finally:
        active[0] = False
        try:
            conn.close()
        except Exception:
            pass
