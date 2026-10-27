# alice.py
# Entitas Alice (Inisiator Skenario Distribusi Kunci)
import socket
import random
import argparse
import aes
import chat

config = {
    "ID": "ALICE",
    "TARGET_ID": "BOB",
    "KA": "master_key_alice"
}


def run_scenario(kdc_host: str, kdc_port: int, bob_host: str, bob_port: int):
    n1 = str(random.randint(100000, 999999))
    req = f"{config['ID']}|{config['TARGET_ID']}|{n1}"

    # Langkah 1 & 2: Hubungi KDC
    try:
        kdc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        kdc_sock.connect((kdc_host, kdc_port))

        print(f"\n[Langkah 1] Kirim request ke KDC ({kdc_host}:{kdc_port}): {req}")
        kdc_sock.sendall(req.encode('utf-8'))

        step2_hex = kdc_sock.recv(4096).decode('utf-8').strip()
        kdc_sock.close()

        print(f"[Langkah 2] Terima dari KDC (Hex): {step2_hex}")
        step2_plain = aes.decrypt(step2_hex, config["KA"])
        ks, target, recv_n1, ticket_hex = step2_plain.split('|')

        if recv_n1 != n1:
            print(f"[!] Nonce N1 tidak cocok ({recv_n1} != {n1})!")
            return

        print(f"  Nonce N1 terverifikasi ({n1})")
        print(f"  Session Key (KS) : {ks}")
        print(f"  Tiket Bob (Hex)  : {ticket_hex}")
    except Exception as e:
        print(f"[!] Gagal pada KDC (Langkah 1-2): {e}")
        return

    # Langkah 3, 4, 5: Hubungi Bob
    try:
        bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bob_sock.connect((bob_host, bob_port))

        print(f"\n[Langkah 3] Kirim Tiket ke Bob ({bob_host}:{bob_port})")
        bob_sock.sendall(ticket_hex.encode('utf-8'))

        step4_hex = bob_sock.recv(4096).decode('utf-8').strip()
        n2_val = int(aes.decrypt(step4_hex, ks))
        print(f"[Langkah 4] Terima tantangan N2 dari Bob: {n2_val} (Hex: {step4_hex})")

        fn2_val = n2_val - 1
        step5_hex = aes.encrypt(str(fn2_val), ks)
        print(f"[Langkah 5] Kirim f(N2) = {fn2_val} ke Bob (Hex: {step5_hex})")
        bob_sock.sendall(step5_hex.encode('utf-8'))

        ack = bob_sock.recv(1024).decode('utf-8').strip()
        if ack == "OK":
            print("[OK] Handshake sukses! Masuk ke ruang chat.")
            chat.start_chat(bob_sock, config["TARGET_ID"], ks, "Alice")
        else:
            print("[!] Handshake ditolak oleh Bob.")
            bob_sock.close()
    except Exception as e:
        print(f"[!] Gagal pada handshake Bob (Langkah 3-5): {e}")


def input_key(prompt: str) -> str:
    val = input(prompt).strip()
    if len(val.encode('utf-8')) != 16:
        print(f"[!] Ditolak: Kunci harus tepat 16 karakter ASCII (diberikan {len(val)})!")
        return ""
    return val


def main():
    parser = argparse.ArgumentParser(description="Alice Entity")
    parser.add_argument("--kdc-host", default="127.0.0.1", help="IP address KDC (default: 127.0.0.1)")
    parser.add_argument("--kdc-port", type=int, default=5000, help="Port KDC (default: 5000)")
    parser.add_argument("--bob-host", default="127.0.0.1", help="IP address Bob (default: 127.0.0.1)")
    parser.add_argument("--bob-port", type=int, default=5002, help="Port Bob (default: 5002)")
    args = parser.parse_args()

    print(f"Alice aktif (KA: {config['KA']})")
    print(f"Target KDC: {args.kdc_host}:{args.kdc_port} | Target Bob: {args.bob_host}:{args.bob_port}")

    while True:
        print("\n--- MENU ALICE ---")
        print("1. Mulai Skenario KDC & Chat dengan Bob")
        print(f"2. Ubah Master Key Alice (KA) [Saat ini: {config['KA']}]")
        print("3. Keluar")

        c = input("Pilihan > ").strip()
        if c == "1":
            run_scenario(args.kdc_host, args.kdc_port, args.bob_host, args.bob_port)
        elif c == "2":
            val = input_key("KA Baru (16 karakter ASCII): ")
            if val:
                config["KA"] = val
                print(f"[OK] KA diubah: {config['KA']}")
        elif c == "3":
            break


if __name__ == "__main__":
    main()