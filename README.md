# AES128_KDC_SocketChat

Implementasi manual algoritma AES-128 dan protokol Key Distribution Center (KDC) 5-langkah (Stallings) untuk komunikasi dua arah berbasis TCP Socket antar 3 entitas (KDC, Alice, Bob) di IP berbeda tanpa library kriptografi eksternal.

## Alur Protokol 5-Langkah (Stallings)

```
1. Alice -> KDC : ID_A || ID_B || N1
2. KDC -> Alice : E(Ka, [Ks || ID_B || N1 || E(Kb, [Ks || ID_A])])
3. Alice -> Bob : E(Kb, [Ks || ID_A])
4. Bob -> Alice : E(Ks, N2)
5. Alice -> Bob : E(Ks, f(N2))  [f(N2) = N2 - 1]
   Setelah Langkah 5, Alice dan Bob berkomunikasi dua arah menggunakan AES-128 (Ks).
```

## Struktur File

- `aes.py`   : Implementasi inti manual AES-128 (SubBytes, ShiftRows, MixColumns, AddRoundKey, KeyExpansion, PKCS#7).
- `kdc.py`   : Server KDC penyedia Session Key (Ks) dan tiket terenkripsi.
- `bob.py`   : Entitas Bob (penerima tiket, penantang nonce N2, dan peserta chat).
- `alice.py` : Entitas Alice (inisiator permintaan KDC, pengirim tiket, dan peserta chat).
- `chat.py`  : Modul komunikasi teks dua arah (full duplex) terenkripsi AES-128.

## Cara Menjalankan (Contoh 3 Mesin / IP Berbeda)

Asumsi IP:
- Mesin KDC   : `192.168.1.10`
- Mesin Bob   : `192.168.1.20`
- Mesin Alice : `192.168.1.30`

Jalankan program dengan urutan berikut:

### 1. Mesin KDC
```bash
python kdc.py --host 0.0.0.0 --port 5000
```

### 2. Mesin Bob
```bash
python bob.py --host 0.0.0.0 --port 5002
```
Pilih menu `1` untuk siaga menerima koneksi.

### 3. Mesin Alice
```bash
python alice.py --kdc-host 192.168.1.10 --kdc-port 5000 --bob-host 192.168.1.20 --bob-port 5002
```
Pilih menu `1` untuk memulai pertukaran kunci dan masuk ke ruang chat.

*(Catatan: Untuk demo pada 1 mesin, cukup jalankan masing-masing file tanpa argumen tambahan karena default host mengarah ke localhost/127.0.0.1).*

## Pengamatan Wireshark

1. Pilih interface jaringan aktif (misal `Wi-Fi` atau `Ethernet`).
2. Masukkan Display Filter berikut:
   ```wireshark
   tcp.port == 5000 || tcp.port == 5002
   ```
3. Klik kanan paket TCP -> **Follow** -> **TCP Stream** untuk mengamati bahwa data setelah Langkah 1 berupa string Heksadesimal terenkripsi tanpa kebocoran plaintext.
