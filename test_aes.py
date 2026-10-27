# test_aes.py
# Unit test mandiri untuk verifikasi algoritma AES-128
import os
import aes


def test_fips_197():
    print("[1/5] Uji Standar Resmi NIST FIPS-197 C.1 (Single Block)...", end=" ")
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ct = "69c4e0d86a7b0430d8cdb78070b4c55a"

    rk = aes.key_expansion(key)
    ct = aes.encrypt_block(pt, rk)
    assert ct.hex() == expected_ct, f"Mismatch: {ct.hex()} != {expected_ct}"
    assert aes.decrypt_block(ct, rk) == pt, "Dekripsi tidak mengembalikan plaintext asli"
    print("OK (Lolos)")


def test_nist_sp800_38a_ecb():
    print("[2/5] Uji NIST SP 800-38A ECB-AES128 (2 Blok)...", end=" ")
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    rk = aes.key_expansion(key)

    b1_pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    b1_exp = "3ad77bb40d7a3660a89ecaf32466ef97"
    assert aes.encrypt_block(b1_pt, rk).hex() == b1_exp
    assert aes.decrypt_block(bytes.fromhex(b1_exp), rk) == b1_pt

    b2_pt = bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51")
    b2_exp = "f5d3d58503b9699de785895a96fdbaaf"
    assert aes.encrypt_block(b2_pt, rk).hex() == b2_exp
    assert aes.decrypt_block(bytes.fromhex(b2_exp), rk) == b2_pt
    print("OK (Lolos)")


def test_nist_sp800_38a_cbc():
    print("[3/6] Uji NIST SP 800-38A CBC-AES128 (2 Blok)...", end=" ")
    key_hex = "2b7e151628aed2a6abf7158809cf4f3c"
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    key_ascii = bytes.fromhex(key_hex).decode('latin1')

    # NIST plaintext blocks
    pt_bytes = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    rk = aes.key_expansion(bytes.fromhex(key_hex))

    # Test raw block chaining directly against NIST standard
    c1 = aes.encrypt_block(aes.xor_bytes(pt_bytes[:16], iv), rk)
    assert c1.hex() == "7649abac8119b246cee98e9b12e9197d"
    c2 = aes.encrypt_block(aes.xor_bytes(pt_bytes[16:], c1), rk)
    assert c2.hex() == "5086cb9b507219ee95db113a917678b2"

    # Test decrypt block
    d2 = aes.xor_bytes(aes.decrypt_block(c2, rk), c1)
    assert d2 == pt_bytes[16:]
    d1 = aes.xor_bytes(aes.decrypt_block(c1, rk), iv)
    assert d1 == pt_bytes[:16]

    # Test full encrypt_cbc and decrypt_cbc roundtrip
    msg = "Pesan rahasia dengan CBC Mode"
    ct_cbc = aes.encrypt_cbc(msg, "kunci_rahasia_16")
    dec_cbc = aes.decrypt_cbc(ct_cbc, "kunci_rahasia_16")
    assert dec_cbc == msg
    print("OK (Lolos)")


def test_padding():
    print("[3/5] Uji PKCS#7 Padding (0, 15, 16, 17, 32 Byte)...", end=" ")
    test_lengths = [0, 15, 16, 17, 32]
    key = "kunci_rahasia_16"

    for length in test_lengths:
        text = "A" * length
        ct = aes.encrypt(text, key)
        dec = aes.decrypt(ct, key)
        assert dec == text, f"Gagal pada panjang {length}"
    print("OK (Lolos)")


def test_invalid_key():
    print("[4/5] Uji Validasi & Penolakan Kunci Salah...", end=" ")
    # Uji panjang kunci tidak 16 karakter
    for bad_key in ["pendek", "kuncisangatpanjangsekali12345"]:
        try:
            aes.prepare_key(bad_key)
            assert False, "Harusnya melempar ValueError untuk kunci non-16"
        except ValueError:
            pass

    # Uji dekripsi dengan kunci yang salah
    ct = aes.encrypt("Pesan Rahasia", "kuncibenar_12345")
    try:
        aes.decrypt(ct, "kuncisalah_12345")
        assert False, "Harusnya gagal dekripsi saat kunci salah"
    except ValueError:
        pass
    print("OK (Lolos)")


def test_random_roundtrip():
    print("[5/5] Uji Roundtrip 20 Blok Acak...", end=" ")
    for _ in range(20):
        k = os.urandom(16)
        p = os.urandom(16)
        rk = aes.key_expansion(k)
        c = aes.encrypt_block(p, rk)
        d = aes.decrypt_block(c, rk)
        assert d == p, "Mismatch pada blok acak"
    print("OK (Lolos)")


if __name__ == "__main__":
    print("=== PENGUJIAN UNIT AES-128 MANUAL ===")
    test_fips_197()
    test_nist_sp800_38a_ecb()
    test_nist_sp800_38a_cbc()
    test_padding()
    test_invalid_key()
    test_random_roundtrip()
    print("SEMUA PENGUJIAN BERHASIL 100%!")
