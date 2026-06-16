# Honey Encryption = DTE + AES-128.
# Alurnya: pesan diubah jadi seed lewat DTE, seed-nya dienkripsi AES.
# Kuncinya: kalau password salah, hasil dekrip AES jadi seed yang acak,
# dan DTE tetap nerjemahin seed acak itu jadi pesan yang kelihatan wajar.
# Jadi penyerang gak bisa tau dari output mana yang bener mana yang umpan.

import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PBKDF2_ITER = 100_000   # iterasi PBKDF2, biar nurunin kunci makin mahal buat ditebak
SEED_LEN = 4            # seed disimpan 4 byte (32 bit), nyambung sama DTE


def turunkan_kunci(password, salt):
    # password -> kunci AES-128 (16 byte) lewat PBKDF2
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITER, dklen=16)


class HoneyEncryption:
    def __init__(self, dte):
        self.dte = dte

    def encrypt(self, password, message):
        seed = self.dte.encode(message)
        plain = seed.to_bytes(SEED_LEN, "big")

        salt = os.urandom(16)
        nonce = os.urandom(16)
        key = turunkan_kunci(password, salt)

        # Pakai AES mode CTR: gak perlu padding, tiap byte di-XOR sama keystream.
        # Ini penting buat honey: dekrip pakai kunci apapun selalu ngasih byte valid,
        # gak ada error "padding rusak" yang bisa dipakai penyerang buat nebak.
        enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
        ct = enc.update(plain) + enc.finalize()
        return salt + nonce + ct          # semua digabung jadi satu blob

    def decrypt(self, password, blob):
        salt, nonce, ct = blob[:16], blob[16:32], blob[32:]
        key = turunkan_kunci(password, salt)

        dec = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
        plain = dec.update(ct) + dec.finalize()

        seed = int.from_bytes(plain, "big")
        return self.dte.decode(seed)


# --- Enkripsi biasa (cuma AES, tanpa DTE) buat pembanding di pengujian ---

def aes_encrypt(password, message):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = turunkan_kunci(password, salt)

    data = message.encode()
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad            # padding PKCS7

    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    return salt + iv + ct


def aes_decrypt(password, blob):
    salt, iv, ct = blob[:16], blob[16:32], blob[32:]
    key = turunkan_kunci(password, salt)

    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    data = dec.update(ct) + dec.finalize()

    pad = data[-1]
    if pad < 1 or pad > 16:
        raise ValueError("padding rusak")      # kunci salah ketauan di sini
    return data[:-pad].decode("utf-8")         # ini juga bisa gagal kalau byte ngaco

def aes_coba(password, blob):
    # versi aes_decrypt yang gak lempar exception —
    # kalau kunci salah dan hasilnya byte ngaco, balikin hex pendek
    # biar bisa ditampilin langsung di tabel perbandingan
    salt, iv, ct = blob[:16], blob[16:32], blob[32:]
    key = turunkan_kunci(password, salt)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    raw = dec.update(ct) + dec.finalize()
    pad = raw[-1]
    if pad < 1 or pad > 16:
        return "\\x" + raw[:6].hex() + "…"    # padding rusak = jelas gibberish
    try:
        return raw[:-pad].decode("utf-8")
    except UnicodeDecodeError:
        return "\\x" + raw[:6].hex() + "…"    # byte ngaco = juga gibberish