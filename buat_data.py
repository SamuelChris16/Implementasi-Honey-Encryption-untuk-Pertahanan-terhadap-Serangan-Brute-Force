# Skrip buat ngisi folder data/ dengan data contoh.
# Cukup dijalanin sekali: python buat_data.py
# Habis itu file di data/ boleh diganti/ditambah sendiri sesuka hati.

import os
import random

random.seed(7)   # biar tiap di-generate hasilnya sama


# 50 password umum (dari daftar password yang sering bocor)
PASSWORDS = [
    "123456", "password", "123456789", "12345678", "qwerty",
    "abc123", "111111", "1234567", "iloveyou", "000000",
    "admin", "letmein", "monkey", "dragon", "sunshine",
    "princess", "football", "welcome", "qwerty123", "1q2w3e4r",
    "master", "superman", "trustno1", "baseball", "shadow",
    "michael", "jordan23", "harley", "hunter", "ranger",
    "buster", "soccer", "killer", "george", "asshole",
    "andrew", "charlie", "robert", "thomas", "hockey",
    "ginger", "joshua", "cheese", "amanda", "summer",
    "ashley", "nicole", "chelsea", "biteme", "matthew",
]


def luhn_lengkap(prefix, panjang=16):
    # bikin nomor kartu valid: isi acak dulu, terus hitung digit cek Luhn
    nomor = [int(c) for c in prefix]
    while len(nomor) < panjang - 1:
        nomor.append(random.randint(0, 9))

    total = 0
    for i, d in enumerate(reversed(nomor)):
        if i % 2 == 0:        # posisi yang bakal kena dobel pas dicek
            d *= 2
            if d > 9:
                d -= 9
        total += d
    cek = (10 - total % 10) % 10
    nomor.append(cek)
    return "".join(str(d) for d in nomor)


def buat_kartu(jumlah=50):
    prefix = ["4", "51", "52", "53", "54", "55"]   # Visa / Mastercard
    kartu = set()
    while len(kartu) < jumlah:
        kartu.add(luhn_lengkap(random.choice(prefix)))
    return sorted(kartu)


def buat_nip(jumlah=50):
    # NIP gaya pegawai: 18 digit (tanggal lahir + tahun + kode + urut)
    nip = set()
    while len(nip) < jumlah:
        thn = random.randint(1975, 1998)
        bln = random.randint(1, 12)
        tgl = random.randint(1, 28)
        masuk = random.randint(2005, 2020)
        kode = random.choice([1, 2])
        urut = random.randint(1, 999)
        nip.add(f"{thn}{bln:02d}{tgl:02d}{masuk}03{kode}{urut:03d}")
    return sorted(nip)


def tulis(path, baris):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(baris) + "\n")


if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    tulis("data/passwords.txt", PASSWORDS)
    tulis("data/kartu.txt", buat_kartu())
    tulis("data/nip.txt", buat_nip())
    print("data contoh berhasil dibuat di folder data/")