# Fungsi-fungsi bantu yang dipakai di banyak tempat:
# baca data, bikin bobot distribusi, dan ngecek format pesan.

import math


def load_data(path):
    # baca file, satu pesan per baris, buang baris kosong sama duplikat
    hasil = []
    sudah_ada = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s and s not in sudah_ada:
                hasil.append(s)
                sudah_ada.add(s)
    return hasil


def buat_bobot(n, distribusi="uniform"):
    # bikin bobot peluang buat n pesan, sesuai bentuk distribusi yang dipilih
    if distribusi == "uniform":
        # semua pesan peluangnya sama
        return [1.0] * n
    if distribusi == "zipf":
        # pesan urutan awal jauh lebih sering muncul (mirip distribusi password asli)
        return [1.0 / (i + 1) for i in range(n)]
    if distribusi == "miring":
        # lebih ekstrem lagi, peluang numpuk di beberapa pesan teratas
        return [1.0 / ((i + 1) ** 2) for i in range(n)]
    raise ValueError("distribusi gak dikenal: " + distribusi)


def normalisasi(weights):
    # ubah bobot jadi peluang (jumlahnya 1)
    total = sum(weights)
    return [w / total for w in weights]


def luhn_valid(nomor):
    # cek nomor kartu pakai algoritma Luhn (buat dataset kartu)
    digit = [int(c) for c in nomor if c.isdigit()]
    if len(digit) != 16:
        return False
    total = 0
    for i, d in enumerate(reversed(digit)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def entropi(probs):
    # entropi Shannon (bit). Makin tinggi = makin nyebar/beragam.
    return -sum(p * math.log2(p) for p in probs if p > 0)


def kl_divergence(empiris, target):
    # KL-divergence(empiris || target), satuan bit.
    # Ngukur seberapa beda distribusi umpan yang muncul vs distribusi yang dirancang.
    total = 0.0
    for m, q in target.items():
        p = empiris.get(m, 0.0)
        if p > 0:
            total += p * math.log2(p / q)
    return total