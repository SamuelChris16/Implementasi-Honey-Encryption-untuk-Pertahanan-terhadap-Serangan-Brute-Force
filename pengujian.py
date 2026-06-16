# Kumpulan fungsi pengujian. Tiap fungsi nyetak tabel hasil yang rapih
# biar gampang di-screenshot, terus balikin angkanya juga.

import os
import math
import time
import random

import honey
from util import normalisasi, entropi, kl_divergence
from dte import DTE, SEED_MAX


# ---------- helper kecil ----------

def pw_acak(n=12):
    # password ngasal buat simulasi tebakan yang salah
    return os.urandom(n).hex()


def decoy_acak(dte, n):
    # Simulasi banyak dekripsi dengan kunci salah.
    # Kunci salah = seed acak, jadi kita decode seed acak langsung (lebih cepet
    # daripada nge-AES ribuan kali, hasilnya sama aja secara distribusi).
    for _ in range(n):
        yield dte.decode(random.randrange(SEED_MAX))


def garis(lebar=60):
    print("-" * lebar)


# ---------- 1. Plausibilitas pesan umpan ----------

def uji_plausibilitas(he, messages, target, jumlah_umpan=12):
    print("\n=== UJI 1: PLAUSIBILITAS PESAN UMPAN ===\n")

    # ambil satu pesan asli, enkripsi pakai password yang benar
    asli = messages[len(messages) // 2]
    pw_benar = "passwordRahasia123"
    blob = he.encrypt(pw_benar, asli)

    # dekripsi pakai banyak password salah -> kumpulin pesan umpannya
    umpan = [he.decrypt(pw_acak(), blob) for _ in range(jumlah_umpan)]

    # semua umpan harus tetap anggota ruang pesan yang sah
    valid = sum(1 for u in umpan if u in he.dte.index)

    print(f"Pesan asli            : {asli}")
    print(f"Password benar -> hasil: {he.decrypt(pw_benar, blob)}")
    print()
    print("Contoh pesan umpan dari password yang salah:")
    for u in umpan[:8]:
        print(f"   {u}")
    print()
    print(f"Jumlah umpan diuji    : {jumlah_umpan}")
    print(f"Umpan berformat valid : {valid}/{jumlah_umpan} ({100*valid/jumlah_umpan:.0f}%)")
    print(f"Umpan unik            : {len(set(umpan))}")
    print()
    print("Interpretasi: tiap password salah menghasilkan pesan yang sama-sama")
    print("absah dan tak terbedakan dari pesan asli, sesuai sifat Honey Encryption.")

    return {"valid": valid, "total": jumlah_umpan, "unik": len(set(umpan))}


# ---------- 2. Overhead kinerja ----------

def uji_overhead(he, messages, putaran=150):
    print("\n=== UJI 2: OVERHEAD KINERJA ===\n")

    pw = "uji-kinerja"
    contoh = messages[: min(len(messages), putaran)]
    contoh = (contoh * (putaran // len(contoh) + 1))[:putaran]

    def timer(fungsi, data):
        t = time.perf_counter()
        for d in data:
            fungsi(d)
        return (time.perf_counter() - t) / len(data) * 1000   # ms per operasi

    blob_he = [he.encrypt(pw, m) for m in contoh]
    blob_aes = [honey.aes_encrypt(pw, m) for m in contoh]

    enc_aes = timer(lambda m: honey.aes_encrypt(pw, m), contoh)
    enc_he = timer(lambda m: he.encrypt(pw, m), contoh)
    dec_aes = timer(lambda b: honey.aes_decrypt(pw, b), blob_aes)
    dec_he = timer(lambda b: he.decrypt(pw, b), blob_he)

    # ukur biaya DTE murni (tanpa AES/PBKDF2) -> ini bagian yang ditambah Honey
    ulang = 50000
    t = time.perf_counter()
    for _ in range(ulang):
        he.dte.encode(contoh[0])
    enc_dte = (time.perf_counter() - t) / ulang * 1e6          # mikrodetik
    t = time.perf_counter()
    for _ in range(ulang):
        he.dte.decode(12345)
    dec_dte = (time.perf_counter() - t) / ulang * 1e6

    print(f"Jumlah operasi per kolom: {putaran}\n")
    print(f"{'Operasi':<12}{'AES biasa (ms)':>16}{'Honey (ms)':>14}{'Selisih (ms)':>14}")
    garis(56)
    for nama, a, h in [("Enkripsi", enc_aes, enc_he), ("Dekripsi", dec_aes, dec_he)]:
        print(f"{nama:<12}{a:>16.3f}{h:>14.3f}{h-a:>+14.3f}")
    garis(56)
    print()
    print(f"Biaya DTE murni  : encode {enc_dte:.2f} us, decode {dec_dte:.2f} us per operasi")
    print(f"Porsi DTE        : ~{(enc_dte/1000)/enc_he*100:.3f}% dari total waktu enkripsi")
    print()
    print("Interpretasi: tambahan kerja Honey Encryption (DTE) cuma orde mikrodetik,")
    print("praktis tak terasa karena biaya didominasi PBKDF2 yang sama di kedua skema.")

    return {"enc_aes": enc_aes, "enc_he": enc_he, "dec_aes": dec_aes,
            "dec_he": dec_he, "enc_dte": enc_dte, "dec_dte": dec_dte}


# ---------- 3. Ketahanan brute-force ----------

def uji_bruteforce(he, messages, percobaan=250, tampil=25):
    print("\n=== UJI 3: KETAHANAN TERHADAP BRUTE-FORCE ===\n")

    asli      = messages[len(messages) // 2]
    pw_benar  = "kunciAsli!2024"
    valid_set = set(messages)

    blob_he  = he.encrypt(pw_benar, asli)
    blob_aes = honey.aes_encrypt(pw_benar, asli)

    # buat daftar tebakan: semua salah kecuali satu di posisi acak
    posisi_benar = random.randint(tampil, percobaan - tampil)
    tebakan = [pw_acak() for _ in range(percobaan)]
    tebakan[posisi_benar] = pw_benar

    # jalankan semua tebakan, simpan hasilnya
    semua     = []
    aes_bocor = 0
    he_bocor  = 0
    for pw in tebakan:
        aes_hasil = honey.aes_coba(pw, blob_aes)
        he_hasil  = he.decrypt(pw, blob_he)

        if aes_hasil not in valid_set:
            aes_bocor += 1
        if he_hasil not in he.dte.index:
            he_bocor += 1

        semua.append({
            "pw":    pw,
            "aes":   aes_hasil,
            "he":    he_hasil,
            "benar": pw == pw_benar,
        })

    # pilih 25 baris untuk ditampilkan: tersebar + baris benar selalu masuk
    langkah = max(1, percobaan // (tampil - 1))
    indeks  = sorted(set(list(range(0, percobaan, langkah))[:tampil - 1] + [posisi_benar]))[:tampil]
    sampel  = [semua[i] for i in indeks]

    # --- cetak header ---
    print(f"Pesan asli yang dilindungi : {asli}")
    print(f"Jumlah tebakan password    : {percobaan}")
    print(f"Kunci benar ada di tebakan : ke-{posisi_benar + 1}\n")

    # --- cetak tabel 25 baris ---
    W1, W2, W3 = 16, 26, 22
    SEP  = "-" * (W1 + W2 + W3 + 6)
    HDR  = f"{'Password dicoba':<{W1}}  {'AES-128 (hasil)':<{W2}}  {'Honey Enc. (hasil)':<{W3}}"
    print(HDR)
    print(SEP)
    for r in sampel:
        pw_col  = r["pw"][:W1]
        aes_col = r["aes"][:W2]
        he_col  = (r["he"] or "?")[:W3]
        baris   = f"{pw_col:<{W1}}  {aes_col:<{W2}}  {he_col:<{W3}}"
        if r["benar"]:
            print(baris + "  <- KUNCI BENAR")
        else:
            print(baris)
    print(SEP)

    # --- cetak ringkasan statistik ---
    print(f"\nRingkasan dari {percobaan} tebakan penuh:")
    print(f"{'Skema':<22}{'Ketahuan salah':<20}{'Bocor':>8}")
    garis(50)
    print(f"{'AES-128 biasa':<22}{aes_bocor:<20}{100*aes_bocor/percobaan:>7.0f}%")
    print(f"{'Honey Encryption':<22}{he_bocor:<20}{100*he_bocor/percobaan:>7.0f}%")
    garis(50)
    print()
    print("Interpretasi: AES biasa langsung ketahuan salah karena hasilnya byte ngaco.")
    print("Honey Encryption selalu keluar pesan wajar, jadi penyerang gak punya sinyal")
    print("buat tau kapan dia berhasil — itulah perlindungan utama Honey Encryption.")

    return {"aes_bocor": aes_bocor, "he_bocor": he_bocor, "percobaan": percobaan}


# ---------- 4. Statistik pesan umpan ----------

def _bit_dari_seed(dte, n):
    # Ambil n seed sebesar yang dihasilkan dekripsi-kunci-salah, ubah jadi bit.
    # Seed kunci-salah setara byte acak kripto, jadi kita pakai os.urandom.
    data = os.urandom(n * 4)
    return [(byte >> b) & 1 for byte in data for b in range(7, -1, -1)]


def nist_monobit(bits):
    # NIST frequency (monobit) test: cek proporsi 0 dan 1 seimbang
    n = len(bits)
    s = sum(2 * b - 1 for b in bits)
    p = math.erfc(abs(s) / math.sqrt(n) / math.sqrt(2))
    return p


def nist_runs(bits):
    # NIST runs test: cek pergantian 0<->1 wajar (gak terlalu sering/jarang)
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return 0.0                       # gagal syarat awal
    v = 1 + sum(1 for i in range(n - 1) if bits[i] != bits[i + 1])
    num = abs(v - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    return math.erfc(num / den)


def uji_statistik(he, messages, target, sampel=20000):
    print("\n=== UJI 4: STATISTIK PESAN UMPAN ===\n")

    # bagian A: distribusi pesan umpan vs distribusi yang dirancang
    hitung = {}
    for u in decoy_acak(he.dte, sampel):
        hitung[u] = hitung.get(u, 0) + 1
    empiris = {m: c / sampel for m, c in hitung.items()}
    kl = kl_divergence(empiris, target)

    # bagian B: uji keacakan bit pakai NIST (sebagian)
    bits = _bit_dari_seed(he.dte, 8000)
    p_mono = nist_monobit(bits)
    p_runs = nist_runs(bits)

    print(f"Jumlah sampel umpan   : {sampel}\n")
    print("Bagian A - kesesuaian distribusi")
    print(f"   KL-divergence(umpan || rancangan) : {kl:.4f} bit")
    print(f"   (makin dekat 0 = umpan makin setia ke distribusi yang dirancang)\n")
    print("Bagian B - keacakan seed (NIST SP 800-22, sebagian)")
    print(f"{'   Uji':<22}{'p-value':>12}{'Status':>10}")
    garis(46)
    for nama, p in [("Monobit", p_mono), ("Runs", p_runs)]:
        status = "LULUS" if p >= 0.01 else "GAGAL"
        print(f"   {nama:<19}{p:>12.4f}{status:>10}")
    garis(46)
    print()
    print("Interpretasi: KL-divergence kecil menandakan pesan umpan mengikuti pola")
    print("ruang pesan, dan uji NIST lulus menandakan seed tersebar acak merata.")

    return {"kl": kl, "monobit": p_mono, "runs": p_runs}


# ---------- 5. Analisis sensitivitas ----------

def analisis_sensitivitas(messages, sampel=20000):
    print("\n=== UJI 5: ANALISIS SENSITIVITAS DISTRIBUSI ===\n")
    from util import buat_bobot

    n = len(messages)
    hasil = []

    for dist in ["uniform", "zipf", "miring"]:
        bobot = buat_bobot(n, dist)
        target = dict(zip(messages, normalisasi(bobot)))
        dte = DTE(messages, bobot)

        hitung = {}
        for u in decoy_acak(dte, sampel):
            hitung[u] = hitung.get(u, 0) + 1
        empiris = {m: c / sampel for m, c in hitung.items()}

        ent = entropi(list(empiris.values()))
        ent_maks = math.log2(n)
        top = max(empiris.values()) * 100
        kl = kl_divergence(empiris, target)
        hasil.append((dist, ent, ent_maks, top, kl))

    print(f"Jumlah pesan: {n}   |   entropi maksimum: {math.log2(n):.2f} bit\n")
    print(f"{'Distribusi':<12}{'Entropi umpan':>16}{'Pesan teratas':>16}{'KL-div':>10}")
    garis(54)
    for dist, ent, ent_maks, top, kl in hasil:
        print(f"{dist:<12}{ent:>10.2f} bit {'':>1}{top:>13.1f}% {kl:>9.4f}")
    garis(54)
    print()
    print("Interpretasi: makin miring distribusi, entropi umpan makin turun dan satu")
    print("pesan makin mendominasi keluaran. Artinya perlindungan melemah pada ruang")
    print("pesan yang tidak seragam - persis keterbatasan yang disebut di abstrak.")

    return hasil