# Menu utama. Tinggal jalanin: python main.py
# Alurnya: pilih data -> pilih distribusi -> pilih pengujian -> lihat hasil.

from dte import DTE
from honey import HoneyEncryption
from util import load_data, buat_bobot, normalisasi
import pengujian


DATASET = {
    "1": ("Password umum", "data/passwords.txt"),
    "2": ("Nomor kartu", "data/kartu.txt"),
    "3": ("NIP pegawai", "data/nip.txt"),
}

DISTRIBUSI = {
    "1": ("uniform", "Uniform (semua sama)"),
    "2": ("zipf", "Zipf (mirip data nyata)"),
    "3": ("miring", "Miring (sangat tidak seragam)"),
}

UJI = {
    "1": "Plausibilitas pesan umpan",
    "2": "Overhead kinerja",
    "3": "Ketahanan brute-force",
    "4": "Statistik pesan umpan",
    "5": "Analisis sensitivitas",
    "6": "Jalankan semua",
}


def pilih(judul, opsi):
    # opsi: dict key -> label (string) yang mau ditampilkan
    print("\n" + judul)
    for k, label in opsi.items():
        print(f"  {k}. {label}")
    return input("Pilihan: ").strip()


def main():
    print("=" * 50)
    print(" HONEY ENCRYPTION + AES-128  |  alat pengujian")
    print("=" * 50)

    d = pilih("Pilih dataset:", {k: v[0] for k, v in DATASET.items()})
    nama_data, path = DATASET.get(d, DATASET["1"])
    messages = load_data(path)

    s = pilih("Pilih distribusi peluang:", {k: v[1] for k, v in DISTRIBUSI.items()})
    dist = DISTRIBUSI.get(s, DISTRIBUSI["2"])[0]

    u = pilih("Pilih pengujian:", UJI)

    # siapin DTE + Honey Encryption sesuai pilihan
    bobot = buat_bobot(len(messages), dist)
    target = dict(zip(messages, normalisasi(bobot)))
    he = HoneyEncryption(DTE(messages, bobot))

    print("\n" + "=" * 50)
    print(f"Dataset    : {nama_data} ({len(messages)} pesan)")
    print(f"Distribusi : {dist}")
    print("=" * 50)

    if u == "1":
        pengujian.uji_plausibilitas(he, messages, target)
    elif u == "2":
        pengujian.uji_overhead(he, messages)
    elif u == "3":
        pengujian.uji_bruteforce(he, messages)
    elif u == "4":
        pengujian.uji_statistik(he, messages, target)
    elif u == "5":
        pengujian.analisis_sensitivitas(messages)
    else:
        pengujian.uji_plausibilitas(he, messages, target)
        pengujian.uji_overhead(he, messages)
        pengujian.uji_bruteforce(he, messages)
        pengujian.uji_statistik(he, messages, target)
        pengujian.analisis_sensitivitas(messages)

    print("\nselesai.")


if __name__ == "__main__":
    main()