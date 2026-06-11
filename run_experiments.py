import csv
import os

from src.messagespace import load
from src.dte import DTE
from eval import plausibility, performance, bruteforce, statistical, sensitivity

RESULTS = "results"


def save_csv(name, header, rows):
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, name), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def main():
    spaces = {
        "Kata sandi umum": load("data/passwords.txt"),
        "Nomor kartu pembayaran": load("data/cards.txt"),
        "Nomor identitas": load("data/ids.txt"),
    }

    print("\n== Eksperimen 1: Plausibilitas ==")
    rows = []
    for label, msgs in spaces.items():
        kl, n = plausibility.run(DTE(msgs), msgs)
        rows.append((label, n, round(kl, 5)))
        print(f"  {label:24s} KL={kl:.5f} (n={n})")
    save_csv("plausibility.csv", ["ruang_pesan", "sampel", "kl_divergence"], rows)

    print("\n== Eksperimen 2: Overhead kinerja ==")
    perf = performance.run(load("data/passwords.txt"))
    for n, tp, th, ov in perf:
        print(f"  ukuran={n:6d}  AES={tp}ms  HE={th}ms  overhead={ov}%")
    save_csv("performance.csv", ["ukuran", "aes_ms", "he_ms", "overhead_persen"], perf)

    print("\n== Eksperimen 3: Ketahanan brute-force ==")
    bf = bruteforce.run(load("data/passwords.txt"))
    print(f"  konvensional: {bf['conventional_valid']} kandidat sah dari {bf['n_keys']} kunci")
    print(f"  honey       : {bf['honey_valid']} kandidat sah dari {bf['n_keys']} kunci")
    save_csv("bruteforce.csv", ["skema", "kunci_dicoba", "kandidat_sah"],
             [("konvensional", bf["n_keys"], bf["conventional_valid"]),
              ("honey_encryption", bf["n_keys"], bf["honey_valid"])])

    print("\n== Eksperimen 4: Uji statistik NIST ==")
    stat = statistical.run(load("data/passwords.txt"))
    for name, verdict, p in stat:
        print(f"  {name:22s} {verdict:6s} p={p}")
    save_csv("statistical.csv", ["uji", "hasil", "p_value"], stat)

    print("\n== Eksperimen 5: Sensitivitas distribusi terhadap keamanan ==")
    sens = sensitivity.run(load("data/passwords.txt"))
    for kind, prob in sens:
        print(f"  distribusi {kind:8s} peluang tebakan terbaik={prob}")
    save_csv("sensitivity.csv", ["distribusi", "peluang_tebakan_terbaik"], sens)

    print(f"\nSemua hasil tersimpan di folder {RESULTS}/")


if __name__ == "__main__":
    main()
