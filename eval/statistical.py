import math

from src.dte import DTE
from src.honey import HoneyEncryption


def _bits_from_ciphertexts(messages, n=2000):
    he = HoneyEncryption(DTE(messages))
    raw = bytearray()
    for i in range(n):
        blob = he.encrypt("kata-sandi-uji", messages[i % len(messages)])
        raw += blob[32:]  # ambil bagian ciphertext saja
    bits = []
    for byte in raw:
        bits.extend((byte >> k) & 1 for k in range(7, -1, -1))
    return bits


def monobit(bits):
    s = sum(1 if b else -1 for b in bits)
    s_obs = abs(s) / math.sqrt(len(bits))
    return math.erfc(s_obs / math.sqrt(2))


def runs(bits):
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= (2 / math.sqrt(n)):
        return 0.0
    vn = 1 + sum(1 for i in range(1, n) if bits[i] != bits[i - 1])
    num = abs(vn - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    return math.erfc(num / den)


def cumulative_sums(bits):
    x = [1 if b else -1 for b in bits]
    s, z = 0, 0
    for v in x:
        s += v
        z = max(z, abs(s))
    n = len(bits)

    def phi(v):
        return 0.5 * (1 + math.erf(v / math.sqrt(2)))

    start = int((-n / z + 1) / 4)
    end = int((n / z - 1) / 4)
    t1 = sum(phi((4 * k + 1) * z / math.sqrt(n)) - phi((4 * k - 1) * z / math.sqrt(n))
             for k in range(start, end + 1))
    start2 = int((-n / z - 3) / 4)
    t2 = sum(phi((4 * k + 3) * z / math.sqrt(n)) - phi((4 * k + 1) * z / math.sqrt(n))
             for k in range(start2, end + 1))
    return max(0.0, 1 - t1 + t2)


def run(messages):
    bits = _bits_from_ciphertexts(messages)
    out = []
    for name, fn in (("Frekuensi (Monobit)", monobit),
                     ("Runtun (Runs)", runs),
                     ("Jumlah Kumulatif", cumulative_sums)):
        p = fn(bits)
        out.append((name, "Lulus" if p >= 0.01 else "Gagal", round(p, 4)))
    return out
