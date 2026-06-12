import random
import bisect

SEED_BITS = 32              # ukuran seed dalam bit
SEED_MAX = 1 << SEED_BITS   # seed ada di rentang [0, 2^32)


class DTE:
    def __init__(self, messages, weights):
        # messages: daftar pesan
        # weights : bobot peluang tiap pesan (gak harus jumlahnya 1)
        self.messages = list(messages)
        self.index = {m: i for i, m in enumerate(self.messages)}

        total = sum(weights)

        # Bangun batas kumulatif di dalam ruang seed [0, 2^32).
        # Tiap pesan kebagian satu potongan rentang, lebarnya sesuai bobot.
        self.bounds = [0]
        acc = 0
        for w in weights:
            acc += w
            self.bounds.append(int(acc / total * SEED_MAX))
        self.bounds[-1] = SEED_MAX   # paksa nutup penuh biar gak ada celah

    def encode(self, message):
        # pesan -> seed: ambil angka acak dari dalam rentang milik pesan itu
        i = self.index[message]
        lo, hi = self.bounds[i], self.bounds[i + 1]
        return random.randrange(lo, hi)

    def decode(self, seed):
        # seed -> pesan: cari rentang mana yang ngandung si seed
        seed &= SEED_MAX - 1                       # jaga-jaga biar tetap 32 bit
        i = bisect.bisect_right(self.bounds, seed) - 1
        return self.messages[i]
