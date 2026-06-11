import bisect
import random
from collections import Counter

SEED_BITS = 32
SEED_MAX = 1 << SEED_BITS


class DTE:
    def __init__(self, messages):
        counts = Counter(messages)
        total = sum(counts.values())
        self.msgs = list(counts.keys())

        # bagi ruang seed [0, SEED_MAX) jadi rentang per pesan,
        # besarnya sebanding dgn peluang pesan itu
        self.bounds = []
        acc = 0.0
        for i, m in enumerate(self.msgs):
            acc += counts[m] / total
            hi = SEED_MAX if i == len(self.msgs) - 1 else int(round(acc * SEED_MAX))
            self.bounds.append(hi)
        self.lows = [0] + self.bounds[:-1]
        self.index = {m: i for i, m in enumerate(self.msgs)}

    def encode(self, msg):
        i = self.index[msg]
        lo, hi = self.lows[i], self.bounds[i]
        if hi <= lo:
            hi = lo + 1
        return random.randrange(lo, hi)

    def decode(self, seed):
        seed %= SEED_MAX
        i = bisect.bisect_right(self.bounds, seed)
        if i >= len(self.msgs):
            i = len(self.msgs) - 1
        return self.msgs[i]
