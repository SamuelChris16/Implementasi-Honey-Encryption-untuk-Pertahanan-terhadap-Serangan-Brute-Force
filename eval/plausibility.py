import math
import random
from collections import Counter

from src.dte import SEED_MAX


def kl_divergence(p, q):
    total = 0.0
    for m, pv in p.items():
        if pv > 0:
            total += pv * math.log(pv / q.get(m, 1e-12))
    return total


def target_dist(messages):
    c = Counter(messages)
    n = sum(c.values())
    return {m: v / n for m, v in c.items()}


def honey_dist(dte, n_samples):
    c = Counter(dte.decode(random.randrange(SEED_MAX)) for _ in range(n_samples))
    n = sum(c.values())
    return {m: v / n for m, v in c.items()}


def run(dte, messages, n_samples=200000):
    p = honey_dist(dte, n_samples)   # distribusi pesan umpan
    q = target_dist(messages)        # distribusi asli
    return kl_divergence(p, q), n_samples
