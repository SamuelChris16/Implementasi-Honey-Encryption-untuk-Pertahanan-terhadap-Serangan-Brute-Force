from collections import Counter


def _build_space(kind, base, n=200):
    space = base[:n]
    if kind == "seragam":
        return space
    skewed = [space[0]] * 80
    for m in space[1:]:
        skewed += [m] * max(1, 20 // max(1, len(space) - 1))
    return skewed


def _best_guess_prob(space):
    c = Counter(space)
    total = sum(c.values())
    return max(c.values()) / total


def run(messages):
    rows = []
    for kind in ("seragam", "timpang"):
        space = _build_space(kind, messages)
        rows.append((kind, round(_best_guess_prob(space), 5)))
    return rows
