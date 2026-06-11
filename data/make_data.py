import os
import random

random.seed(42)
HERE = os.path.dirname(__file__)


def write(name, items):
    with open(os.path.join(HERE, name), "w", encoding="utf-8") as f:
        f.write("\n".join(items))


def passwords(n=10000):
    base = ["password", "123456", "qwerty", "admin", "letmein", "welcome",
            "monkey", "dragon", "iloveyou", "sunshine"]
    return [random.choice(base) + str(random.randint(0, 9999)) for _ in range(n)]


def cards(n=10000):
    return [f"4{random.randint(0, 999):03d}{random.randint(0, 999999999999):012d}"[:16]
            for _ in range(n)]


def ids(n=10000):
    return [f"EMP{random.randint(0, 999999):06d}" for _ in range(n)]


if __name__ == "__main__":
    write("passwords.txt", passwords())
    write("cards.txt", cards())
    write("ids.txt", ids())
    print("data dibuat di", HERE)
