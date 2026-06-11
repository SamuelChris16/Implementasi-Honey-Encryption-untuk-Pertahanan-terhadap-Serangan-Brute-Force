import os
import time

from src.dte import DTE
from src.honey import HoneyEncryption, derive_key, keystream


def _plain_aes_roundtrip(password, message):
    salt, nonce = os.urandom(16), os.urandom(16)
    data = message.encode()
    # enkripsi (turunkan kunci dari password)
    key = derive_key(password, salt)
    ct = bytes(a ^ b for a, b in zip(data, keystream(key, nonce, len(data))))
    # dekripsi (turunkan kunci lagi, seperti operasi terpisah)
    key2 = derive_key(password, salt)
    _ = bytes(a ^ b for a, b in zip(ct, keystream(key2, nonce, len(ct)))).decode(errors="ignore")


def _he_roundtrip(he, password, message):
    blob = he.encrypt(password, message)
    _ = he.decrypt(password, blob)


def _bench(fn, reps):
    t0 = time.perf_counter()
    for _ in range(reps):
        fn()
    return (time.perf_counter() - t0) * 1000 / reps


def run(messages, sizes=(100, 1000, 10000), reps=200):
    rows = []
    pw, msg = "kata-sandi-uji", messages[0]
    for n in sizes:
        space = messages[:n] if len(messages) >= n else messages
        he = HoneyEncryption(DTE(space))
        t_plain = _bench(lambda: _plain_aes_roundtrip(pw, msg), reps)
        t_he = _bench(lambda: _he_roundtrip(he, pw, msg), reps)
        overhead = (t_he - t_plain) / t_plain * 100 if t_plain else 0.0
        rows.append((n, round(t_plain, 3), round(t_he, 3), round(overhead, 1)))
    return rows
