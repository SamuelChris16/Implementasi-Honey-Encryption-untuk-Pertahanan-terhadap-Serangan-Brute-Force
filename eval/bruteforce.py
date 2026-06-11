import os

from src.dte import DTE
from src.honey import HoneyEncryption, derive_key, keystream


def _conventional_valid_count(password_list, correct_pw, message, valid_set):
    # baseline: AES biasa, cek validitas dari hasil dekripsi
    salt, nonce = os.urandom(16), os.urandom(16)
    key = derive_key(correct_pw, salt)
    data = message.encode()
    ct = bytes(a ^ b for a, b in zip(data, keystream(key, nonce, len(data))))

    valid = 0
    for pw in password_list:
        k = derive_key(pw, salt)
        out = bytes(a ^ b for a, b in zip(ct, keystream(k, nonce, len(ct))))
        try:
            text = out.decode()
        except UnicodeDecodeError:
            continue
        if text in valid_set:
            valid += 1
    return valid


def _honey_valid_count(he, password_list, correct_pw, message):
    blob = he.encrypt(correct_pw, message)
    # tiap tebakan selalu menghasilkan pesan dalam ruang -> semuanya "sah"
    return sum(1 for pw in password_list if he.decrypt(pw, blob) is not None)


def run(messages, n_keys=500):
    space = messages
    valid_set = set(space)
    correct = "kunci-benar-rahasia"
    guesses = [f"tebakan-{i}" for i in range(n_keys - 1)] + [correct]

    conv = _conventional_valid_count(guesses, correct, space[0], valid_set)
    he = HoneyEncryption(DTE(space))
    honey = _honey_valid_count(he, guesses, correct, space[0])
    return {"n_keys": n_keys, "conventional_valid": conv, "honey_valid": honey}
