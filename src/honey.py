import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PBKDF2_ITER = 100_000
KEY_LEN = 16  # AES-128


def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN,
                     salt=salt, iterations=PBKDF2_ITER)
    return kdf.derive(password.encode())


def keystream(key, nonce, nbytes):
    c = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return c.update(b"\x00" * nbytes) + c.finalize()


class HoneyEncryption:
    def __init__(self, dte):
        self.dte = dte

    def encrypt(self, password, message):
        salt, nonce = os.urandom(16), os.urandom(16)
        key = derive_key(password, salt)
        seed = struct.pack(">I", self.dte.encode(message))
        ks = keystream(key, nonce, 4)
        ct = bytes(a ^ b for a, b in zip(seed, ks))
        return salt + nonce + ct

    def decrypt(self, password, blob):
        salt, nonce, ct = blob[:16], blob[16:32], blob[32:]
        key = derive_key(password, salt)
        ks = keystream(key, nonce, 4)
        seed = struct.unpack(">I", bytes(a ^ b for a, b in zip(ct, ks)))[0]
        return self.dte.decode(seed)
