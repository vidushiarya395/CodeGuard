# Example only: scanned by the tests, never run.  CG-DEP-009 (safe)
from Crypto.Cipher import AES


def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag
