# Example only: scanned by the tests, never run.  CG-DEP-009 (vulnerable)
from Crypto.Cipher import AES


def encrypt(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(data)
