"""
hw0_basic_check.py
"""

from Crypto.Cipher import ChaCha20


def chacha_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext
