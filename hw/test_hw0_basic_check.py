"""
test_hw0_basic_check.py
"""

from hw0_basic_check import chacha_encrypt


def test_chacha_encrypt():
    plaintext = b"stream ciphers are cool"
    key = bytes.fromhex(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    nonce = bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    expected_result = "75ec0f4ed01f78769e79b0c4ae3dfbbce0eedfec1e3342"

    result = chacha_encrypt(plaintext, key, nonce)
    assert result.hex() == expected_result
