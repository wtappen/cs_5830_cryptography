import collections
import requests
import requests_cache
import bitstring
from operator import mod

import config as cfg

from Crypto.Cipher import AES

AEADCiphertext = collections.namedtuple("AEADCiphertext", ["ciphertext", "tag"])

ALL_ZEROS_NONCE = bytes([0 for i in range(12)])
MAX_BYTE_LENGTH = 1024 // 8


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def getWireData_oracle() -> (int, int, AEADCiphertext, bytes):
    res = requests.get(cfg.Q2_GET_WIRE_DATA, auth=(cfg.usr, cfg.key))
    try:
        res_dict = res.json()
        N = int.from_bytes(bytes.fromhex(res_dict["N"]), "big")
        E = res_dict["E"]
        flagEncryption = bytes.fromhex(res_dict["FlagEncryption"])
        sessionKeyEncryption = bytes.fromhex(res_dict["SessionKeyEncryption"])
        flagEncryption = AEADCiphertext(flagEncryption[:-16], flagEncryption[-16:])
        return N, E, flagEncryption, sessionKeyEncryption
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}\n\n{e}"
        )
        exit(-1)


def checkConfirmation_oracle(
    flagEncryption: AEADCiphertext, sessionKeyEncryption: bytes
) -> bool:
    flagEncryption = flagEncryption.ciphertext + flagEncryption.tag
    res = requests.get(
        cfg.Q2_CHECK_CONFIRMATION,
        auth=(cfg.usr, cfg.key),
        params={
            "FlagEncryption": flagEncryption.hex(),
            "SessionKeyEncryption": sessionKeyEncryption.hex(),
        },
    )
    if res.text == "true":
        return True
    elif res.text == "false":
        return False
    else:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)

def check_encrypt_fake_stuff(sessionKeyGuessInt, sessionKeyEncryptionGuessInt):
    sessionKeyGuess = sessionKeyGuessInt.to_bytes(16, "big")
    sessionKeyEncryptionGuess = sessionKeyEncryptionGuessInt.to_bytes(MAX_BYTE_LENGTH, "big")

    cipher = AES.new(sessionKeyGuess, mode=AES.MODE_GCM, nonce=ALL_ZEROS_NONCE)
    cipher.update(sessionKeyEncryptionGuess)
    fakeCiphertext, fakeTag = cipher.encrypt_and_digest(b"RSA{ffff}")
    fakeFlagEncryption = AEADCiphertext(fakeCiphertext, fakeTag)
    return checkConfirmation_oracle(fakeFlagEncryption, sessionKeyEncryptionGuess)

def recover_flag() -> bytes:
    N, E, flagEncryption, sessionKeyEncryption = getWireData_oracle()
    res = checkConfirmation_oracle(flagEncryption, sessionKeyEncryption)
    assert res == True

    # This snippet shows how to convert between bytes & int
    sessionKeyEncryptionInt = int.from_bytes(sessionKeyEncryption, "big")
    sessionKeyEncryptionBytes = sessionKeyEncryptionInt.to_bytes(MAX_BYTE_LENGTH, "big")
    assert sessionKeyEncryption == sessionKeyEncryptionBytes

    # TODO: fill in your answer here to recover the session key
    Ck = int.from_bytes(sessionKeyEncryption, "big")

    k_so_far = []

    for b in range(127, -1, -1):
        kb = 0
        for i, b in enumerate(k_so_far):
            kb = kb | b << 127 - i
        print(bitstring.Bits(kb.to_bytes(16, "big")))
        Cb = mod(Ck * (mod(2 ** (b  * E), N)), N)
        if check_encrypt_fake_stuff(kb, Cb):
            k_so_far.append(0)
        else:
            k_so_far.append(1)
        print(k_so_far)
    

    ba = bitstring.BitArray(k_so_far)
    sessionKeyGuess = ba.tobytes()
    print(ba)
    print(sessionKeyGuess)

    # X. Once we recovered the session key, we can use it to decrypt the given
    #    ciphertext to reveal the flag.
    cipher = AES.new(sessionKeyGuess, mode=AES.MODE_GCM, nonce=ALL_ZEROS_NONCE)
    cipher.update(sessionKeyEncryptionBytes)
    msg = cipher.decrypt_and_verify(flagEncryption.ciphertext, flagEncryption.tag)
    return msg


if __name__ == "__main__":
    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)
    recoveredFlag = recover_flag()
    print(f"recovered flag:\n{recoveredFlag.decode()}")
