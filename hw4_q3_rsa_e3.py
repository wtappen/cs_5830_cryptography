from hashlib import sha256
import requests
import time
import os

import config as cfg

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from sympy import root

MAX_BYTE_LENGTH = 2048 // 8
Sha256AlgorithmId = (
    b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
)


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def getPkAndMsg_oracle() -> (int, bytes):
    res = requests.get(cfg.Q3_GETMSG_URL, auth=(cfg.usr, cfg.key))
    try:
        res_dict = res.json()
        N = int.from_bytes(bytes.fromhex(res_dict["N"]), "big")
        msg = bytes.fromhex(res_dict["Message"])
        return N, msg
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}\n\n{e}"
        )
        exit(-1)


def verifyRSA_oracle(sig: int) -> bool:
    res = requests.get(
        cfg.Q3_VERIFYRSA_URL,
        auth=(cfg.usr, cfg.key),
        params={
            "Signature": sig.to_bytes(MAX_BYTE_LENGTH, "big").hex(),
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


def forge_signature() -> int:
    N, msg = getPkAndMsg_oracle()

    TARGET_BYTE_LENGTH = 256

    prefix = bytes.fromhex('0001ff00')
    hash = sha256(msg).hexdigest()

    b = prefix + Sha256AlgorithmId + bytes.fromhex(hash)
    b = b + bytes.fromhex('ff') * (TARGET_BYTE_LENGTH - len(b))
    i = int.from_bytes(b, "big")

    return int(root(i, 3))

if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    sig = forge_signature()
    if verifyRSA_oracle(sig) == True:
        print("Successfully forged a valid signature!")
    else:
        print("Failed to forge a valid signature!")
