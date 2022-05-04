import collections
from operator import mod
import requests
import requests_cache
import bitstring
from sympy import mod_inverse
from ecdsa import SigningKey, NIST256p
from hashlib import sha256

import config as cfg

ECDSASignature = collections.namedtuple("ECDSASignature", ["r", "s"])

MAX_BYTE_LENGTH = 256 // 8
CURVE = NIST256p
N = NIST256p.generator.order()
MESSAGE = ("Hello from " + cfg.usr).encode()


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def getSignature_oracle() -> (bytes, ECDSASignature):
    res = requests.get(cfg.Q1_GET_SIGNATURE, auth=(cfg.usr, cfg.key))
    try:
        res_dict = res.json()
        msg = bytes.fromhex(res_dict["Message"])
        r = int.from_bytes(bytes.fromhex(res_dict["R"]), "big")
        s = int.from_bytes(bytes.fromhex(res_dict["S"]), "big")
        return msg, ECDSASignature(r, s)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}\n\n{e}"
        )
        exit(-1)


def verifySignature_oracle(sig: ECDSASignature) -> bool:
    res = requests.get(
        cfg.Q1_VERIFY_SIGNATURE,
        auth=(cfg.usr, cfg.key),
        params={
            "R": sig.r.to_bytes(MAX_BYTE_LENGTH, "big").hex(),
            "S": sig.s.to_bytes(MAX_BYTE_LENGTH, "big").hex(),
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


def recover_secret_key() -> int:

    def H(msg):
        hashHex = sha256(msg).hexdigest()
        return int.from_bytes(bytes.fromhex(hashHex), "big")

    r1 = 0
    r2 = 1

    while r1 != r2:
        res1 = getSignature_oracle()
        res2 = getSignature_oracle()
        m1, sig1 = res1[0], res1[1]
        m2, sig2 = res2[0], res2[1]
        s1, r1 = sig1.s, sig1.r
        s2, r2 = sig2.s, sig2.r

    k = mod_inverse(s1 - s2, N) * (H(m1) - H(m2))
    return mod((s1 * k - (H(m1))) * mod_inverse(r1, N), N)


def forge_signature(msg) -> ECDSASignature:
    secret_key = recover_secret_key()
    sk = SigningKey.from_secret_exponent(secret_key, curve=CURVE, hashfunc=sha256)
    hashHex = sha256(msg).hexdigest()
    hashInt = int.from_bytes(bytes.fromhex(hashHex), "big")
    r, s = sk.sign_number(hashInt)
    return ECDSASignature(r, s)


if __name__ == "__main__":
    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    sig = forge_signature(MESSAGE)
    if verifySignature_oracle(sig) == True:
        print("Successfully forged a valid signature!")
    else:
        print("Failed to forge a valid signature!")
