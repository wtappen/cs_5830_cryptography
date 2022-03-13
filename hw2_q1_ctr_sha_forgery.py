import requests
import requests_cache
import time

import config as cfg
import hashlib

BLOCK_BYTES = 16


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), f"xor given bytes of unequal length. {len(a)=} {len(b)=}"
    return bytes(a ^ b for a, b in zip(a, b))


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def sha256(data: bytes) -> bytes:
    m = hashlib.sha256()
    m.update(data)
    return m.digest()


def genCookie_oracle() -> bytes:
    res = requests.get(cfg.Q1_GENCOOKIE_URL, auth=(cfg.usr, cfg.key))
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def isCookieAdFree_oracle(ct: bytes) -> bool:
    res = requests.get(
        cfg.Q1_ADFREE_URL, auth=(cfg.usr, cfg.key), params={"ct": ct.hex()}
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


def gen_cookie_ad_free() -> bytes:

    c = genCookie_oracle()
    iv = c[:BLOCK_BYTES]
    estimated_time = int(time.time()) + 60 * 60

    for t in range(estimated_time - 60, estimated_time + 61):
        no_hash_plaintext = "username=wmt45&validtill=" + str(t) + "&adfree=0"
        plaintext = (
            no_hash_plaintext
            + "&sha256="
            + sha256(no_hash_plaintext.encode("utf-8")).hex()
        )
        pad = xor(plaintext.encode(), c[BLOCK_BYTES:])

        new_no_hash_plaintext = "username=wmt45&validtill=" + str(t) + "&adfree=1"
        new_plaintext = (
            new_no_hash_plaintext
            + "&sha256="
            + sha256(new_no_hash_plaintext.encode("utf-8")).hex()
        )
        new_cookie = iv + xor(new_plaintext.encode("utf-8"), pad)

        if isCookieAdFree_oracle(new_cookie):
            return new_cookie

    return bytes(1)


if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    cookie_ad_free = gen_cookie_ad_free()
    print("Forged AdFree cookie ciphertext:", cookie_ad_free.hex())
