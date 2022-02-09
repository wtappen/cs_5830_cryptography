import requests
import requests_cache
from datetime import timedelta

import config as cfg

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


def ecb_encryption_oracle(pt: bytes) -> bytes:
    # Cache requests locally so that we don't have to hit the server for the same request multiple times.
    session = requests_cache.CachedSession(
        "ecb_oracle_cache", backend="sqlite", expire_after=timedelta(hours=2)
    )
    res = session.get(cfg.ECB_URL, auth=(cfg.usr, cfg.key), params={"pt": pt.hex()})
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def recover_flag() -> bytes:
    flag = bytes()

    msg = bytes()
    original_len = len(bytearray(ecb_encryption_oracle(msg)))
    i = 0
    while True:
        i += 1
        msg += bytes(1)
        if len(bytearray(ecb_encryption_oracle(msg))) > original_len:
            flag_len = BLOCK_BYTES - i
            break

    # TODO: implement optimization to try all 256 combinations in one query
    msg = bytes(BLOCK_BYTES - flag_len % BLOCK_BYTES)
    for i in range(1, flag_len):
        msg += bytes(1)
        e_last_block = ecb_encryption_oracle(msg)[BLOCK_BYTES:]
        for x in range(256):
            test_msg = bytes([x]) + flag + bytes([BLOCK_BYTES - i] * (BLOCK_BYTES - i))
            e_try = ecb_encryption_oracle(test_msg)
            if e_try[-2 * BLOCK_BYTES : -BLOCK_BYTES] == e_last_block:
                flag = bytes([x]) + flag
                print("current flag is: " + flag.decode())
                continue

    return flag


if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    flag = recover_flag()
    print(flag.decode())
