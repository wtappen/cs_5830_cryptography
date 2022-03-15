import requests
import secrets
import copy
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


def encrypt_oracle() -> bytes:
    res = requests.get(cfg.Q3_ENCRYPT_URL, auth=(cfg.usr, cfg.key))
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def check_padding_oracle(ct: bytes) -> bool:
    res = requests.get(
        cfg.Q3_PADDING_URL, auth=(cfg.usr, cfg.key), params={"ct": ct.hex()}
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


def int_to_byte(i):
    return i.to_bytes(1, "big")


def byte_to_int(b):
    return int.from_bytes(b, "big")


def recover_flag() -> bytes:
    flag = bytes()

    c = encrypt_oracle()
    c_blocks = [c[i : i + BLOCK_BYTES] for i in range(0, len(c), BLOCK_BYTES)]
    c0 = c_blocks[0]
    c1 = c_blocks[1]

    r = bytearray(BLOCK_BYTES)
    x = 0

    # for i from 8th index to 0th index:
    # set bytes from i + 1 to the end of the block with value that will make the plaintext look like all the right padding

    # for all 256 values:
    # check if r + c1 is legit
    # if so:
    # record what the plaintext value is
    # break out of loop

    known = bytearray(BLOCK_BYTES)
    for i in range(7, 0, -1):
        known[-i] = 7
    print(known)

    for j in range(8, -1, -1):
        pad_num = BLOCK_BYTES - j
        print(pad_num)
        for k in range(j + 1, BLOCK_BYTES):
            r[k] = byte_to_int(
                xor(
                    xor(int_to_byte(c0[k]), int_to_byte(known[k])), int_to_byte(pad_num)
                )
            )
        print(r.hex())
        for i in range(256):
            r[j] = i
            # print(r.hex())
            if check_padding_oracle(bytes(r) + c1):
                print(i)
                b = xor(
                    xor(i.to_bytes(1, "big"), (c0[j]).to_bytes(1, "big")),
                    pad_num.to_bytes(1, "big"),
                )
                print(b.hex())
                known[j] = byte_to_int(b)
                break
    flag = bytes(known[:9])

    return flag


# multiple = False
# for n in range(BLOCK_BYTES, 1, -1):
#     r_check = r[:]
#     r_check[BLOCK_BYTES - n] = 1
#     if not check_padding_oracle(bytes(r) + c1):
#         plaintext =


if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    flag = recover_flag()
    print(flag.decode())
