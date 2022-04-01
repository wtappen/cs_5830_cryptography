import requests
import requests_cache

import config as cfg
import pymd5

BLOCK_BYTES = 64
MD5_BYTES = 16


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def genCookie_oracle() -> bytes:
    res = requests.get(cfg.Q2_GENCOOKIE_URL, auth=(cfg.usr, cfg.key))
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def isCookieAdFree_oracle(cookie: bytes) -> bool:
    res = requests.get(
        cfg.Q2_ADFREE_URL, auth=(cfg.usr, cfg.key), params={"cookie": cookie.hex()}
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


def padding(msg_len_in_bytes: int) -> bytes:
    return pymd5.padding(msg_len_in_bytes * 8)


def md5_compress(state: bytes, block: bytes) -> bytes:
    assert len(block) == BLOCK_BYTES, f"block size not equal to 64 bytes"
    assert len(state) == MD5_BYTES, f"state size not equal to 16 bytes"
    decoded = pymd5._decode(state, MD5_BYTES)
    return pymd5._encode(
        pymd5.md5_compress(pymd5._decode(state, MD5_BYTES), block), MD5_BYTES
    )


def gen_cookie_ad_free() -> bytes:
    original_cookie = genCookie_oracle()
    original_hash = original_cookie[-MD5_BYTES:]
    original_cookie_no_hash = '&'.join(original_cookie.decode().split('&')[:-1]).encode()
    
    cookie_bit_len = len(original_cookie_no_hash) * 8

    # to_hash = '&adfree=1'.encode()
    # s = original_hash
    # for i in range(0, len(to_hash), BLOCK_BYTES):
    #     s = md5_compress(s, to_hash[i:i + BLOCK_BYTES])
    
    # forged_hash = s

    for secret_len in range(16, 65):
        padding0 = padding(len(original_cookie_no_hash) + secret_len)
        my_padding = padding(len(original_cookie_no_hash) + secret_len + len(padding0) + len('&adfree=1'.encode()))
        to_hash = '&adfree=1'.encode() + my_padding
        # print(len(original_cookie_no_hash) + secret_len + len(padding0) + len('&adfree=1'.encode()))
        print((len(original_cookie_no_hash) + secret_len + len(padding0) + len('&adfree=1'.encode())) * 8)
        print(my_padding.hex())
        s = original_hash
        for i in range(0, len(to_hash), BLOCK_BYTES):
            s = md5_compress(s, to_hash[i:i + BLOCK_BYTES])

        forged_cookie = original_cookie_no_hash + padding0 + '&adfree=1&md5='.encode() + s
        # print(original_cookie)
        # print(forged_cookie.hex())
        # break
        if isCookieAdFree_oracle(forged_cookie):
            print("hooray!!")
            break

    return forged_cookie



if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    ad_free_cookie = gen_cookie_ad_free()
    if isCookieAdFree_oracle(ad_free_cookie) == True:
        print("Successfully forged AdFree cookie!")
