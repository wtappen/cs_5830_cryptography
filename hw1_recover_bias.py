from itertools import count
import requests

import config as cfg


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), f"xor given bytes of unequal length. {len(a)=} {len(b)=}"
    return bytes(a ^ b for a, b in zip(a, b))


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def bias_encryption_oracle(pt: bytes) -> bytes:
    res = requests.get(cfg.BIAS_URL, auth=(cfg.usr, cfg.key), params={"pt": pt.hex()})
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def recover_flag() -> bytes:
    flag = bytes()
    flag_length = len(bytearray(bias_encryption_oracle(bytes(bytearray()))))

    counters = {}
    running_max = {"byte_index": -1, "count": 0}
    for _ in range(500):
        e_msg = bytearray(bias_encryption_oracle(bytes(bytearray(20))))
        for i, b in enumerate(e_msg):
            if not i in counters:
                counters[i] = {}
            if not b in counters[i]:
                counters[i][b] = 0
            counters[i][b] += 1
            if counters[i][b] > running_max["count"]:
                running_max["byte_index"] = i
                running_max["count"] = counters[i][b]
                running_max["value"] = b
    biased_index = running_max["byte_index"]
    biased_e_value = running_max["value"]

    biased_pad_value = xor(bytes([0]), bytes([biased_e_value]))

    msg = bytearray(biased_index)
    for _ in range(flag_length):
        e_vals = []
        for i in range(10):
            e_vals.append(bytearray(bias_encryption_oracle(bytes(msg)))[biased_index])
        most_common = max(e_vals, key=e_vals.count)
        flag += xor(biased_pad_value, bytes([most_common]))
        msg = msg[:-1]

    return flag


if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    flag = recover_flag()
    print(flag.decode())
