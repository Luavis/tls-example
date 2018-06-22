import hmac
import hashlib


def p_hash(secret, seed, length=1, hash=hashlib.sha256):
    def a_func(n):
        if n == 0:
            return seed
        return hmac.new(secret, a_func(n - 1), hash).digest()
    p = b''
    count = int(length / hash().digest_size) + 1
    while count > 0:
        p = hmac.new(secret, a_func(count) + seed, hash).digest() + p
        count -= 1
    return p[:length]


def prf(secret, label, seed, hash=hashlib.sha256, verify_data_length=12):
    return p_hash(secret, label + seed, verify_data_length, hash)


def prf_key_block(secret, label, seed, mac_len, key_len, iv_len):
    b = prf(
        secret,
        label,
        seed,
        verify_data_length=(mac_len + key_len + iv_len) * 2,
    )
    cur = 0
    ret = []
    ret.append(b[cur:cur + mac_len])
    cur += mac_len
    ret.append(b[cur:cur + mac_len])
    cur += mac_len
    ret.append(b[cur:cur + key_len])
    cur += key_len
    ret.append(b[cur:cur + key_len])
    cur += key_len
    ret.append(b[cur:cur + iv_len])
    cur += iv_len
    ret.append(b[cur:cur + iv_len])
    cur += iv_len

    return ret
