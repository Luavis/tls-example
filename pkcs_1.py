from hashlib import sha256
from math import log
import random
import binascii


def byte_size(num):
    if num == 0:
        return 1
    return int(log(num, 256)) + 1


"""
4.  Data Conversion Primitives

   Two data conversion primitives are employed in the schemes defined in
   this document:

   o  I2OSP - Integer-to-Octet-String primitive

   o  OS2IP - Octet-String-to-Integer primitive
"""
def i2osp(x, x_len):
    if x >= 256 ** x_len:
        raise ValueError('integer too long')
    return x.to_bytes(x_len, 'big')

def os2ip(x):
    h = binascii.hexlify(x)
    return int(h, 16)

def encode_eme_pkcs_v15(k, message):
    ps_len = k - len(message) - 3
    # PS must not contain \x00
    ps = bytearray(random.sample(range(1, 256), ps_len))
    return b'\x00\x02' + ps + b'\x00' + message

def rsaep(n, e, m):
    if m < 0 or m > n - 1:
        raise ValueError('message representative out of range')
    return pow(m, e, n)

def rsadp(n, d, c):
    if c < 0 or c > n - 1:
        raise ValueError('ciphertext representative out of range')
    return pow(c, d, n)

# verification primitive
def rsavp(n, e, s):
    if s < 0 or s > n - 1:
        raise ValueError('signature representative out of range')
    return pow(s, e, n)


def rsaes_pkcs_1_v1_5_encrypt(modulus, exponent, message):
    k = byte_size(modulus)
    m_len = len(message)
    if m_len > k - 11:
        raise ValueError('message too long')
    em = encode_eme_pkcs_v15(k, message)
    m = os2ip(em)
    c = rsaep(modulus, exponent, m)
    return i2osp(c, k)

def rsaes_pkcs_1_v1_5_decrypt(modulus, exponent, ciphertext):
    k = byte_size(modulus)
    c = os2ip(ciphertext)
    m = rsadp(modulus, exponent, c)
    em = i2osp(m, k)
    return b''.join(em.split(b'\x00')[2:])  # decode eme_encrypt

# RSA Signature Scheme with Appendix
def rsassa_pkcs_1_v1_5_verify(
    modulus,
    exponent,
    signature,
    message,
    hash=sha256
):
    if hash is not sha256:
        raise NotImplementedError('only support sha256 hash in RSASSA')
    k = byte_size(modulus)
    s = os2ip(signature)
    m = rsavp(modulus, exponent, s)
    em = i2osp(m, k)

    # EMSA-PKCS1-v1_5-ENCODE
    # sha256WithRSAEncryption
    em_len = len(em)
    algorithm_id = b'\x86H\x86\xf7\r\x01\x01\x0b'
    h = hash(message).digest()
    # DigestInfo ::= SEQUENCE {
    #     digestAlgorithm AlgorithmIdentifier,
    #     digest OCTET STRING
    # }
    t = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01' + \
        b'\x65\x03\x04\x02\x01\x05\x00\x04\x20' + h
    em_ = b'\x00\x01' + (b'\xff' * (em_len - len(t) - 3)) + b'\x00' + t
    return em == em_
