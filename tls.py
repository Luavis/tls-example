import socket
import time
import io
import secrets
import hmac
import hashlib
from struct import pack, unpack
from x509 import X509, parse_der
from pkcs_1 import rsaes_pkcs_1_v1_5_encrypt
from prf import prf, prf_key_block
from Crypto.Cipher import AES
from ca import ca_cert


CHANGE_CIPHER_SPEC_TYPE = 20
ALERT_TYPE = 21
HANDSHAKE_TYPE = 22
APPLICATION_TYPE = 23

# Handshake protocol
HANDSHAKE_HELLO_REQUEST = 0
HANDSHAKE_CLIENT_HELLO = 1
HANDSHAKE_SERVER_HELLO = 2
HANDSHAKE_CERTIFICATE = 11
HANDSHAKE_SERVER_KEY_EXCHANGE = 12
HANDSHAKE_CERTIFICATE_REQUEST = 13
HANDSHAKE_SERVER_HELLO_DONE = 14
HANDSHAKE_CERTIFICATE_VERIFY = 15
HANDSHAKE_CLIENT_KEY_EXCHANGE = 16
HANDSHAKE_FINISHED = 20

CIPHER_SUITE_TLS_NULL_WITH_NULL_NULL = b'\x00\x00'
CIPHER_SUITE_TLS_RSA_WITH_NULL_MD5 = b'\x00\x01'
CIPHER_SUITE_TLS_RSA_WITH_NULL_SHA = b'\x00\x02'
CIPHER_SUITE_TLS_RSA_WITH_NULL_SHA256 = b'\x00\x3B'
CIPHER_SUITE_TLS_RSA_WITH_RC4_128_MD5 = b'\x00\x04'
CIPHER_SUITE_TLS_RSA_WITH_RC4_128_SHA = b'\x00\x05'
CIPHER_SUITE_TLS_RSA_WITH_3DES_EDE_CBC_SHA = b'\x00\x0A'
CIPHER_SUITE_TLS_RSA_WITH_AES_128_CBC_SHA = b'\x00\x2F'
CIPHER_SUITE_TLS_RSA_WITH_AES_256_CBC_SHA = b'\x00\x35'
CIPHER_SUITE_TLS_RSA_WITH_AES_128_CBC_SHA256 = b'\x00\x3C'
CIPHER_SUITE_TLS_RSA_WITH_AES_256_CBC_SHA256 = b'\x00\x3D'


def uint24_to_int(b_len):
    return (b_len[0] << 16) + (b_len[1] << 8) + b_len[2]


def plain_text(content_type, body):
    t = pack('>B', content_type)  # handshake
    ver = pack('>BB', 3, 3)  # version
    return t + ver + pack('>H', len(body)) + body


IV = secrets.token_bytes(AES.block_size)
SEQ = 0
CLIENT_MAC = None
CLIENT_AES = None
SERVER_MAC = None
SERVER_AES = None


def cipher_text(content_type, body):
    global SEQ, CLIENT_MAC, CLIENT_AES
    mac_fn = CLIENT_MAC.copy()
    t = pack('>B', content_type)  # handshake
    ver = pack('>BB', 3, 3)  # version
    mac_fn.update(SEQ.to_bytes(8, 'big'))
    mac_fn.update(t)
    mac_fn.update(ver)
    mac_fn.update(pack('>H', len(body)))
    mac_fn.update(body)
    mac = mac_fn.digest()

    SEQ += 1  # update seq
    body = body + mac
    pad_len = AES.block_size - 1 - (len(body) % AES.block_size)
    body = IV + body
    body += (pad_len.to_bytes(1, 'big') * (pad_len + 1))
    fragment = CLIENT_AES.encrypt(body)

    return t + ver + pack('>H', len(fragment)) + fragment


def decode_cipher_content(fragment):
    d_fragment = SERVER_AES.decrypt(fragment)
    d_fragment = d_fragment[AES.block_size:]  # remove IV
    pad_len = d_fragment[-1]
    MAC_SIZE = hashlib.sha1().digest_size
    without_pad = d_fragment[:-(pad_len+1)]
    content = without_pad[:-MAC_SIZE]
    mac = without_pad[-MAC_SIZE:]
    # TODO: verify MAC

    return content


def decode_plain_text(body):
    t, ver1, ver2, length = unpack('>BBBH', body[:5])
    return t, (ver1, ver2), length


def vector_to_bytes(data, len_size=1, e_size=1):
    ret = (len(data) * e_size).to_bytes(len_size, 'big')
    if isinstance(data, list):
        ret += b''.join(data)
    else:
        ret += data
    return ret


"""
Handshake flow
      Client                                               Server

      ClientHello                  -------->
                                                      ServerHello
                                                     Certificate*
                                               ServerKeyExchange*
                                              CertificateRequest*
                                   <--------      ServerHelloDone
      Certificate*
      ClientKeyExchange
      CertificateVerify*
      [ChangeCipherSpec]
      Finished                     -------->
                                               [ChangeCipherSpec]
                                   <--------             Finished
      Application Data             <------->     Application Data

             Figure 1.  Message flow for a full handshake

   * Indicates optional or situation-dependent messages that are not
   always sent.
"""

def handshake(s, host, ciphers):
    def handshake_body(msg_type, body):
        l = len(body)
        b_len = l.to_bytes(3, 'big')
        return plain_text(HANDSHAKE_TYPE, pack('>B', msg_type) + b_len + body)

    def handshake_cipher_body(msg_type, body):
        l = len(body)
        b_len = l.to_bytes(3, 'big')
        return cipher_text(HANDSHAKE_TYPE, pack('>B', msg_type) + b_len + body)

    def decode_handshake_header(sock):
        t, ver, length = decode_plain_text(sock.recv(5))
        if t is not HANDSHAKE_TYPE:
            raise ValueError('body is not handshake type')
        body = sock.recv(length)
        msg_type, b_len = unpack('>B3s', body[:4])
        return msg_type, uint24_to_int(b_len), body[4:], body

    def client_hello(s):
        gmt_unix_time = int(time.time())
        client_version = pack('>BB', 3, 3)
        random = pack(
            '>I28s',
            gmt_unix_time,
            secrets.token_bytes(28),
        )
        compression_methods = [b'\x00']  # NULL
        body = \
            client_version + \
            random +  \
            b'\x00' + \
            vector_to_bytes(ciphers, 2, 2) + \
            vector_to_bytes(compression_methods)  # without session
        server_name = b'\x00'  # host name type
        server_name += vector_to_bytes(host.encode('utf-8'), 2, 1)
        server_name_list = vector_to_bytes(server_name, 2, 1)
        extension_data = vector_to_bytes(server_name_list, 2, 1)
        extension_type = b'\x00\x00'  # server_name
        extension = extension_type + extension_data
        extensions = vector_to_bytes(extension, 2, 1)
        body += extensions
        payload = handshake_body(HANDSHAKE_CLIENT_HELLO, body)
        s.send(payload)
        return random, payload[5:]

    def server_hello(msg_type, body):
        cur = 35
        ver1, ver2, random, sess_len = unpack('>BB32sB', body[:cur])
        print('server version: ', ver1, ver2)
        sess_id, = unpack(str(sess_len) + 's', body[cur:cur + sess_len])
        cur += sess_len
        print('session id: ', sess_id)
        cipher, compress = unpack('>2sB', body[cur:cur+3])
        cur += 3
        print('cipher: 0x{}'.format(cipher.hex()))
        print('compress method: ', compress)
        return random

    def certificate(msg_type, body):
        cert_list_len = uint24_to_int(unpack('>3s', body[:3])[0])
        cur = 3
        certs = []
        while cur <= cert_list_len:
            cert_len = uint24_to_int(unpack('>3s', body[cur:cur+3])[0])
            cur += 3
            certs.append(body[cur:cur+cert_len])
            cur += cert_len
        return certs

    def server_key_exchange(msg_type, body):
        raise NotImplementedError('server key exchange is not implemented')

    def server_hello_done(msg_type, body):
        if len(body) is not 0:
            raise ValueError('server done must be empty body')

    def client_key_exchange(s, certificate):
        """
        In public key encryption, a public key algorithm is used to encrypt
        data in such a way that it can be decrypted only with the matching
        private key.  A public-key-encrypted element is encoded as an opaque
        vector <0..2^16-1>, where the length is specified by the encryption
        algorithm and key.

        RSA encryption is done using the RSAES-PKCS1-v1_5 encryption scheme
        defined in [PKCS1].
        """
        client_version = pack('>BB', 3, 3)
        random = secrets.token_bytes(46)
        pre_master_secret = client_version + random
        modulus = certificate.pubkey['modulus']
        exponent = certificate.pubkey['exponent']
        e_pre_master_secret = rsaes_pkcs_1_v1_5_encrypt(
            modulus, exponent, pre_master_secret
        )
        payload = handshake_body(
            HANDSHAKE_CLIENT_KEY_EXCHANGE,
            vector_to_bytes(e_pre_master_secret, len_size=2, e_size=1)
        )
        s.send(payload)
        return pre_master_secret, payload[5:]


    def change_cipher_spec(s):
        s.send(plain_text(CHANGE_CIPHER_SPEC_TYPE, b'\x01'))

    def client_finished(s, master_secret, handshake_hash):
        verify_data = prf(
            master_secret,
            b'client finished',
            handshake_hash,
            verify_data_length=12,
        )
        s.send(handshake_cipher_body(HANDSHAKE_FINISHED, verify_data))
        l = len(verify_data)
        b_len = l.to_bytes(3, 'big')
        return pack('>B', HANDSHAKE_FINISHED) + b_len + verify_data

    certificates = []
    server_random = None
    handshake_hash = hashlib.sha256()
    client_random, client_hello_msg = client_hello(s)
    handshake_hash.update(client_hello_msg)
    while True:
        msg_type, length, body, payload = decode_handshake_header(s)

        handshake_hash.update(payload)
        if msg_type is HANDSHAKE_SERVER_HELLO:
            server_random = server_hello(msg_type, body)
        elif msg_type is HANDSHAKE_CERTIFICATE:
            certs = certificate(msg_type, body)
            for c in certs:
                buf = io.BytesIO(c)
                c = X509(parse_der(buf))
                certificates.append(c)
        elif msg_type is HANDSHAKE_SERVER_KEY_EXCHANGE:
            server_key_exchange(msg_type, body)
        elif msg_type is HANDSHAKE_SERVER_HELLO_DONE:
            server_hello_done(msg_type, body)
            break
        else:
            raise NotImplementedError()

    for i in range(len(certificates) - 1):
        if not certificates[i].is_valid_signature(certificates[i + 1]):
            raise ValueError('invalid certificate')

    if not certificates[-1].is_valid_signature(ca_cert[0]):  # first CA is DST...
        raise ValueError('invalid certificate')

    pre_master_secret, msg = client_key_exchange(s, certificates[0])
    handshake_hash.update(msg)
    master_secret = prf(
        pre_master_secret,
        b'master secret',
        client_random + server_random,
        verify_data_length=48,
    )

    (
        client_write_mac_key,
        server_write_mac_key,
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    ) = prf_key_block(
        master_secret,
        b'key expansion',
        server_random + client_random,
        mac_len=hashlib.sha1().digest_size,
        key_len=AES.block_size,
        iv_len=len(IV),
    )
    global CLIENT_MAC, SERVER_MAC, CLIENT_AES, SERVER_AES
    change_cipher_spec(s)
    CLIENT_MAC = hmac.new(client_write_mac_key, None, hashlib.sha1)
    SERVER_MAC = hmac.new(server_write_mac_key, None, hashlib.sha1)
    CLIENT_AES = AES.new(client_write_key, AES.MODE_CBC, client_write_iv)
    SERVER_AES = AES.new(server_write_key, AES.MODE_CBC, server_write_iv)
    payload = client_finished(s, master_secret, handshake_hash.copy().digest())
    handshake_hash.update(payload)
    # get Change cipher spec
    t, ver, length = decode_plain_text(s.recv(5))
    flag = s.recv(length)
    if t is not CHANGE_CIPHER_SPEC_TYPE or flag != b'\x01':
        raise AssertionError(
            'server have to change cipher spec after client finished'
        )
    while True:
        t, ver, length = decode_plain_text(s.recv(5))
        if t == HANDSHAKE_TYPE:
            content = decode_cipher_content(s.recv(length))
            verify_data = content[4:]
            calc_verify_data = prf(
                master_secret,
                b'server finished',
                handshake_hash.digest(),
                verify_data_length=12,
            )
            if not calc_verify_data == verify_data:
                raise AssertionError('verify data is not matched!')
            break
        else:
            AssertionError('server must response HANDSHAKE_TYPE')

s = socket.socket()
host = 'example.com'
port = 443
s.connect((host, port))
handshake(s, host, [CIPHER_SUITE_TLS_RSA_WITH_AES_128_CBC_SHA])

print('-----------------------\n')

s.send(cipher_text(
    APPLICATION_TYPE,
    b'GET / HTTP/1.1\r\n' +
    b'Host: example.com\r\n\r\n',
))


def read_content(s):
    t, _, length = decode_plain_text(s.recv(5))
    if t == APPLICATION_TYPE:
        fragment = b''
        while len(fragment) < length:
            a = s.recv(length - len(fragment))
            fragment += a
        content = decode_cipher_content(fragment)
        return content.decode('utf-8')
    else:
        AssertionError('server must response APPLICATION_TYPE')

print(read_content(s))
print(read_content(s))
s.close()
