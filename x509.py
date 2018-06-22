import io
import hashlib
import pkcs_1

class Node:
    def __init__(self, node_type, body, payload=None):
        self.type = node_type
        self.body = body
        self.children = []
        self.payload = payload

    @property
    def stream(self):
        return io.BytesIO(self.body)

    def __getitem__(self, key):
        return self.children[key]

    @property
    def value(self):
        if self.type == 0x02:
            return int.from_bytes(self.body, 'big')
        elif self.type == 0x05:
            return None
        elif self.type & 0x20 is not 0:
            return self.children
        elif self.type == 0x06:
            oid = self.parse_oid()
            return {
                '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
                '1.2.840.113549.1.1.1': 'rsaEncryption',
                '2.5.4.6': 'countryName',
                '2.5.4.10': 'organizationName',
                '2.5.4.3': 'commonName',
            }.get(oid, oid)
        else:
            return self.body

    def __repr__(self):
        return '[type: {0}, value: {1}]'.format(self.type, self.value)

    def parse_oid(self):
        oid = [int(self.body[0] / 40), self.body[0] % 40]
        buf = io.BufferedReader(io.BytesIO(self.body[1:]))

        def parse_digit(stream, prev=0):
            d = ord(buf.read(1))
            if d & 0x80 is not 0:
                return parse_digit(stream, (d & 0x7F) | (prev << 7))
            else:
                return d | (prev << 7)

        while len(buf.peek()) is not 0:
            d = parse_digit(buf)
            oid.append(d)

        return '.'.join(map(lambda i: str(i), oid))


def parse_der(stream, parent_node=None):
    def read_len():
        fb = stream.read(1)
        first = ord(fb)
        if first & 0x80 is not 0:  # if MSB on
            size = first & 0x7f
            if size is 0:
                raise NotImplementedError('indefinite lenght is not impl')
            b_length = stream.read(size)
            return int.from_bytes(b_length, 'big'), fb + b_length
        else:
            return first, fb
    while True:
        tb = stream.read(1)
        if len(tb) == 0:  # if end
            break
        t = ord(tb)
        l, lb = read_len()
        body = stream.read(l)
        if t & 0x20 is not 0:  # check contructed:
            node = Node(t, body, tb + lb + body)
            parse_der(node.stream, parent_node=node)
            if parent_node:
                parent_node.children.append(node)
            else:
                return node
        else:
            if parent_node:
                parent_node.children.append(Node(t, body))
            else:
                return node

class X509:
    __slots__ = [
        'ver',
        'serial_number',
        'algorithm',
        'serial_number',
        'issuer',
        'validity',
        'subject',
        'pubkey',
        'body',
        'signature_algorithm',
        'signature',
    ]

    def __init__(self, node):
        if node.type is not 48:
            raise ValueError('invalid certificate')
        cert = node[0]
        self.body = cert.payload
        self.signature_algorithm = node[1][0]
        self.signature = node[2].value[1:]
        self.ver = cert[0][0]
        self.serial_number = cert[1]

        # ignore index 1: parameter
        self.algorithm = cert[2][0]

        # issuer
        self.issuer = {}
        for issuers in cert[3]:
            if issuers.type == 49:
                for issuer in issuers.value:
                    self.issuer[issuer[0].value] = issuer[1].value

        # validity
        if cert[4].type == 48:
            self.validity = [
                cert[4][0].value.decode('ascii'),
                cert[4][1].value.decode('ascii'),
            ]

        # subject
        self.subject = {}
        for subjects in cert[5]:
            if subjects.type == 49:
                for subject in subjects.value:
                    self.subject[subject[0].value] = subject[1].value

        # public key info
        if cert[6].type == 48:
            self.pubkey = {}
            pubkey = cert[6].value
            # ignore index 1: parameter
            self.pubkey['algorithm'] = pubkey[0][0].value
            self.pubkey['parameter'] = pubkey[0][1].value
            k = pubkey[1].value
            if k[0] is not 0:
                raise NotImplementedError('non-zero key padding is not supported')
            key = parse_der(io.BytesIO(k[1:]))
            self.pubkey['modulus'] = key[0].value
            self.pubkey['exponent'] = key[1].value

    def __repr__(self):
        return """X509 Certificate
ver: {0}
Serial Number: {1}
Algorithm: {2}
Serial Number: {3}
Issuer: {4}
Validity: {5}
Subject: {6}
Public Key: {7}
Signature: {8}
""".format(
        self.ver,
        self.serial_number,
        self.algorithm,
        self.serial_number,
        self.issuer,
        self.validity,
        self.subject,
        self.pubkey,
        self.signature
    )

    def is_valid_signature(self, parent):
        em = pkcs_1.rsassa_pkcs_1_v1_5_verify(
            parent.pubkey['modulus'],
            parent.pubkey['exponent'],
            self.signature,
            self.body
        )
        return True


if __name__ == '__main__':
    f = open('./chain.der', 'rb')
    der = f.read()
    f.close()
    stream = io.BytesIO(der)
    cert = parse_der(stream)
    print(X509(cert))
    f.close()
