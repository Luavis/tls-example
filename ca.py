import base64
import io
from x509 import X509, parse_der
ca_list = [
    'dst.pem'
]

ca_cert = []

for ca in ca_list:
    f = open(ca)
    pem = f.read()
    pem_content = ''.join(pem.split('\n')[1:-1])
    der = base64.decodestring(pem_content.encode('utf-8'))
    cert = X509(parse_der(io.BytesIO(der)))
    ca_cert.append(cert)
