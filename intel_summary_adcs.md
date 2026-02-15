# Project Nexus: Intelligence Summary (AD CS ESC9-ESC13)
# Protocol: Pure English / XEEA Internal Use Only

## 1. ESC11: Relay to ICertPassage (RPC)
- **Endpoint**: `ICertPassage` interface (UUID: `91ae6060-9e3c-11cf-8d7c-00aa00c091be`).
- **Primitive**: NTLM Relay via RPC/DCOM.
- **Vulnerability**: If the CA allows RPC enrollment and NTLM authentication is not strictly hardened (signing/extended protection), an attacker can relay machine account auth to this interface.
- **Nexus Logic**: Modular Impacket-based RPC binder targeting `\pipe\cert`. Uses `CertServerRequest` (Opnum 0) to submit CSRs directly over RPC.
- **Stealth**: Avoids HTTP enrollment noise. Use randomized RPC call signatures.

## 2. ESC13: OID Group Link Abuse
- **Endpoint**: Active Directory `msDS-OIDToGroupLink` attribute.
- **Primitive**: Certificate-based Group Membership Injection.
- **Vulnerability**: A certificate template linked to an Issuance Policy OID that is mapped to an AD group (via `msDS-OIDToGroupLink`) grants the enrollee membership of that group upon authentication.
- **Nexus Logic**: Enumerate templates with `msPKI-Certificate-Policy`. Check OID objects for group links. Automated enrollment for templates linked to 'Tier 0' groups (e.g. Enterprise Admins).
- **Stealth**: No group membership change in AD (membership is ephemeral in the Kerberos TGT).

## 3. ESC9 & ESC10: Strong Mapping Bypass
- **Attribute**: `msDS-StrongCertificateBindingOnCertificate` and `altSecurityIdentities`.
- **Primitive**: Identity Injection / Attribute Modification.
- **Vulnerability**: Abuses weak certificate mapping requirements (`CertificateMappingMethods` registry key). If an attacker has write access to a target's `altSecurityIdentities`, they can link a malicious certificate to a high-privileged account.
- **Nexus Logic**: Integrated LDAP module to check/modify target account attributes before triggering coercion.

## 4. ESC12: ADCS Policy Server Relay
- **Endpoint**: Certificate Enrollment Policy (CEP) Web Service.
- **Primitive**: HTTP NTLM Relay.
- **Vulnerability**: Relaying auth to the CEP web service to discover templates and CA details, often used as a precursor to other ESC attacks.

---
© 2026 XEEA Security / Project Nexus
