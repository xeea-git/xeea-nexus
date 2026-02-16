# XEEA Nexus: Unified Red Team Orchestrator

![XEEA Nexus Banner](https://img.shields.io/badge/XEEA-Nexus-red?style=for-the-badge)
**The industry-standard orchestrator for multi-protocol coercion and escalation.**

XEEA Nexus is a high-performance, modular engine designed for advanced red team operations in complex Active Directory environments. It integrates sophisticated coercion primitives with state-of-the-art relay and escalation modules, providing a unified pipeline for domain dominance.

## 🚀 Core Capabilities

### 1. Advanced AD CS Escalation (ESC9 - ESC13)
Nexus provides the most comprehensive implementation of recent AD CS vulnerabilities, including:
- **ESC11 (Relay to ICertPassage)**: Modular RPC/DCOM binding for silent NTLM relaying to CA interfaces.
- **ESC13 (OID Group Link Abuse)**: Automated identification and exploitation of ephemeral group membership injection via issuance policies.
- **ESC9/ESC10 (Strong Mapping Bypass)**: Intelligence-driven LDAP modification to bypass certificate mapping hardening.

### 2. Multi-Protocol Coercion Engine
- **Automated Coercion**: Integrated triggers for MS-EFSR, MS-FSRVP, and MS-DFSNM.
- **Stealth Integration**: Orchestrated timing and protocol selection to minimize EDR/IDS signatures.

### 3. Nexus-Gate Stealth Stager
- **Dynamic Syscall Invocation**: Bypasses user-mode hooks via direct NT syscalls (Project Nexus-Gate).
- **Multi-Stage Execution**: Transition-based memory protection (RW -> RX) to evade scanners.
- **Process Injection**: Professional, high-stability injection techniques for persistent access.

## 🛠 Usage

```bash
# Initialize Nexus Core
python3 nexus-core.py --coercion --relay ldaps://dc01.internal

# Execute ESC11 Module
python3 esc11_module.py -t ca01.internal -ca INTERNAL-CA -u user01 -p 'Password123!'
```

## 📋 Technical Intelligence

For detailed protocol breakdowns and implementation logic, refer to:
- `intel_summary_adcs.md`: Comprehensive guide to AD CS primitives.

## ⚖️ License & Compliance

Proprietary technology developed by **XEEA SECURITY**. For internal use by authorized personnel only. 

### 🔄 Redundancy & Backup
Primary Forgejo Node: [https://git.cxntz0ne.eu.org/megamind-bot/xeea-nexus](https://git.cxntz0ne.eu.org/megamind-bot/xeea-nexus)

---
© 2026 XEEA SECURITY | *Precision in Persistence. Excellence in Execution.*
