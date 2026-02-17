# XEEA Nexus: Unified Red Team Orchestrator

![XEEA Nexus Banner](https://img.shields.io/badge/XEEA-Nexus-red?style=for-the-badge)
**The industry-standard orchestrator for multi-protocol coercion, escalation, and persistent C2.**

XEEA Nexus is a high-performance, modular engine designed for advanced red team operations in complex Active Directory environments. It integrates sophisticated coercion primitives with state-of-the-art relay and escalation modules, providing a unified pipeline for domain dominance.

## 🚀 Core Capabilities

### 1. Multi-Protocol Coercion & Discovery
- **Automated Coercion Engine**: Integrated triggers for MS-EFSR, MS-FSRVP, and MS-DFSNM (PetitPotam, ShadowCoerce, DFSCoerce).
- **Stealth Discovery**: Passive and active identification of relayable targets and vulnerable CA interfaces.
- **Protocol Selection**: Intelligence-driven selection of coercion methods to minimize EDR/IDS signatures.

### 2. Advanced AD CS Escalation (ESC1 - ESC13)
Nexus provides the most comprehensive implementation of AD CS vulnerabilities, including:
- **ESC11 (Relay to ICertPassage)**: Modular RPC/DCOM binding for silent NTLM relaying to CA interfaces.
- **ESC13 (OID Group Link Abuse)**: Automated identification and exploitation of ephemeral group membership injection via issuance policies.
- **ESC9/ESC10 (Strong Mapping Bypass)**: Intelligence-driven LDAP modification to bypass certificate mapping hardening.

### 3. Integrated C2 Listeners & Stagers
- **Multi-Protocol Listeners**: High-performance handlers for HTTP/S, DNS, and SMB beacons.
- **Nexus-Gate Stealth Stager**: Bypasses user-mode hooks via direct NT syscalls and dynamic invocation.
- **Multi-Stage Execution**: Transition-based memory protection (RW -> RX) to evade scanners.
- **Process Injection**: Professional, high-stability injection techniques for persistent access.

### 4. Real-Time Visualization & Orchestration
- **Nexus Graph Visualizer**: Real-time attack chain visualization (SVG/ASCII) powered by a customized Mermaid.js engine.
- **Dynamic Orchestration**: Automated Coercion -> Relay -> AD CS/LDAP escalation pipeline.
- **Extensible Plugin System**: Hot-pluggable architecture for custom modules, listeners, and specialized report generators.

## 🛠 Usage

```bash
# Initialize Nexus Core with Coercion -> Relay Pipeline
python3 nexus-core.py --coercion --relay ldaps://dc01.internal

# Deploy C2 Listener
python3 nexus-core.py --listener http --port 443

# Execute ESC11 Module
python3 esc11_module.py -t ca01.internal -ca INTERNAL-CA -u user01 -p 'Password123!'
```

## 📋 Technical Intelligence

For detailed protocol breakdowns and implementation logic, refer to:
- `intel_summary_adcs.md`: Comprehensive guide to AD CS primitives.
- `plugins/`: Directory for specialized expansion modules.
- `listeners/`: Core C2 listener implementations.

## ⚖️ License & Compliance

Proprietary technology developed by **XEEA SECURITY**. For internal use by authorized personnel only. 

### 🔄 Repositories & Redundancy
- **Primary Forgejo**: [https://git.cxntz0ne.eu.org/megamind-bot/xeea-nexus](https://git.cxntz0ne.eu.org/megamind-bot/xeea-nexus)
- **Secondary GitHub Backup**: XEEA Arsenal / Nexus Core

---
© 2026 XEEA SECURITY | *Precision in Persistence. Excellence in Execution.*
