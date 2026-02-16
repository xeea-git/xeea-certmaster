# XEEA CertMaster: Advanced AD CS ESC1 Auditor & Hunter

![XEEA CertMaster Banner](https://img.shields.io/badge/XEEA-CertMaster-red?style=for-the-badge)
**Professional, automated discovery and exploitation of misconfigured Active Directory Certificate Templates.**

XEEA CertMaster is a standalone tool designed for high-efficiency identification and exploitation of AD CS ESC1 vulnerabilities. It automates the complex discovery-to-escalation pipeline, providing a silent, reliable path to domain dominance.

## 🚀 Key Features

- **Automated ESC1 Discovery**: High-speed LDAP querying to identify certificate templates where the SAN is enrollee-supplied and Client Authentication EKU is present.
- **Silent CSR Generation**: Automatically generates a Private Key and a Certificate Signing Request (CSR) with a custom Subject Alternative Name (SAN) targeting high-value accounts (e.g., Domain Admins).
- **Direct DCOM Submission**: Implements the `ICertRequestD2::Submit` (MS-WCCE) logic for direct communication with the Certificate Authority.
- **PURE XEEA Standard**: 100% proprietary code with a minimalist, automated interface designed for surgical execution.

## 🛠 Usage

```bash
# Scan for vulnerable templates
python3 xeea_certmaster.py -d domain.local -u user -p password --scan

# Exploit ESC1 and retrieve certificate for Administrator
python3 xeea_certmaster.py -d domain.local -u user -p password -template "VulnerableTemplate" -target-user "Administrator"
```

## 📋 Requirements

- `impacket`
- `ldap3`
- `cryptography`

### 🔄 Redundancy & Backup
Primary Forgejo Node: [https://git.cxntz0ne.eu.org/megamind-bot/xeea-certmaster](https://git.cxntz0ne.eu.org/megamind-bot/xeea-certmaster)

---
© 2026 XEEA Security | *Precision in Persistence. Excellence in Execution.*
