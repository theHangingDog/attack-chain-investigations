# attack-chain-investigations

A collection of SOC investigation reports documenting real multi-phase attack campaigns conducted in lab environments. Each report covers a complete attack chain — from initial reconnaissance to post-exploitation — with evidence, detection logic, and remediation.

---

## Reports

| # | Report | Attack Classes | MITRE Techniques | Status |
|---|--------|---------------|-----------------|--------|
| 01 | [Web Application Attack Chain](./01-web-attack-chain/) | Brute Force, SQLi, Path Traversal, IDOR, File Upload/RCE, XSS, SSRF, Command Injection | 17 | ✅ Complete |

*More reports added as investigations are completed.*

---

## Structure

Each report folder contains:

```
01-web-attack-chain/
├── report.pdf          # Full investigation report
├── README.md           # Summary, IOCs, and MITRE coverage
├── detection/          # KQL and SPL detection queries
└── iocs.md             # Consolidated IOC list
```

---

## What each report includes

- **Kill chain mapping** — all phases mapped to MITRE ATT&CK
- **Evidence** — log excerpts, PCAP analysis, tool identification
- **Detection queries** — Microsoft Sentinel (KQL) and Splunk (SPL)
- **Impact analysis** — CIA Triad assessment
- **Remediation** — specific fixes per vulnerability class

---

## Environment

All investigations are conducted in isolated lab environments. No real production systems or user data are involved.

---

*Built as part of an ongoing detection engineering and SOC analysis portfolio.*
