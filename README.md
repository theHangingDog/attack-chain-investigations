# attack-chain-investigations
A collection of SOC investigation reports documenting real multi-phase attack campaigns conducted in lab environments. Each report covers a complete attack chain — from initial reconnaissance to post-exploitation — with evidence, detection logic, and remediation.

---

## Reports

| # | Report | Attack Classes | MITRE Techniques | Status |
|---|--------|---------------|-----------------|--------|
| 01 | [Web Application Attack Chain](./01-web-attack-chain/) | Brute Force, SQLi, Path Traversal, IDOR, File Upload/RCE, XSS, SSRF, Command Injection | 17 | ✅ Complete |
| 02 | [Cloud Attack Chain — AWS](./cloud-attack-chain/aws/) | IAM Abuse, Privilege Escalation, Cross-Account Trust Abuse, Lambda Exploitation, S3 Data Loss | 5 | ✅ Complete |

*More reports added as investigations are completed.*

---

## Cloud Attack Chain — AWS

Investigation reports covering a multi-phase cloud attack campaign targeting AWS infrastructure. Each report documents an individual attack phase with detection logic and remediation.

| # | Report | Category |
|---|--------|----------|
| 01 | [Critical S3 Data Loss — Unexpected Bucket Deletion Event](./cloud-attack-chain/aws/Critical_S3_Data_Loss-Unexpected_Bucket_Deletion_Event.md) | Data Destruction / Exfiltration |
| 02 | [Suspicious IAM Instance Profile Provisioning in AWS](./cloud-attack-chain/aws/Suspicious_IAM_Instance_Profile_Provisioning_in_AWS.md) | Privilege Escalation |
| 03 | [Suspicious Cross-Account Trust Relationship Identified](./cloud-attack-chain/aws/Suspicious_Cross_Account_Trust_Relationship_Identified.md) | Lateral Movement |
| 04 | [Suspicious Lambda Function Execution Identified](./cloud-attack-chain/aws/Suspicious_Lambda_Function_Execution_Identified.md) | Execution / Defense Evasion |
| 05 | [Unauthorized IAM Policy Modification Detected](./cloud-attack-chain/aws/Unauthorized_IAM_Policy_Modification_Detected.md) | Persistence / Privilege Escalation |

---

## Structure

Each report folder contains:

```
01-web-attack-chain/
├── report.pdf          # Full investigation report
├── README.md           # Summary, IOCs, and MITRE coverage
├── detection/          # KQL and SPL detection queries
└── iocs.md             # Consolidated IOC list

cloud-attack-chain/
└── aws/
    ├── Critical_S3_Data_Loss-Unexpected_Bucket_Deletion_Event.md
    ├── Suspicious_IAM_Instance_Profile_Provisioning_in_AWS.md
    ├── Suspicious_Cross_Account_Trust_Relationship_Identified.md
    ├── Suspicious_Lambda_Function_Execution_Identified.md
    └── Unauthorized_IAM_Policy_Modification_Detected.md
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
