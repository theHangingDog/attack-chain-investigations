# Incident Investigation Report
**Report ID:** INC-2025-001  
**Classification:** TLP:AMBER | PAP:AMBER  
**Severity:** CRITICAL  
**Platform:** AWS (CloudTrail)  
**Analyst:** Arkaprava  
**Date:** 2025-03-21  

---

## 1. Executive Summary

A compromised IAM user **Emp05** was observed making repeated `AssumeRole` attempts against an internal role (`Assume_Role`) from a single external IP. After 18 failed `AccessDenied` attempts, the attacker successfully assumed the role and proceeded to enumerate and exfiltrate data from an S3 bucket (`previousyearfinancedatabuk`), specifically downloading a sensitive finance archive `2023-2024+finance+data.zip`.

**Business Impact:** Unauthorized access to financial data. Confirmed data exfiltration. High risk of regulatory and reputational damage.

---

## 2. Scope and Objective

- **What was analyzed:** AWS CloudTrail logs ingested into Elastic SIEM
- **Involved user:** `Emp05` (IAMUser), then assumed identity `Assume_Role`
- **Source IP:** `36.255.87.4`, `36.255.87.5`, `36.255.87.6`
- **Affected resource:** S3 bucket — `previousyearfinancedatabuk`
- **Objective:** Identify the scope of unauthorized role assumption and data access

---

## 3. Methodology

- **Tool:** Elastic SIEM (Discover) — `aws` data view
- **Log source:** `aws.cloudtrail`
- **Approach:** Queried CloudTrail for `AssumeRole` events by IAMUser identity type, filtered by error codes (`AccessDenied`, `ValidationException`), then pivoted to the assumed role session to trace post-compromise activity

---

## 4. Detailed Analysis

### 4.1 Role Enumeration / Brute-Force Attempts

> 📸 *[Screenshot 1 — Elastic: AssumeRole query, 20 events, error breakdown]*

> 📸 *[Screenshot 2 — Elastic: AccessDenied filter, 18 events, Emp05, IP 36.255.87.4]*

> 📸 *[Screenshot 3 — Elastic: Continuation of AccessDenied events]*

User `Emp05` made **18 consecutive `AssumeRole` calls**, all returning `AccessDenied`, targeting multiple role ARNs (`arn:aws:iam::010928207857:role/1` through `/A`). All requests originated from `36.255.87.4` using `Boto3/1.34.124` (Python automation tool), indicating scripted enumeration.

### 4.2 ValidationException — Session Duration Abuse Attempt

> 📸 *[Screenshot 4 — Elastic: ValidationException event, durationSeconds 43200]*

One attempt returned a `ValidationException` — the attacker requested a session of **43,200 seconds (12 hours)**, exceeding the role's `MaxSessionDuration`. This reveals deliberate intent to maintain long-term persistent access.

**Role targeted:** `arn:aws:iam::010928207857:role/Assume_Role`  
**Session name:** `CWkF8z0p1X6OZEM2A1K0`

### 4.3 Successful Role Assumption & Data Exfiltration

> 📸 *[Screenshot 5 — Elastic: Assume_Role session — ListObjects, GetObject on finance bucket]*

Following the failed attempts (likely after obtaining valid credentials or a policy change), the attacker successfully assumed the role. Using the session `Assume_Role/QwVMDSy9rMLf0SgNa3e8`, the following actions were recorded:

| Timestamp (UTC) | Action | Resource | Outcome |
|---|---|---|---|
| 2025-01-30T10:43:20Z | GetCallerIdentity | — | Success |
| 2025-01-30T10:44:40Z | ListObjects | previousyearfinancedatabuk | Success |
| 2025-01-30T10:45:26Z | HeadBucket | previousyearfinancedatabuk | Success |
| 2025-01-30T10:45:26Z | HeadObject | 2023-2024+finance+data.zip | Success |
| 2025-01-30T10:45:28Z | GetObject | 2023-2024+finance+data.zip | Success |

The `GetObject` call confirms **exfiltration of financial data**.

### 4.4 TheHive Case Reference

> 📸 *[Screenshot 6 — TheHive Case #5, Suspicious Cross-Account Trust Relationship Identified]*

Case `#5` was created in TheHive with severity **CRITICAL**, tagged `AWS`, `Trust Relationship`, `Privilege Escalation`, `IAM`, `Cross-Account Trust`. Detection time: **27 seconds**.

---

## 5. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| IAM User | `Emp05` |
| Assumed Role | `arn:aws:iam::010928207857:role/Assume_Role` |
| Source IPs | `36.255.87.4`, `36.255.87.5`, `36.255.87.6` |
| Session Name | `CWkF8z0p1X6OZEM2A1K0` |
| Exfiltrated File | `2023-2024+finance+data.zip` |
| S3 Bucket | `previousyearfinancedatabuk` |
| User Agent | `Boto3/1.34.124 md/python#3.x` |

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Valid Accounts (Compromised IAM) | T1078.004 |
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548 |
| Credential Access | Steal Application Access Token (STS AssumeRole) | T1528 |
| Discovery | Cloud Storage Object Discovery | T1619 |
| Exfiltration | Transfer Data to Cloud Account | T1537 |

---

## 7. Findings

- `Emp05` credentials were compromised and used for automated role enumeration
- The attacker systematically tried multiple role ARNs — indicating prior knowledge or brute-forcing of the account structure
- A 12-hour session was requested, signaling intent for persistent access
- Post-assumption activity was fast and targeted — the attacker went straight for the finance bucket
- No MFA was enforced on the `AssumeRole` policy for the `Assume_Role` role

---

## 8. Impact Assessment

| Area | Detail |
|---|---|
| Affected Data | `2023-2024+finance+data.zip` — financial records |
| Affected Resource | S3 bucket `previousyearfinancedatabuk` |
| Compromised Identity | `Emp05` (IAMUser), `Assume_Role` session |
| **Severity** | **CRITICAL** |

---

## 9. Recommendations

- **Immediately** revoke `Emp05` credentials and invalidate active sessions
- Enforce **MFA** on all `AssumeRole` trust policies for sensitive roles
- Restrict `sts:AssumeRole` to specific, trusted account principals — not `"AWS": "*"`
- Enable **S3 Object-level logging** and set CloudTrail alerts for `GetObject` on sensitive buckets
- Implement **SCPs** (Service Control Policies) to restrict `AssumeRole` from unrecognized IPs
- Review all IAM roles with wildcard `Principal` in their trust policies

---

## 10. Conclusion

A compromised IAM user (`Emp05`) conducted a scripted role enumeration attack using the AWS Boto3 SDK. After persistent attempts, the attacker successfully assumed an overly permissive IAM role and exfiltrated a financial data archive from S3. The attack chain — from enumeration to exfiltration — completed within approximately **4 minutes**. The root cause is an improperly scoped trust policy combined with the absence of MFA enforcement on role assumption.

---
*Report generated as part of multi-cloud blue team investigation lab — CyberWarFare Labs Module 5*
