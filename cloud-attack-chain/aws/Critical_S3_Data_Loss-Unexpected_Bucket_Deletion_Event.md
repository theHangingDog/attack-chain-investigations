# Incident Investigation Report
**Report ID:** INC-2025-005  
**Classification:** TLP:AMBER | PAP:AMBER  
**Severity:** HIGH  
**Platform:** AWS (CloudTrail / S3)  
**Analyst:** Arkaprava  
**Date:** 2025-03-21  

---

## 1. Executive Summary

An unauthenticated attacker used the web fuzzing tool **Wfuzz** to enumerate objects in a publicly accessible S3 bucket (`appbackupfilesbuk`), generating over **4,600 requests**. A `config.txt` file was successfully retrieved — likely containing AWS credentials. Those credentials were then used to authenticate as `HelpdeskAdmin`, who proceeded to exfiltrate `function-source.zip`, then delete both objects and finally the entire bucket, resulting in **confirmed data loss and infrastructure destruction**.

**Business Impact:** An S3 bucket containing application source code and configuration was fully wiped. Sensitive credentials stored in `config.txt` were exposed prior to deletion, creating a secondary compromise risk.

---

## 2. Scope and Objective

- **What was analyzed:** AWS CloudTrail logs via Elastic SIEM
- **Involved identities:** Anonymous (Wfuzz), `HelpdeskAdmin` (IAMUser)
- **Source IPs:** `36.255.87.0` – `36.255.87.7`
- **Geo-location:** Bengaluru, India
- **Affected resource:** S3 bucket `appbackupfilesbuk`
- **Objective:** Determine how the bucket was accessed, what was exfiltrated, and reconstruct the full deletion chain

---

## 3. Methodology

- **Tool:** Elastic SIEM (Discover) — `aws` data view
- **Log source:** `aws.cloudtrail`
- **Approach:** Queried `DeleteBucket`/`DeleteObject` events to identify the responsible user, pivoted to all `HelpdeskAdmin` S3 activity, then traced backwards to find the initial reconnaissance — uncovering the Wfuzz enumeration phase via user-agent analysis on the bucket.

---

## 4. Detailed Analysis

### 4.1 Phase 1 — Unauthenticated Bucket Enumeration via Wfuzz
![Alt text](cloud-attack-chain/images/aws/unexpected s3 bucket deletion activity/Screenshot 2026-03-20 173353.png)
> 📸 *[Screenshot 6 — Elastic: event.action breakdown — GetObject 99.8%, bucket appbackupfilesbuk]*

> 📸 *[Screenshot 7 — Elastic: Expanded Wfuzz record — GetObject success, key=config.txt, anonymous identity, IP 36.255.87.5]*

An anonymous actor used **Wfuzz 3.1.0** — a brute-force web/path fuzzer — to fire **4,619 requests** against `appbackupfilesbuk`, attempting to enumerate object keys (visible keys include: `databases`, `decrypt`, `dav`, `peel`, `pfx`, `phpBB2`, `php-bin`, `People`, `PDF`, `config.txt`). 

The majority of requests returned `AccessDenied`, but **`config.txt` was successfully retrieved** via an anonymous `GetObject` call at `2025-01-30T10:09:41Z` from `36.255.87.5`. This file almost certainly contained plaintext AWS credentials — the bucket was publicly readable for this object.

### 4.2 Phase 2 — HelpdeskAdmin Session Established

> 📸 *[Screenshot 4 — Elastic: GetCallerIdentity by HelpdeskAdmin, IP 36.255.87.6]*

Shortly after the Wfuzz scan, `HelpdeskAdmin` authenticated and called `GetCallerIdentity` at `2025-01-30T10:13:06Z` from `36.255.87.6`, confirming the session. The user agent switched to `aws-cli/2.15.28` — indicating a human or scripted CLI session using credentials likely obtained from `config.txt`.

### 4.3 Phase 3 — Reconnaissance and Exfiltration

> 📸 *[Screenshot 3 — Elastic: ListObjects and GetObject by HelpdeskAdmin — function-source.zip downloaded via s3.cp]*

> 📸 *[Screenshot 2 — Elastic: HelpdeskAdmin full S3 activity — 9 events, all action types visible]*

`HelpdeskAdmin` enumerated the bucket via `ListObjects` at `10:13:29Z`, identified target files, and then downloaded `function-source.zip` at `10:16:10Z` using `s3.cp` — confirming **exfiltration of application source code**. A second `ListObjects` call was made at `10:20:17Z` using `s3.rb.rm` — the S3 remove command.

### 4.4 Phase 4 — Destruction

> 📸 *[Screenshot 1 — Elastic: DeleteObject (function-source.zip, config.txt) and DeleteBucket — HelpdeskAdmin, Bengaluru, 36.255.87.7]*

At `2025-01-30T10:20:18Z`, both objects were deleted:
- `function-source.zip` — `DeleteObject` — **Success**
- `config.txt` — `DeleteObject` — **Success**

At `2025-01-30T10:20:19Z`, `DeleteBucket` was called on `appbackupfilesbuk` — **Success**. The bucket no longer exists.

**Full Attack Timeline:**

| Timestamp (UTC) | Actor | Action | Target | Outcome |
|---|---|---|---|---|
| 10:09:41Z | Anonymous (Wfuzz) | GetObject | config.txt | **Success — credentials exposed** |
| 10:13:06Z | HelpdeskAdmin | GetCallerIdentity | — | Success |
| 10:13:29Z | HelpdeskAdmin | ListObjects | appbackupfilesbuk | Success |
| 10:16:10Z | HelpdeskAdmin | GetObject | function-source.zip | **Success — exfiltrated** |
| 10:20:17Z | HelpdeskAdmin | ListObjects | appbackupfilesbuk | Success |
| 10:20:18Z | HelpdeskAdmin | DeleteObject | function-source.zip | **Success — destroyed** |
| 10:20:18Z | HelpdeskAdmin | DeleteObject | config.txt | **Success — destroyed** |
| 10:20:19Z | HelpdeskAdmin | DeleteBucket | appbackupfilesbuk | **Success — bucket gone** |

Total time from credential theft to full destruction: **~11 minutes.**

### 4.5 TheHive Case Reference

> 📸 *[Screenshot 8 — TheHive Case #1 Task details — Investigation steps]*

> 📸 *[Screenshot 9 — TheHive Case #1 General — Critical S3 Data Loss, SEV:HIGH]*

Case `#1` was raised in TheHive, tagged `AWS`, `S3`, `Data Loss`, severity **HIGH**. Detection time: **28 seconds**.

---

## 5. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| IAM User | `HelpdeskAdmin` |
| IAM ARN | `arn:aws:iam::010928207857:user/HelpdeskAdmin` |
| Source IPs | `36.255.87.0` – `36.255.87.7` |
| Geo-location | Bengaluru, Karnataka, India |
| Initial Recon Tool | `Wfuzz/3.1.0` |
| Exfiltrated Files | `function-source.zip`, `config.txt` |
| Deleted Bucket | `appbackupfilesbuk` |
| CLI User Agent | `aws-cli/2.15.28 Python/3.11.8 Windows/10` |

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Active Scanning — Wordlist Scanning | T1595.003 |
| Initial Access | Valid Accounts — Cloud Accounts (via stolen config) | T1078.004 |
| Credential Access | Unsecured Credentials in Cloud Storage | T1552.005 |
| Collection | Data from Cloud Storage | T1530 |
| Exfiltration | Transfer Data to Cloud Account | T1537 |
| Impact | Data Destruction | T1485 |

---

## 7. Findings

- `appbackupfilesbuk` was publicly accessible — `config.txt` was readable without authentication, which directly enabled the compromise
- Storing plaintext AWS credentials in S3 is a critical misconfiguration — this was the root cause of the entire incident
- `HelpdeskAdmin` had `s3:DeleteBucket` and `s3:DeleteObject` permissions — destructive S3 actions should require explicit approval or MFA
- The Wfuzz scan generated **4,619 requests** — no rate limiting, IP-based blocking, or anomaly detection was in place for anonymous bucket access
- The attacker cleaned up evidence (deleted `config.txt`) making post-incident forensics harder

---

## 8. Impact Assessment

| Area | Detail |
|---|---|
| Data Destroyed | `function-source.zip` (app source code), `config.txt` |
| Bucket Lost | `appbackupfilesbuk` — permanently deleted |
| Credentials Exposed | AWS keys present in `config.txt` — must be treated as fully compromised |
| Compromised Identity | `HelpdeskAdmin` |
| **Severity** | **HIGH** |

---

## 9. Recommendations

- **Immediately** rotate all AWS credentials that may have been stored in `config.txt` across the entire account
- Enable **S3 Block Public Access** at the account level — no bucket should allow anonymous reads
- Never store credentials in S3 objects — use **AWS Secrets Manager** or **Parameter Store**
- Require **MFA Delete** on all S3 buckets to prevent unauthorized bucket deletion
- Enable **S3 Versioning** and **Object Lock** on critical buckets to prevent permanent data loss
- Set CloudWatch alarms for `DeleteBucket` and `DeleteObject` events — especially from IPs outside corporate ranges
- Implement **AWS WAF** or S3 access logging with anomaly alerting to detect Wfuzz-style enumeration

---

## 10. Conclusion

A publicly exposed `config.txt` in an S3 bucket was discovered by an unauthenticated attacker using the Wfuzz fuzzing tool. The file contained AWS credentials belonging to `HelpdeskAdmin`. Within minutes, the attacker authenticated, exfiltrated application source code, and systematically deleted all objects and the bucket itself. The root cause is a combination of public S3 access, credential mismanagement, and the absence of destructive action controls. This is a textbook **misconfiguration-to-data-destruction** attack chain.

---
*Report generated as part of multi-cloud blue team investigation lab — CyberWarFare Labs Module 5*
