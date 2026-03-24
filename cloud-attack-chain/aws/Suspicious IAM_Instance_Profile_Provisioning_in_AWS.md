# Incident Investigation Report
**Report ID:** INC-2025-003  
**Classification:** TLP:AMBER | PAP:AMBER  
**Severity:** HIGH  
**Platform:** AWS (CloudTrail / Lambda)  
**Analyst:** Arkaprava  
**Date:** 2025-03-21  

---

## 1. Executive Summary

A compromised IAM user `Emp02` invoked an existing Lambda function (`dev-app-lambda`) which was found to contain malicious code — specifically designed to generate and return new IAM access keys for a target user (`S3User`). The generated credentials were subsequently used to enumerate and exfiltrate a file (`project7289-blueprint.jpeg`) from an S3 bucket. This represents a full credential theft and data exfiltration chain facilitated via a backdoored Lambda function.

**Business Impact:** IAM credentials were generated and handed to an attacker through a weaponized Lambda function. Sensitive project assets were accessed and likely exfiltrated.

---

## 2. Scope and Objective

- **What was analyzed:** AWS CloudTrail logs via Elastic SIEM
- **Involved users:** `Emp02` (initial access), `S3User` (generated credentials)
- **Source IPs:** `36.255.87.0` – `36.255.87.5`
- **Affected resources:** Lambda function `dev-app-lambda`, S3 bucket `project7289assetfilesbuk`
- **Objective:** Trace the full chain from initial Lambda invocation to credential use and data exfiltration

---

## 3. Methodology

- **Tool:** Elastic SIEM (Discover) — `aws` data view
- **Log source:** `aws.cloudtrail`, Lambda function code review
- **Approach:** Pivoted from `Emp02` activity → Lambda invocation → assumed role credentials → `S3User` post-compromise activity. Cross-referenced Lambda source code to confirm malicious intent.

---

## 4. Detailed Analysis

### 4.1 Initial Reconnaissance by Emp02

> 📸 *[Screenshot 1 — Elastic: Emp02 field stats — GetCallerIdentity, ListBuckets, ListFunctions20150331]*

> 📸 *[Screenshot 2 — Elastic: Emp02 tabular view — 3 events, ListBuckets failed (AccessDenied), ListFunctions succeeded]*

At `2025-01-30T10:31:06Z`, `Emp02` called `GetCallerIdentity` to confirm their session context. Shortly after, they attempted `ListBuckets` — which was **denied** — then successfully called `ListFunctions20150331` via `lambda.amazonaws.com`, discovering available Lambda functions in the account.

| Timestamp (UTC) | Action | Outcome | Notes |
|---|---|---|---|
| 2025-01-30T10:31:06Z | GetCallerIdentity | Success | Session verification |
| 2025-01-30T10:31:38Z | ListBuckets | **Failure** (AccessDenied) | Direct S3 access blocked |
| 2025-01-30T10:32:17Z | ListFunctions20150331 | Success | Lambda enumeration |

### 4.2 Lambda Invocation and Credential Generation

> 📸 *[Screenshot 3 — Elastic: AssumeRole by lambda.amazonaws.com, role dev-app-lambda-role, credentials returned]*

At `2025-01-30T10:35:00Z`, Lambda assumed its execution role (`service-role/dev-app-lambda-role-edn14g4n`) with session name `dev-app-lambda`. The response contained a full set of temporary credentials (`ASIAQFC27G7Y7QZGNWQY`), expiring at **10:35 PM** the same day — granting a near 12-hour window.

> 📸 *[Screenshot 4 — Lambda function code: dev-app-lambda, creates IAM access key for TARGET_IAM_USER (S3User)]*

Inspection of the Lambda function `dev-app-lambda` (`lambda_function.py`) revealed it calls `iam_client.create_access_key()` for a target user defined via environment variable `TARGET_IAM_USER` (defaulting to `S3User`). The function returns both `AccessKeyId` and `SecretAccessKey` in the response body — this is a **credential harvesting backdoor** deployed as a Lambda function.

### 4.3 Post-Compromise Activity — S3User

> 📸 *[Screenshot 5 — Elastic: S3User — GetCallerIdentity, ListBuckets, ListObjects, GetObject, HeadObject, HeadBucket]*

Using the freshly generated credentials, the attacker operated as `S3User` and performed the following:

| Timestamp (UTC) | Action | Target | Outcome |
|---|---|---|---|
| 2025-01-30T10:36:19Z | GetCallerIdentity | — | Success |
| 2025-01-30T10:36:57Z | ListBuckets | — | Success |
| 2025-01-30T10:37:06Z | ListObjects | project7289assetfilesbuk | Success |
| 2025-01-30T10:38:01Z | HeadBucket / HeadObject | project7289-blueprint.jpeg | Success |
| 2025-01-30T10:38:04Z | GetObject | project7289-blueprint.jpeg | **Success — Exfiltration** |

The file `project7289-blueprint.jpeg` was downloaded — likely a design blueprint or sensitive project asset.

---

## 5. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| IAM Users | `Emp02`, `S3User` |
| Source IPs | `36.255.87.0` – `36.255.87.5` |
| Lambda Function | `dev-app-lambda` |
| Lambda Role | `service-role/dev-app-lambda-role-edn14g4n` |
| Access Key Generated | `ASIAQFC27G7Y7QZGNWQY` |
| Exfiltrated File | `project7289-blueprint.jpeg` |
| S3 Bucket | `project7289assetfilesbuk` |
| Malicious Code | `iam_client.create_access_key(Username=user_name)` in `lambda_function.py` |

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Discovery | Cloud Service Discovery (Lambda enumeration) | T1526 |
| Credential Access | Steal Application Access Token | T1528 |
| Credential Access | Forge Web Credentials via IAM key creation | T1552.005 |
| Execution | Serverless Execution | T1648 |
| Collection | Data from Cloud Storage | T1530 |
| Exfiltration | Transfer Data to Cloud Account | T1537 |

---

## 7. Findings

- `Emp02` had `lambda:ListFunctions` and `lambda:InvokeFunction` permissions — excessive for a standard user account
- The Lambda function `dev-app-lambda` was pre-deployed with malicious code that creates IAM credentials on invocation — this is either an insider threat or a supply chain/CI-CD compromise
- `S3User` had no MFA and was reachable purely through programmatic keys, making credential abuse trivial
- The entire chain from enumeration to exfiltration completed in under **7 minutes**

---

## 8. Impact Assessment

| Area | Detail |
|---|---|
| Compromised Accounts | `Emp02`, `S3User` (via generated keys) |
| Exfiltrated Asset | `project7289-blueprint.jpeg` (project design asset) |
| Affected Lambda | `dev-app-lambda` — actively weaponized |
| **Severity** | **HIGH** |

---

## 9. Recommendations

- **Immediately** delete the access key `ASIAQFC27G7Y7QZGNWQY` and audit all actions taken by `S3User`
- Remove or redeploy `dev-app-lambda` after a full code audit — treat it as **compromised**
- Enforce **least privilege** on Lambda execution roles — `iam:CreateAccessKey` should never be in a Lambda's permission set
- Restrict `lambda:InvokeFunction` to specific admin roles only
- Enable **Lambda code signing** to detect unauthorized deployments
- Set CloudWatch alarms for `iam:CreateAccessKey` calls originating from Lambda execution roles
- Enforce **MFA** on all human IAM users including `Emp02`

---

## 10. Conclusion

`Emp02`, after being blocked from direct S3 access, pivoted through a backdoored Lambda function to generate fresh IAM credentials for `S3User`. The Lambda function contained explicit credential harvesting logic targeting a predefined IAM user. The generated keys were used within minutes to enumerate and exfiltrate a project blueprint from S3. The root cause is a weaponized Lambda function with excessive IAM permissions and absent code review controls.

---
*Report generated as part of multi-cloud blue team investigation lab — CyberWarFare Labs Module 5*
