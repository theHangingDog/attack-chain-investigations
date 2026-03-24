# Incident Investigation Report
**Report ID:** INC-2025-004  
**Classification:** TLP:AMBER | PAP:AMBER  
**Severity:** MEDIUM  
**Platform:** AWS (CloudTrail)  
**Analyst:** Arkaprava  
**Date:** 2025-03-21  

---

## 1. Executive Summary

IAM user `Batch2_Emp09` was observed modifying an existing IAM policy (`Resource_Access_Policy`) to include broad EC2 permissions — specifically `ec2:*` scoped to a specific instance ID. The user then leveraged this newly granted access to enumerate and subsequently **stop** that EC2 instance. This indicates deliberate privilege escalation followed by unauthorized infrastructure disruption.

**Business Impact:** A running EC2 instance (`i-0dbcce9ecac58d534`) was intentionally stopped. Any dependent services or workloads on this instance experienced downtime.

---

## 2. Scope and Objective

- **What was analyzed:** AWS CloudTrail logs via Elastic SIEM
- **Involved user:** `Batch2_Emp09` (IAMUser)
- **Source IP:** `36.255.87.0`, `36.255.87.2`
- **Modified policy:** `Resource_Access_Policy` (version V6)
- **Affected resource:** EC2 Instance `i-0dbcce9ecac58d534` (ap-south-1)
- **Objective:** Determine how the policy was modified and what actions were subsequently taken

---

## 3. Methodology

- **Tool:** Elastic SIEM (Discover) — `aws` data view
- **Log source:** `aws.cloudtrail`
- **Approach:** Queried `CreatePolicyVersion` events for IAM users, identified the modified policy document, then pivoted on the instance ID to reconstruct all actions taken by `Batch2_Emp09`

---

## 4. Detailed Analysis

### 4.1 Policy Modification

> 📸 *[Screenshot 6 — Elastic: CreatePolicyVersion by Batch2_Emp09, Resource_Access_Policy, ec2:* on instance i-0dbcce9ecac58d534]*

At `2025-01-30T10:26:22Z`, `Batch2_Emp09` called `CreatePolicyVersion` on `Resource_Access_Policy`, injecting two new permission statements and setting it as the **default version (V6)**:

```json
{
  "Effect": "Allow",
  "Action": "ec2:DescribeInstances",
  "Resource": "*"
},
{
  "Effect": "Allow",
  "Action": "ec2:*",
  "Resource": "arn:aws:ec2:ap-south-1:010928207857:instance/i-0dbcce9ecac58d534"
}
```

This granted full EC2 control over a specific instance — targeted and deliberate.

### 4.2 Full Activity Timeline of Batch2_Emp09

> 📸 *[Screenshot 7 — Elastic: Instance ID pivot — CreatePolicyVersion and StopInstances events]*

> 📸 *[Screenshot 8 — Elastic: All 5 events for Batch2_Emp09 — GetCallerIdentity, CreatePolicyVersion, DescribeInstances x2, StopInstances]*

| Timestamp (UTC) | Action | Outcome | Notes |
|---|---|---|---|
| 2025-01-30T10:24:06Z | GetCallerIdentity | Success | Session confirmed |
| 2025-01-30T10:24:40Z | DescribeInstances | **Failure** | No EC2 permission yet |
| 2025-01-30T10:26:22Z | CreatePolicyVersion | Success | Added `ec2:*` to policy |
| 2025-01-30T10:27:03Z | DescribeInstances | Success | Policy now active |
| 2025-01-30T10:28:58Z | StopInstances | Success | Instance stopped |

The sequence is unambiguous — the user modified the policy specifically to gain access, verified it worked, then disrupted the target instance.

### 4.3 TheHive Case Reference

> 📸 *[Screenshot 9 — TheHive Case #3 Task details — Investigation steps]*

> 📸 *[Screenshot 10 — TheHive Case #3 General — Unauthorized IAM Policy Modification, SEV:MEDIUM]*

Case `#3` was raised in TheHive with severity **MEDIUM**, tagged `AWS`, `IAM`, `Policy Modification`, `Privilege Escalation`. Time to detect: **approximately 1 hour**. Investigation tasks included identifying the modified policy, attributing the actor, assessing privileges granted, and examining post-modification actions.

---

## 5. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| IAM User | `Batch2_Emp09` |
| IAM ARN | `arn:aws:iam::010928207857:user/Batch2_Emp09` |
| Source IPs | `36.255.87.0`, `36.255.87.2` |
| Modified Policy | `arn:aws:iam::010928207857:policy/Resource_Access_Policy` |
| Policy Version | V6 (malicious, set as default) |
| Target Instance | `i-0dbcce9ecac58d534` (ap-south-1) |

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Privilege Escalation | Abuse Elevation Control Mechanism — IAM Policy | T1548 |
| Defense Evasion | Modify Cloud Compute Infrastructure | T1578 |
| Discovery | Cloud Infrastructure Discovery | T1580 |
| Impact | Service Stop | T1489 |

---

## 7. Findings

- `Batch2_Emp09` holds `iam:CreatePolicyVersion` — a highly sensitive permission that should be restricted to administrators only
- The initial `DescribeInstances` failure followed immediately by a policy modification confirms **deliberate, planned privilege escalation**
- The attacker knew the exact instance ID beforehand — suggesting prior reconnaissance or insider knowledge
- The detection time of approximately **1 hour** is too slow for this type of targeted infrastructure attack
- No change management record or approval exists for the policy version update

---

## 8. Impact Assessment

| Area | Detail |
|---|---|
| Disrupted Resource | EC2 instance `i-0dbcce9ecac58d534` — stopped |
| Modified Policy | `Resource_Access_Policy` — V6 now grants `ec2:*` on the instance |
| Compromised Identity | `Batch2_Emp09` |
| **Severity** | **MEDIUM** (infrastructure disruption, no confirmed data loss) |

---

## 9. Recommendations

- **Immediately** revert `Resource_Access_Policy` to the last approved version and disable V6
- Revoke `iam:CreatePolicyVersion` from `Batch2_Emp09` and all non-admin batch/service accounts
- Restart and audit EC2 instance `i-0dbcce9ecac58d534` for any changes made prior to its shutdown
- Implement **AWS Config** rules to alert on any new IAM policy version creation
- Enforce **IAM Access Analyzer** to continuously flag overly permissive policy changes
- Reduce detection time with a real-time CloudWatch alert on `CreatePolicyVersion` events from non-admin users

---

## 10. Conclusion

`Batch2_Emp09` exploited an overly permissive IAM configuration to modify an existing policy, inject EC2 control permissions targeting a specific instance, and then stop that instance. The attack was calculated — the user confirmed their lack of access, updated the policy, verified the new access, and acted within minutes. The root cause is a batch/non-admin account holding `iam:CreatePolicyVersion`, which is effectively a privilege escalation primitive in AWS.

---
*Report generated as part of multi-cloud blue team investigation lab — CyberWarFare Labs Module 5*
