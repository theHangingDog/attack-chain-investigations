# Incident Investigation Report
**Report ID:** INC-2025-002  
**Classification:** TLP:AMBER | PAP:AMBER  
**Severity:** CRITICAL  
**Platform:** AWS (CloudTrail)  
**Analyst:** Arkaprava  
**Date:** 2025-03-21  

---

## 1. Executive Summary

IAM user `dev_pipeline_user_07` was observed creating a custom IAM role (`EC2Role`), attaching the `AmazonS3ReadOnlyAccess` managed policy to it, and then associating it with an EC2 instance profile — all without any authorization record. The activity follows a privilege escalation pattern where an attacker or insider abuses IAM permissions to grant persistent, elevated cloud access to a compute resource.

**Business Impact:** An EC2 instance now holds S3 read access via an unauthorized role. Any code or process running on that instance can silently read from S3 buckets, leading to potential data exposure.

---

## 2. Scope and Objective

- **What was analyzed:** AWS CloudTrail logs via Elastic SIEM
- **Involved user:** `dev_pipeline_user_07`
- **Source IPs:** `36.255.87.2`, `36.255.87.6`
- **Resources created:** IAM Role (`EC2Role`), Instance Profile (`EC2InstanceProfile`)
- **Policy attached:** `arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess`
- **Objective:** Trace the full chain of unauthorized IAM provisioning and assess intent

---

## 3. Methodology

- **Tool:** Elastic SIEM (Discover) — `aws` data view
- **Log source:** `aws.cloudtrail`
- **Approach:** Queried for `CreateInstanceProfile`, `AddRoleToInstanceProfile`, `AttachRolePolicy`, `CreateRole` events tied to `dev_pipeline_user_07`. Events were correlated chronologically to reconstruct the full provisioning chain.

---

## 4. Detailed Analysis

### 4.1 Role Creation

![Alt text](<../images/aws/suspicious iam instance profile creation/Screenshot 2026-03-20 184011.png>)
At `2025-01-31T07:34:06Z`, `dev_pipeline_user_07` created an IAM role named `EC2Role` from IP `36.255.87.6`. The trust policy was configured to allow `ec2.amazonaws.com` to perform `sts:AssumeRole` — meaning any EC2 instance can assume this role automatically at launch.

```json
{
  "Effect": "Allow",
  "Principal": { "Service": "ec2.amazonaws.com" },
  "Action": "sts:AssumeRole"
}
```

### 4.2 Policy Attachment

![Alt text](<../images/aws/suspicious iam instance profile creation/Screenshot 2026-03-20 183124.png>)

At `2025-01-31T07:40:02Z`, the managed policy `AmazonS3ReadOnlyAccess` was attached to `EC2Role` from IP `36.255.87.2`. This grants any EC2 instance using this role full read access to all S3 buckets in the account.

| Timestamp (UTC) | Action | Role | Policy | Outcome |
|---|---|---|---|---|
| 2025-01-31T07:34:06Z | CreateRole | EC2Role | — | Success |
| 2025-01-31T07:40:02Z | AttachRolePolicy | EC2Role | AmazonS3ReadOnlyAccess | Success |

### 4.3 Instance Profile Creation and Role Assignment

![Alt text](<../images/aws/suspicious iam instance profile creation/Screenshot 2026-03-20 182531.png>)
![Alt text](<../images/aws/suspicious iam instance profile creation/Screenshot 2026-03-20 183124.png>)

At `2025-01-31T07:41:14Z`, an instance profile named `EC2InstanceProfile` was created. Shortly after, `dev_pipeline_user_07` attempted to attach `MyEC2Role` to the profile (which **failed**), then successfully attached `EC2Role` at `07:43:27Z`.

| Timestamp (UTC) | Action | Instance Profile | Role | Outcome |
|---|---|---|---|---|
| 2025-01-31T07:41:14Z | CreateInstanceProfile | EC2InstanceProfile | — | Success |
| 2025-01-31T07:43:19Z | AddRoleToInstanceProfile | EC2InstanceProfile | MyEC2Role | **Failure** |
| 2025-01-31T07:43:27Z | AddRoleToInstanceProfile | EC2InstanceProfile | EC2Role | Success |

The failed first attempt with `MyEC2Role` suggests the actor tried an existing role first before falling back to the one they just created.

### 4.4 TheHive Case Reference

![Alt text](<../images/aws/suspicious iam instance profile creation/Screenshot 2026-03-20 184426.png>)
Case `#2` was created in TheHive with severity **CRITICAL**, tagged `AWS`, `EC2`, `Privilege Escalation`. Detection time: **29 seconds**. Investigation tasks included tracing instance profile creation, role assignment, policy analysis, and AttachRolePolicy review.

---

## 5. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| IAM User | `dev_pipeline_user_07` |
| Source IPs | `36.255.87.2`, `36.255.87.6` |
| Created Role | `EC2Role` |
| Instance Profile | `EC2InstanceProfile` |
| Policy Attached | `arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess` |
| IAM ARN | `arn:aws:iam::010928207857:user/dev_pipeline_user_07` |

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Privilege Escalation | Abuse Elevation Control Mechanism — Cloud Accounts | T1548 |
| Persistence | Account Manipulation — Additional Cloud Credentials | T1098.001 |
| Defense Evasion | Use Alternate Authentication Material | T1550 |
| Discovery | Cloud Storage Object Discovery (S3 via role) | T1619 |

---

## 7. Findings

- `dev_pipeline_user_07` has IAM write permissions that should not be held by a pipeline/service account
- The role creation, policy attachment, and profile association all happened within a **9-minute window** — indicating scripted or planned execution
- The first `AddRoleToInstanceProfile` failure suggests the attacker attempted to reuse an existing role (`MyEC2Role`) before creating their own
- No approval workflow or change management record exists for these IAM changes
- `AmazonS3ReadOnlyAccess` is a broad managed policy — grants read access to **all** S3 buckets in the account

---

## 8. Impact Assessment

| Area | Detail |
|---|---|
| Affected Resource | EC2 instance with `EC2InstanceProfile` attached |
| Access Granted | Read access to all S3 buckets in account |
| Compromised Identity | `dev_pipeline_user_07` |
| **Severity** | **CRITICAL** |

---

## 9. Recommendations

- **Immediately** revoke `dev_pipeline_user_07`'s IAM write permissions and audit all actions taken by this user
- Remove `EC2InstanceProfile` and detach `EC2Role` from any active EC2 instances
- Enforce **IAM permission boundaries** on service/pipeline accounts — they should never have `iam:CreateRole`, `iam:AttachRolePolicy`, or `iam:CreateInstanceProfile`
- Implement **AWS Config rules** to alert on `CreateRole` and `AttachRolePolicy` events from non-admin users
- Use **AWS SCPs** to restrict IAM write operations to designated admin roles only
- Enable CloudTrail alerts for any `iam:*` actions from CI/CD pipeline identities

---

## 10. Conclusion

User `dev_pipeline_user_07` — likely a compromised CI/CD or developer account — systematically created an IAM role, attached a broad S3 policy, and linked it to an EC2 instance profile within a 9-minute window. The chain of actions is consistent with a privilege escalation technique where an attacker plants a backdoor role on a compute resource to maintain persistent, covert access to cloud storage. The root cause is excessive IAM permissions granted to a non-admin pipeline account.

---
*Report generated as part of multi-cloud blue team investigation lab — CyberWarFare Labs Module 5*
