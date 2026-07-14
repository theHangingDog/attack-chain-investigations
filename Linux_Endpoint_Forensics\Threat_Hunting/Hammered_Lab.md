---
date: 2026-07-04
platform: CyberDefenders
category: Endpoint Forensics
lab_name: Hammered Lab
source_url: https://cyberdefenders.org/blueteam-ctf-challenges/hammered/
difficulty: Easy
time_taken: 30 min
status: Completed
tags:
  - lab
mitre_techniques:
  -   T1078.001, T1110.001, T1136.001, T1046 , T1562.004, T1210
threat_actor: NA
---
# Hammered Lab

## Scenario
In this lab, we step into the role of a Security Operations Center (SOC) analyst tasked with investigating suspicious activity on a compromised web server. The challenge revolves around analyzing system logs, identifying unauthorized access, detecting attacker behavior, and uncovering security misconfigurations that may have facilitated the breach. By leveraging various Linux command-line tools, we will examine authentication logs, firewall configurations, network activity, and package installation records to reconstruct the attack timeline and determine the extent of the compromise.

The lab primarily focuses on endpoint forensics, requiring a deep dive into system logs to trace attacker movements. We will analyze SSH login attempts, detect brute-force attacks, investigate firewall rule modifications, and review database security warnings. Additionally, we will explore Apache access logs to identify potential web-based threats and determine how attackers interacted with the server. By following a structured forensic methodology, we will gather key insights into the attacker’s tactics, techniques, and procedures (TTPs), helping us strengthen future security defenses.

## Objective / Questions
- [x] Q1: Which service did the attackers use to gain access to the system? → **ssh**
- [x] Q2: What is the operating system version of the targeted system? (one word) → **4.2.4-1ubuntu3**
- [x] Q3: What is the name of the compromised account? → **root**
- [x] Q4: How many attackers, represented by unique IP addresses, were able to successfully access the system after initial failed attempts? → **6**
- [x] Q5: Which attacker's IP address successfully logged into the system the most number of times? → **219.150.161.20**
- [x] Q6: How many requests were sent to the Apache Server? → **365**
- [x] Q7: How many rules have been added to the firewall? → **6**
- [x] Q8: One of the downloaded files on the target system is a scanning tool. Provide the tool name. → **nmap**
- [x] Q9: When was the last login from the attacker with IP 219.150.161.20? Format: MM/DD/YYYY HH:MM:SS AM → **04/19/2010 05:56:05 AM**
- [x] Q10: The database displayed two warning messages, provide the most important and dangerous one. → **mysql.user contains 2 root accounts without password!**
- [x] Q11: Multiple accounts were created on the target system. Which one was created on Apr 26 04:43:15? → **wind3str0y**
- [x] Q12: Few attackers were using a proxy to run their scans. What is the corresponding user-agent used by this proxy? → **pycscand/2.1**

## Tools Used
- `grep`
- `awk`
- `sed`
- `sort`, `uniq`
- `wc -l`
- `comm`

## Analysis

### Initial Access / Entry Point
- Attackers gained access via SSH service (`auth.log` showed numerous `Failed password` attempts followed by `Accepted password` entries).
- Brute-force attacks targeted the `root` account, which was ultimately compromised.

### Execution / Actions Observed
- Successful SSH logins from multiple external IPs (especially `219.150.161.20`).
- Installation of `nmap` scanning tool (detected in `term.log` via `grep "Setting up" term.log`).
- Creation of new user accounts (e.g., `wind3str0y` on Apr 26).
- Firewall rules added using `iptables` to allow inbound traffic on non-standard ports.

### Persistence
- Added firewall rules allowed persistent access (ports 2244, 53, 113).
- Created a local user account (`wind3str0y`) with `/bin/bash` shell.
- MySQL had two root accounts without passwords – a clear backdoor.

### Privilege Escalation
- The `root` account was directly compromised via SSH brute force.
- MySQL root accounts without passwords could allow database-level privilege escalation.

### Defense Evasion
- Attackers used proxies (identifiable by `pycscand/2.1` user-agent) to obfuscate scanning activities.
- Added firewall rules to permit their own traffic and possibly block other connections.

### Lateral Movement
- Installation of `nmap` suggests intent to scan internal network for further targets.

### C2 / Exfiltration
- Firewall rules for DNS (port 53) and SSH on port 2244 may have been used for command-and-control or data exfiltration.

### Impact
- System fully compromised at root level.
- Database insecure with blank root passwords.
- Multiple attacker IPs gained access.

### Evidence Reviewed
- **Artifact:** `auth.log`
  **Finding:** Hundreds of failed SSH attempts, then successful root logins from various IPs.
  **Why it matters:** Confirms brute-force attack and compromise.

- **Artifact:** `kern.log`
  **Finding:** Shows kernel version `4.2.4-1ubuntu3`.
  **Why it matters:** Identifies OS version for vulnerability correlation.

- **Artifact:** `term.log` (APT log)
  **Finding:** `nmap` installed.
  **Why it matters:** Indicates attacker performing network reconnaissance.

- **Artifact:** `apache2/www-access.log`
  **Finding:** 365 requests; user-agent `pycscand/2.1` from proxy IP.
  **Why it matters:** Reveals scanning tool used via proxy.

- **Artifact:** Firewall logs (command history)
  **Finding:** 6 `iptables` rules added.
  **Why it matters:** Shows attacker modifying network access controls.

- **Artifact:** `auth.log` (useradd entries)
  **Finding:** User `wind3str0y` created.
  **Why it matters:** Evidence of persistence via new account.

- **Artifact:** MySQL error logs (warnings)
  **Finding:** `mysql.user contains 2 root accounts without password!`
  **Why it matters:** Critical database misconfiguration enabling unauthorized access.

## Timeline
| Time (UTC) | Event | Source |
|---|---|---|
| Prior to Apr 19 | Repeated failed SSH attempts from multiple IPs | auth.log |
| Apr 19 05:56:05 | Last successful login from `219.150.161.20` | auth.log |
| Around Apr 19 | Firewall rules added (iptables) | command history |
| Apr 26 04:43:15 | User `wind3str0y` created | auth.log |
| Unknown | `nmap` installed | term.log |
| Unknown | Apache logs show 365 requests, some from proxy with `pycscand/2.1` | www-access.log |
| Unknown | MySQL warnings about blank root passwords | mysql logs |

## Threat Actor / Attribution
- **Group / Campaign:** Unknown; multiple external IPs acting in coordination.
- **Confidence:** Medium – based on IP addresses (may be compromised machines or proxies).
- **Basis for attribution:** Use of common brute-force tools, `nmap`, and proxy scanning; no specific threat group identified.

## Indicators / Artifacts

### Network
- `219.150.161.20` (most frequent successful logins)
- Other IPs that successfully logged in (6 total, see analysis)
- Proxy IPs (e.g., `193.109.122.x` associated with `pycscand/2.1`)

### Host
- `nmap` (package installed)
- `wind3str0y` (local user)
- Firewall rules added:
  - `-A INPUT -p ssh --dport 2424 -j ACCEPT`
  - `-A INPUT -p tcp --dport 53 -j ACCEPT`
  - `-A INPUT -p udp --dport 53 -j ACCEPT`
  - `-A INPUT -p tcp --dport ssh -j ACCEPT`
  - `-A INPUT -p ssh --dport 53 -j ACCEPT`
  - `-A INPUT -p tcp --dport 113 -j ACCEPT`

### Cloud
- N/A

### Actor Infrastructure
- Proxy servers (IPs not fully disclosed) using `pycscand/2.1`

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|---|---|---|
| Initial Access | SSH Brute Force | T1110.001 |
| Initial Access | Valid Accounts (root) | T1078.001 |
| Persistence | Create Account (local) | T1136.001 |
| Discovery | Network Scanning (nmap) | T1046 |
| Defense Evasion | Impair Defenses (firewall modifications) | T1562.004 |
| Credential Access | Unsecured Credentials (MySQL blank root) | T1552.001? |
| Lateral Movement | Internal Reconnaissance via nmap | T1046 |

## Detection Opportunities
```kql
// Example: Detect multiple failed logins followed by success from same IP
let threshold = 10;
auth_log
| where event_type == "Failed"
| summarize Failures = count() by src_ip
| where Failures > threshold
| join kind=inner (auth_log | where event_type == "Success" | summarize Successes = count() by src_ip) on src_ip
| where Successes > 0
```
## Answers / Flags

|Question|Answer|
|---|---|
|Q1|ssh|
|Q2|4.2.4-1ubuntu3|
|Q3|root|
|Q4|6|
|Q5|219.150.161.20|
|Q6|365|
|Q7|6|
|Q8|nmap|
|Q9|04/19/2010 05:56:05 AM|
|Q10|mysql.user contains 2 root accounts without password!|
|Q11|wind3str0y|
|Q12|pycscand/2.1|

## Key Takeaways

- **SSH brute-force attacks** remain a primary vector; disable root login and enforce key-based authentication.
- **Firewall misconfigurations** can be exploited to maintain persistence; audit rules frequently.
- **System logs** (`auth.log`, `kern.log`, `term.log`, `www-access.log`) are invaluable for incident response.
- **Database security** is often overlooked; ensure all accounts have strong passwords.
- **User-agent strings** can reveal automated tools; monitor for uncommon agents.
- **Post-compromise actions** (user creation, tool installation) provide clear indicators of attacker intent.
## References

- Linux system log analysis (grep, awk, sed)
- MITRE ATT&CK framework
- Apache log format
- MySQL security best practices
