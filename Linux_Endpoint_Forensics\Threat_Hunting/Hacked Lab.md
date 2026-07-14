---
date: 2026-07-04
platform: CyberDefenders
category: Endpoint Forensics
lab_name: CyberDefenders
source_url: https://cyberdefenders.org/blueteam-ctf-challenges/hacked/
difficulty: Medium
time_taken: 1 hour
status: Completed
tags:
  - lab
mitre_techniques:
  - Below mentioned
threat_actor: NA
---

# Hacked Lab

## Scenario
> Paste the brief/prompt exactly as given.

## Objective / Questions
- [x] Q1: What is the system timezone?
- [x] Q2: Who was the last user to log in to the system?
- [x] Q3: What was the source port the user 'mail' connected from?
- [x] Q4: How long was the last session for user 'mail'? (Minutes only)
- [x] Q5: Which server service did the last user use to log in to the system?
- [x] Q6: What type of authentication attack was performed against the target machine?
- [x] Q7: How many IP addresses are listed in the '/var/log/lastlog' file?
- [x] Q8: How many users have a login shell?
- [x] Q9: What is the password of the mail user?
- [x] Q10: Which user account was created by the attacker?
- [x] Q11: How many user groups exist on the machine?
- [x] Q12: How many users have sudo access?
- [x] Q13: What is the home directory of the PHP user?
- [x] Q14: What command did the attacker use to gain root privilege?
- [x] Q15: Which file did the user 'root' delete?
- [x] Q16: Recover the deleted file, open it and extract the exploit author name.
- [x] Q17: What is the content management system (CMS) installed on the machine?
- [x] Q18: What is the version of the CMS installed on the machine?
- [x] Q19: Which port was listening to receive the attacker's reverse shell?


## Tools Used
- FTK Imager (for disk image mounting)
- Linux native commands (cat, grep, tail, less)
- John the Ripper with rockyou.txt
- unshadow utility
- Disk Drill / TestDisk (file recovery)
- Text editor (bootstrap.inc analysis)
## Analysis
### Initial Access / Entry Point

**Finding:** The attacker gained initial access via SSH brute-force attack against the root account from IP 192.168.210.131.

**Evidence:**

- `/var/log/auth.log` shows a massive amount of failed password attempts for `root`:
    
    `Oct  5 12:42:33 VulnOSv2 sshd[1838]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.210.131  user=root`
    `Oct  5 12:42:35 VulnOSv2 sshd[1838]: Failed password for root from 192.168.210.131 port 57200 ssh2`
    
- Multiple simultaneous SSH connections were attempted, exceeding the maximum authentication attempts threshold (6 > 3), indicating a brute-force tool was used.
    
- The attack was successful when `root` logged in:
    `May  2 18:57:11 VulnOSv2 sshd[1454]: Accepted password for root from 192.168.210.131 port 57210 ssh2`
    

**Why it matters:** The brute-force attack against `root` was the initial vector that allowed the attacker to gain a foothold on the system.

### Execution / Actions Observed

**Finding:** After gaining access, the attacker performed reconnaissance and established persistence by creating a new user account.

**Evidence:**

- The attacker checked system information:
    
    `May  2 18:51:47 VulnOSv2 sudo: vulnosadmin : TTY=pts/0 ; PWD=/etc/ssh ; USER=root ; COMMAND=/bin/bash`
    
- Password for `root` was changed:
    
    `May  2 18:54:20 VulnOSv2 passwd[1501]: pam_unix(passwd:chauthtok): password changed for root`
    
- A new user `php` was created:
    
    `Oct  5 13:06:38 VulnOSv2 sudo: root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/sbin/useradd -d /usr/php -m --system --shell /bin/bash --skel /etc/skel -G sudo php`
    

**Why it matters:** The attacker moved quickly to establish persistence by creating a new user (`php`) with sudo access and modifying the root password.

---

### Persistence

**Finding:** The attacker created a new user (`php`), added it to the sudo group, and later compromised the `mail` user to maintain access.

**Evidence:**

- User `php` was created with sudo privileges:
    
    `Oct  5 13:06:38 VulnOSv2 useradd[2525]: add 'php' to group 'sudo'`
    
- The `mail` user was modified to have a login shell and sudo access:
    
    `Oct  5 13:08:31 VulnOSv2 chsh[2536]: changed user 'mail' shell to '/bin/bash'
    `Oct  5 13:09:18 VulnOSv2 usermod[2561]: add 'mail' to group 'sudo'
    
- Password for `mail` was set to "forensics" (cracked using John the Ripper).
    

**Why it matters:** The attacker created multiple persistence mechanisms:

1. A new user (`php`) with system privileges
2. Compromised an existing user (`mail`) and gave it sudo access
3. Changed the root password
 
---

### Privilege Escalation

**Finding:** The attacker used `sudo su -` to gain root privileges after logging in as `mail`.

**Evidence:**

- In `/var/log/auth.log`:
    
    `Oct  5 13:14:04 VulnOSv2 sudo: mail : TTY=pts/1 ; PWD=/var/mail ; USER=root ; COMMAND=/bin/su -`
    `Oct  5 13:14:04 VulnOSv2 su[2721]: Successful su for root by root`
    
- The command `sudo su -` was used multiple times across different sessions:

    `Oct  5 13:19:21 VulnOSv2 sudo: mail : TTY=pts/1 ; PWD=/var/mail ; USER=root ; COMMAND=/bin/su -`
    `Oct  5 13:21:11 VulnOSv2 sudo: mail : TTY=pts/1 ; PWD=/var/mail ; USER=root ; COMMAND=/bin/su -`

**Why it matters:** `sudo su -` is a classic privilege escalation technique that allows a user with sudo rights to switch to the root user.

---

### Defense Evasion

**Finding:** The attacker deleted an exploit file (`37292.c`) and attempted to cover tracks by using backdoor scripts.

**Evidence:**

- The root user's `.bash_history` shows deletion:
    
    `Oct  5 13:23:34 ... COMMAND=/usr/bin/rm 37292.c`
    
- Exploit code in `37292.c` (recovered) contained the author name "rebel".
    
- The attacker attempted to access `/jabc/scripts/update.php?cmd=ls` to execute commands:
    
    `[Sat Oct 05 13:17:48.483527 2019] [:error] [pid 1789] [client 192.168.210.131:41888] PHP Notice:  Undefined index: cmd in /var/www/html/jabc/scripts/update.php on line 2`
    

**Why it matters:** The attacker attempted to use a backdoor script (`update.php`) for command execution and deleted evidence of the exploit tool used.

---

### Lateral Movement

No evidence of lateral movement was observed. The attacker remained on the single compromised host.

---

### C2 / Exfiltration

**Finding:** The attacker set up a reverse shell listener on port 4444.

**Evidence:**

- Decoding the Base64 payload found in `/var/log/apache2/access.log` reveals the reverse shell configuration:
    
    - The encoded payload shows the attacker's IP as `192.168.210.131` and port `4444`
    - The payload includes a full reverse shell implementation using socket streams

**Why it matters:** The attacker prepared for remote command execution by establishing a reverse shell listener on port 4444, allowing them to maintain interactive access to the compromised system.

---

### Impact

- **System compromise:** The attacker had root-level access to the server.
- **User accounts compromised:** `mail` user credentials were cracked and elevated.
- **New user created:** `php` user was added with sudo privileges.
- **Web application exposed:** Drupal 7.26 was installed and accessible.
- **Backdoor established:** The `update.php` script could be used for arbitrary command execution.
- **Data exfiltration possible:** With root access, the attacker could exfiltrate any data on the system.

---

### Evidence Reviewed

- **Artifact:** `/var/log/auth.log`  
    **Finding:** Massive brute-force attempts followed by successful root login, new user creation, and sudo abuse.  
    **Why it matters:** This is the primary source for reconstructing the attack timeline and identifying the attacker's actions.

- **Artifact:** `/var/log/apache2/access.log`  
    **Finding:** Contains Base64-encoded reverse shell payload with IP 192.168.210.131 and port 4444.  
    **Why it matters:** Reveals the attacker's intended C2 infrastructure and confirms the reverse shell strategy.

- **Artifact:** `/var/www/html/jabc/includes/bootstrap.inc`  
    **Finding:** Line: `define('VERSION', '7.26');`  
    **Why it matters:** Confirms the Drupal version, which may have known vulnerabilities that were exploited.

- **Artifact:** `/etc/shadow` and `/etc/passwd` (unshadowed)  
    **Finding:** `mail:$6$G/CEd0XL$C8TIdJAPK/u/5VU9NByTAd4VgKj26SZD6g2RcVWU6ckFko2lK8g14h3hAbhKxVJbRGogQIHN6Vk7cTYBJJ8R/.:17000:0:99999:7:::`  
    **Why it matters:** This hash was cracked to reveal the password "forensics".

## ## Timeline

|Time (UTC)|Event|Source|
|---|---|---|
|Oct 5 12:39:27|First failed SSH attempt from 192.168.210.131|auth.log|
|Oct 5 12:42-12:47|Aggressive SSH brute-force attack (multiple concurrent connections)|auth.log|
|Oct 5 13:06:38|Attacker creates `php` user with sudo access|auth.log|
|Oct 5 13:08:31|Attacker changes `mail` user shell to /bin/bash|auth.log|
|Oct 5 13:09:18|Attacker adds `mail` user to sudo group|auth.log|
|Oct 5 13:09:03|`mail` user password set|auth.log|
|Oct 5 13:13:53|`mail` user logs in via SSH from port 57708|auth.log|
|Oct 5 13:14:04|Attacker uses `sudo su -` to gain root|auth.log|
|Oct 5 13:17:48|Backdoor script executed (`update.php?cmd=ls`)|error.log|
|Oct 5 13:23:34|Final `mail` user login and root escalation|auth.log|


## Threat Actor / Attribution

- **Group / Campaign:** Unknown
- **Confidence:** Low
- **Basis for attribution:** No specific threat actor group could be definitively identified. The attack appears opportunistic, targeting a vulnerable Linux web server.

## Indicators / Artifacts

### Network

- Source IP: `192.168.210.131`
- Source ports: `57200`, `57208`, `57210`, `57708`, etc. (multiple connections)
- Target port: 22 (SSH)
- Reverse shell port: 4444

### Host

- `/var/log/auth.log` - Contains attack evidence
- `/var/log/apache2/access.log` - Contains reverse shell payload
- `/var/www/html/jabc/includes/bootstrap.inc` - Drupal version information
- `/var/www/html/jabc/scripts/update.php` - Backdoor script
- `/tmp/37292.c` - Deleted exploit file (author: "rebel")


### Cloud

- N/A
### Actor Infrastructure

- IP: `192.168.210.131` (source of attack)

## MITRE ATT&CK Mapping

|Tactic|Technique|ID|
|---|---|---|
|Initial Access|SSH Brute Force|T1110|
|Persistence|Create Account|T1136|
|Persistence|Modify Existing Account|T1098|
|Privilege Escalation|Sudo and SU|T1548|
|Defense Evasion|Indicator Removal|T1070|
|Defense Evasion|File Deletion|T1070.004|
|Command and Control|Standard Protocol (SSH)|T1071|
|Command and Control|Reverse Shell|T1071.001|
|Credential Access|Brute Force|T1110|
|Credential Access|Password Cracking|T1110.002|


## Detection Opportunities
```kql
// Detect failed SSH login attempts (potential brute force)
// Look for spikes in failed attempts from a single IP
// Log Source: auth.log
grep "Failed password" /var/log/auth.log | sort | uniq -c | sort -nr

// Detect new user creation by non-standard processes
// Log Source: auth.log
grep "useradd" /var/log/auth.log

// Detect user modifications (shell, groups)
// Log Source: auth.log
grep -E "chsh|usermod|passwd" /var/log/auth.log

// Detect sudo usage by non-admin users
// Log Source: auth.log
grep "sudo" /var/log/auth.log | grep -v "vulnosadmin"

// Detect web shell execution attempts
// Log Source: access.log / error.log
grep "update.php" /var/log/apache2/access.log
grep "cmd=" /var/log/apache2/access.log
```

## ## Answers / Flags

|Question|Answer|
|---|---|
|Q1: System timezone|Europe/Brussels|
|Q2: Last user to log in|mail|
|Q3: Source port for 'mail'|57708|
|Q4: Last session duration for 'mail'|1|
|Q5: Server service for login|sshd|
|Q6: Type of authentication attack|brute-force|
|Q7: IP addresses in lastlog|2|
|Q8: Users with login shell|5|
|Q9: Password of mail user|forensics|
|Q10: User account created by attacker|php|
|Q11: Number of user groups|58|
|Q12: Users with sudo access|2|
|Q13: Home directory of PHP user|/usr/php|
|Q14: Command to gain root privilege|sudo su -|
|Q15: File deleted by root|37292.c|
|Q16: Exploit author name|rebel|
|Q17: CMS installed|drupal|
|Q18: CMS version|7.26|
|Q19: Reverse shell port|4444|


## Key Takeaways
1. **SSH Brute Force** remains a common and effective initial access vector. Proper authentication controls (fail2ban, rate limiting, key-based auth) are critical.

2. **User Account Persistence** is a primary technique used by attackers. The creation of `php` and modification of `mail` are classic examples of establishing persistence.

3. **Sudo Privileges** should be carefully managed. The attacker exploited sudo access to escalate to root using `sudo su -`.

4. **Web Application Backdoors** can be hidden in legitimate scripts. `update.php` was used as a command execution vector.

5. **Log Analysis** is essential for reconstructing attacks. `auth.log`, `access.log`, and `error.log` provided the complete attack timeline.

6. **File Recovery** can reveal deleted evidence. `37292.c` was recovered and revealed the exploit author.

7. **Password Hygiene** is critical. The `mail` user password "forensics" was easily cracked with John the Ripper.

8. **Drupal Vulnerability** exposure: Version 7.26 may have known vulnerabilities that contributed to the initial compromise.

9. **Reverse Shell Detection**: The Base64-encoded payload in `access.log` demonstrated command-and-control preparation.

10. **System Hardening**: The system lacked adequate protection against brute force, had weak password policies, and insufficient monitoring.

## References
## References

- MITRE ATT&CK Framework: [https://attack.mitre.org/](https://attack.mitre.org/
- CyberDefenders Hacked Lab: [https://cyberdefenders.org/](https://cyberdefenders.org/)
- John the Ripper Password Cracker: [https://www.openwall.com/john/](https://www.openwall.com/john/)
- Drupal Security Advisories: [https://www.drupal.org/security](https://www.drupal.org/security)
