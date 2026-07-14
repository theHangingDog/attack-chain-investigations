---
date: 2026-07-04
platform: CyberDefenders
category: Endpoint Forensics
lab_name: Insider Lab
source_url: https://cyberdefenders.org/blueteam-ctf-challenges/insider/
difficulty: Easy
time_taken: 30 min
status: Completed
tags:
  - lab
mitre_techniques:
  - T1059.004,T1003, T1074
threat_actor: NA
---
# Scenario
Analyze Linux disk image artifacts, including logs and Bash history, using FTK Imager to investigate insider threat activities and reconstruct user actions.

# Objective / Questions
- [x] Q1: Which Linux distribution is being used on this machine?
- [x] Q2: What is the MD5 hash of the Apache access.log file?
- [x] Q3: It is suspected that a credential dumping tool was downloaded. What is the name of the downloaded file?
- [x] Q4: A super-secret file was created. What is the absolute path to this file?
- [x] Q5: What program used the file didyouthinkwedmakeiteasy.jpg during its execution?
- [x] Q6: What is the third goal from the checklist Karen created?
- [x] Q7: How many times was Apache run?
- [x] Q8: This machine was used to launch an attack on another. Which file contains the evidence for this?
- [x] Q9: It is believed that Karen was taunting a fellow computer expert through a bash script within the Documents directory. Who was the expert that Karen was taunting?
- [x] Q10: A user executed the su command to gain root access multiple times at 11:26. Who was the user?
- [x] Q11: Based on the bash history, what is the current working directory?

# Tools Used
- FTK Imager
- Linux Command Line (for hash calculation and log analysis)
- Text Editor / Hex Editor

# Analysis

## Initial Access / Entry Point
- The threat actor, Karen, operated primarily as the `root` user on a Kali Linux system.
- Evidence of GUI login via GDM (`gdm-password` sessions observed in `auth.log`).
- The hostname of the compromised machine is `KarenHacker`.

## Execution / Actions Observed
- Karen created and executed bash scripts (`hellworld.sh`, `firstscript`, `firstscript_fixed`) in `/root/Documents/myfirsthack/`.
- Used the `binwalk` tool to analyze an image file (`didyouthinkwedmakeiteasy.jpg`).
- Downloaded a credential dumping tool (`mimikatz_trunk.zip`) to the `/root/Downloads` directory.
- Created a super-secret file on the Desktop.
- Attempted to use `apt` to install a non-existent package `moo` (likely testing command-line skills or an easter egg).
- Taunted a user named "Young" via a bash script.

## Persistence
- No explicit malicious persistence mechanisms (like rogue cronjobs) were observed in the provided bash history, though standard system cronjobs ran frequently in the background.

## Privilege Escalation
- The user operated primarily as `root`.
- At `11:26` on Mar 20, multiple `su` commands were executed. The `auth.log` indicates `Successful su for postgres by root`, meaning the `root` user switched to the `postgres` user account.

## Defense Evasion
- Frequent use of the `clear` command in bash history to hide tracks.
- Creation and immediate deletion of a file named `delete-me.txt`.

## Lateral Movement
- An image file (`irZLAohL.jpeg`) found in the root directory contains visual evidence of an attack launched against another machine (shows a command prompt with elevated privileges).

## C2 / Exfiltration
- Creation of `SuperSecretFile.txt` and `keys.txt` might indicate staging for data exfiltration.

## Impact
- Potential compromise of credentials via the downloaded `mimikatz_trunk.zip`.
- Evidence of an attack launched against an external target from this machine.

# Evidence Reviewed
- **Artifact:** `/var/log/auth.log`
  - **Finding:** GDM login sessions, `su` command executions to `postgres`, and system reboots.
  - **Why it matters:** Establishes user activity, privilege switching, and system timeline.
- **Artifact:** `/root/.bash_history`
  - **Finding:** Commands revealing file creation, script execution, tool usage (`binwalk`), and directory navigation.
  - **Why it matters:** Directly shows the threat actor's intent, actions, and current working directory.
- **Artifact:** `/var/log/apache2/`
  - **Finding:** Log files exist but are exactly 0 bytes in size.
  - **Why it matters:** Proves Apache was installed/configured but never actually run or received traffic.
- **Artifact:** `/root/Desktop/` & `/root/Downloads/`
  - **Finding:** `SuperSecretFile.txt`, `Checklist`, `mimikatz_trunk.zip`.
  - **Why it matters:** Highlights the actor's goals, motives, and malicious tool acquisition.


# Threat Actor / Attribution
- **Group / Campaign:** Insider Threat (Karen)
- **Confidence:** High
- **Basis for attribution:** Bash history and desktop files (`Checklist`) explicitly name "Karen" and outline her goals. Hostname is explicitly set to `KarenHacker`.

# Indicators / Artifacts
## Network
- N/A (No network pcap provided, but Apache logs indicate port 80/443 was potentially configured).

## Host
- `/root/Downloads/mimikatz_trunk.zip`
- `/root/Desktop/SuperSecretFile.txt`
- `/root/Desktop/Checklist`
- `/root/Documents/myfirsthack/firstscript_fixed`
- `/root/irZLAohL.jpeg`
- `/root/didyouthinkwedmakeiteasy.jpg`

## Cloud
- N/A

## Actor Infrastructure
- Local Linux workstation (Kali), hostname `KarenHacker`.

# MITRE ATT&CK Mapping
| Tactic | Technique | ID |
| --- | --- | --- |
| Credential Access | OS Credential Dumping | T1003 |
| Execution | Command and Scripting Interpreter: Bash | T1059.004 |
| Discovery | System Information Discovery | T1082 |
| Collection | Data Staged | T1074 |

# Detection Opportunities
- Monitor for the download of known Windows/Linux credential dumping tools (e.g., Mimikatz) in Linux environments.
- Alert on unusual `su` or `sudo` activity, especially switching to service accounts like `postgres`.
- Monitor for the creation of suspicious files on the Desktop or in user directories (e.g., `SuperSecretFile.txt`, `keys.txt`).
- Track the execution of steganography or binary analysis tools like `binwalk` on image files.

# Answers / Flags
| Question | Answer |
| --- | --- |
| Q1: Linux distribution | kali |
| Q2: MD5 hash of Apache access.log | D41D8CD98F00B204E9800998ECF8427E |
| Q3: Credential dumping tool downloaded | mimikatz_trunk.zip |
| Q4: Absolute path to super-secret file | /root/Desktop/SuperSecretFile.txt |
| Q5: Program used on didyouthinkwedmakeiteasy.jpg | binwalk |
| Q6: Third goal from Karen's checklist | profit |
| Q7: How many times was Apache run? | 0 |
| Q8: File containing evidence of attack | irZLAohL.jpeg |
| Q9: Expert Karen was taunting | Young |
| Q10: User from su command at 11:26 | postgres |
| Q11: Current working directory | /root/Documents/myfirsthack/ |

# Key Takeaways
- Bash history and desktop artifacts are goldmines for understanding an insider threat's mindset, goals, and actions.
- Empty log files can be just as informative as populated ones (proving a service was never used, yielding the MD5 hash of an empty file: `d41d8cd98f00b204e9800998ecf8427e`).
- Threat actors often leave behind taunts or checklists that provide direct insight into their motives.
- Always verify the context of `su` logs; `Successful su for postgres by root` indicates the target user being accessed.

# References
- FTK Imager Documentation
- MITRE ATT&CK Framework
- Linux System Administration and Logging (`/var/log/auth.log`, `~/.bash_history`)
