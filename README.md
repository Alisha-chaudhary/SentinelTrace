# SOC Detection Lab: Attack Simulation to Detection Engineering

A self-built SOC environment in which a simulated attack against a Windows endpoint is captured with Sysmon, forwarded to Splunk, and investigated using custom SPL detections mapped to MITRE ATT&CK.

**Attacker action → endpoint telemetry → SIEM ingestion → detection engineering → ATT&CK-aligned investigation**

---

## Summary

I built a small SOC lab with a Kali attacker VM and a Windows target VM, then ran a controlled attack against the Windows endpoint (reconnaissance, SMB enumeration, an authentication attempt, PowerShell execution, and persistence via a scheduled task). Endpoint activity was captured with Sysmon, configured using Olaf Hartong's modular ruleset, and forwarded to Splunk for investigation. I wrote and tuned SPL searches against the resulting telemetry, working directly with raw Sysmon XML where Splunk did not auto-extract the fields I expected, and mapped the observed behaviors to MITRE ATT&CK where applicable. I also documented a telemetry gap I ran into with Windows Firewall log ingestion rather than leaving it out.

---

## Architecture

```
                         SIMULATED ATTACK
                              |
                              v
                       +-------------+
                       | Kali Linux  |
                       |  ATTACKER   |
                       +------+------+
                              |
                 Recon / SMB / Auth attempts
                              |
                              v
                    +--------------------+
                    |    WINDOWS VM      |
                    |     TARGET         |
                    |                    |
                    | Firewall logging   |
                    | Sysmon (Hartong    |
                    |  modular config)   |
                    +---------+----------+
                              |
                    Endpoint telemetry
                              |
                              v
                  +-----------------------+
                  | Splunk Universal      |
                  |    Forwarder          |
                  +-----------+-----------+
                              |
                              v
                  +-----------------------+
                  | Splunk Enterprise     |
                  |       SIEM            |
                  +-----------+-----------+
                              |
                        Raw XML / SPL
                              |
                              v
                 +------------------------+
                 | Detection engineering  |
                 |                        |
                 | - Data validation      |
                 | - Field analysis       |
                 | - SPL development      |
                 | - Tuning               |
                 | - Investigation        |
                 +-----------+------------+
                              |
                              v
                       MITRE ATT&CK
                    behavioral alignment
```

The Windows VM had two separate networking responsibilities: an attack path (Kali to Windows) and a telemetry path (Windows to Splunk). Getting attacker connectivity working without breaking the telemetry path was itself one of the early engineering problems in the project.

---

## Why Sysmon, and why Olaf Hartong's config specifically

Network telemetry alone only shows what an attacker sent, not what happened on the endpoint afterward. Sysmon was chosen to get endpoint-level visibility (process creation, image loads, file and registry activity) so the investigation could follow the attack past the network layer.

For the configuration itself, I used [Olaf Hartong's sysmon-modular](https://github.com/olafhartong/sysmon-modular) ruleset rather than a generic Sysmon XML for three reasons:

- It's built modularly, which made it easier to reason about and maintain rather than treating Sysmon as a black box.
- It's tuned to avoid the "log everything" trap. The more verbose configurations in that repo are explicitly documented as research-grade and not meant to be dropped into production as-is, which matched my goal of getting useful signal without flooding the lab with noise on 8GB of RAM.
- It ties configuration choices to MITRE ATT&CK, treating specific event types as potential detection-relevant sources for specific techniques rather than claiming any single event "detects" a technique outright. That framing matched how I wanted to structure my own detections.

---

## Attack narrative

### 1. Reconnaissance

Kali scanned the Windows host across common service ports:

```
nmap -Pn -T2 -p 135,139,445,3389,5985,22,80,443 192.168.1.44
```

Only one port came back open:

```
445/tcp open  microsoft-ds
```

Everything else (22, 80, 135, 139, 443, 3389, 5985) returned filtered. That single open port was the decision point for the rest of the attack: SMB was the only exposed service, so it became the target.

I then ran targeted NSE scripts against port 445 to enumerate SMB further: `smb2-security-mode`, `smb2-time`, and `smb-enum*`. All three failed or errored out rather than returning enumeration data. This is worth documenting on its own: it shows the target's SMB configuration was resistant to casual NSE-script enumeration, not that the scripts were pointed at the wrong thing. A service being open doesn't mean it's easy to enumerate, and knowing which scripts fail against a hardened config is itself useful reconnaissance.

### 2. SMB enumeration and authentication attempt

With scripted enumeration unsuccessful, I moved to direct authentication attempts using `smbclient`, trying several username formats against the same target (`alish`, `BHIM\alish`, `.\alish`, `Bhim\alish`). All four attempts returned:

```
session setup failed: NT_STATUS_LOGON_FAILURE
```

I also tested an anonymous/null session:

```
smbclient -L //192.168.1.44 -N
session setup failed: NT_STATUS_ACCESS_DENIED
```

Both results are left in as-is. SMB was exposed and reachable, but neither valid-username-guessing nor a null session got in. The null session being rejected is actually a positive security finding about the target configuration, not just a failed attack step: it means anonymous SMB enumeration was properly locked down. A SOC needs to be able to detect *attempted* activity regardless of outcome, so these failures are still meaningful evidence.

### 3. Credential attack

Hydra was used to brute-force SMB authentication against the same host using the rockyou wordlist:

```
hydra -l alish -P /usr/share/wordlists/rockyou.txt -t 2 -f smb://192.168.1.44
[ERROR] invalid reply from target smb://192.168.1.44:445/
```

This is a more specific failure than "wrong credentials": Hydra never got a valid SMB protocol reply to work with, which points to something at the protocol or negotiation level (such as SMB signing enforcement or a version mismatch) rather than a simple authentication rejection. That distinction matters for the writeup: the attack didn't fail because the password list was wrong, it failed to even establish the exchange it needed.

### 4. PowerShell execution

The simulation moved from network-level activity to endpoint-level activity via PowerShell execution, which gave Sysmon's Process Creation event (Event ID 1) something concrete to capture and gave the investigation richer telemetry to work with than network logs alone.

### 5. Persistence

A scheduled task, `SOC-Lab-Persistence`, was created via `schtasks`. This maps to **MITRE ATT&CK T1053.005 (Scheduled Task)**, which covers adversary use of Windows Task Scheduler for execution and persistence.

---

## From network evidence to endpoint evidence

Sysmon telemetry for the above activity appeared in Splunk under `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, with relevant event types including:

| Event ID | Meaning |
|---|---|
| 1 | Process Creation |
| 7 | Image/DLL Load |
| 10 | Process Access |
| 11 | File Creation |
| 13 | Registry Value Set |

**A real problem I ran into:** Splunk did not automatically extract every Sysmon XML attribute into a usable field (fields like `DestinationIp` weren't just sitting there ready to query). Rather than writing SPL against fields I assumed existed, I inspected the raw XML directly and adapted my searches to the telemetry that was actually present. I also ran a baseline search (`index=main earliest=-15m`) before writing any detection logic, to confirm what was actually arriving in Splunk rather than designing searches around assumptions.

That loop, generate activity, observe telemetry, validate ingestion, inspect the raw structure, write SPL, test it, tune it, is the detection engineering workflow the project actually followed.

---

## Detections

Each detection below is built from telemetry actually observed in the lab, not a hypothetical query.

### 1. PowerShell execution (T1059.001)

```spl
index=main earliest=-24h sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "powershell.exe" "T1059.001"
```

**Result:** 38 events in 24 hours. Captured both Event ID 1 (process creation, e.g. `powershell.exe -NoProfile -Command "Write-Output 'SOC-LAB-INITIAL-ACCESS'"`) and Event ID 11 (file creation of `PSScriptPolicyTest` temp files, a known PowerShell execution artifact). Confirms PowerShell activity is visible end to end from command line to file-system side effects.

### 2. Isolating a specific simulated action

```spl
index=main earliest=-10m sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "SOC-LAB-INITIAL-ACCESS"
| table _time host source sourcetype _raw
| sort -_time
```

**Result:** 1 event, returning the full raw XML for the exact PowerShell command that generated the marker string, including the technique tag `T1059.001` applied by the Sysmon ruleset. This is the query I'd use to trace a single suspicious action back to its complete process context (parent process, hashes, logon ID) rather than just confirming it happened.

### 3. LOLBin execution: rundll32 (T1218.011)

```spl
index=main earliest=-30m sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "<EventID>1</EventID>"
```

**Result:** 21 events in 30 minutes, including a `rundll32.exe` execution spawned by `svchost.exe`, tagged `technique_id=T1218.011` (Signed Binary Proxy Execution) by the Hartong ruleset. Rundll32 is a legitimate Windows binary that's also a common attacker LOLBin, so this is exactly the kind of event a detection needs to be able to surface for a human to judge.

### 4. Outbound connection flagged as Masquerading (T1036)

```spl
index=main earliest=-30m sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>3</EventID>" "192.168.1.44"
```

**Result:** 1 event, an outbound connection from `192.168.1.44` to `20.184.175.0:443`, tagged `technique_id=T1036` by the ruleset. The process involved was running from a Defender-related path, so this needed manual review rather than an automatic verdict, which is itself the point: a tagged event is a lead for an analyst, not a conviction.

### 5. Failed authentication volume (Event ID 4625)

```spl
index=main earliest=-24h "4625" | stats count
```

**Result:** 9 events in 24 hours, confirming failed logon attempts are landing in Splunk and can be counted/trended, which is the starting point for a brute-force or credential-attack detection.

### 6. Registry modification tied to a specific process

```spl
index=main earliest=-10m "Microsoft-Windows-Sysmon" notepad.exe
```

**Result:** 6 events, Event ID 13 (registry SetValue) tied to a Notepad process, confirming registry telemetry is captured and attributable to a specific process rather than logged as an anonymous system change.

### 7. Baseline validation and a real false positive

```spl
index=main earliest=-10m "Microsoft-Windows-Sysmon"
```

**Result:** 1,383 events in 10 minutes. I ran this as a baseline check before building any detection, to see what telemetry volume actually looked like. It surfaced a legitimate Microsoft OneDrive process tagged `technique_id=T1574.002` (DLL Side-Loading) by the ruleset. This was a genuine false positive: the rule fired correctly on the pattern it was built to catch, but the process was benign. I'm keeping this in the writeup because recognizing "the rule fired" is not the same as "this is malicious" is a real part of the job, not a flaw in the lab.

### 8. Testing and ruling out a hypothesis

```spl
index=main earliest=-30m sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>3</EventID>"
| search "192.168.1.45" "192.168.1.44"
```

**Result:** 0 events. I ran this to check for a network connection between two specific hosts and got nothing back. I'm including the negative result because ruling something out with evidence is as much a part of an investigation as finding something.

---

## Telemetry gap: Windows Firewall logging

Windows Firewall logging was enabled and configured to write to `pfirewall.log`:

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public `
-LogAllowed True `
-LogBlocked True `
-LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
```

The log file itself was generated successfully, but the expected firewall records did not show up in Splunk. This is documented as a gap between log generation and log forwarding, not hidden or left out. It's a useful finding on its own: enabling logging on an endpoint doesn't automatically mean the SIEM is receiving it, and the collection pipeline has to be validated separately from the logging configuration.

---

## Attack timeline

| Stage | Attacker activity | Evidence | SOC visibility |
|---|---|---|---|
| 01 | Host reconnaissance | Nmap | Network activity |
| 02 | Service discovery | TCP/445 | SMB exposure |
| 03 | SMB enumeration | smbclient / SMB tests | Network/service activity |
| 04 | Authentication attempt | NT_STATUS_LOGON_FAILURE | Failed authentication |
| 05 | PowerShell execution | Sysmon Event ID 1 | Process telemetry |
| 06 | Persistence | Scheduled task | Endpoint telemetry |
| 07 | Investigation | SPL | SIEM visibility |
| 08 | Detection | Detection searches | Analyst conclusion |

---

## What each component contributed

| Component | Role | What it produced |
|---|---|---|
| Kali Linux | Attacker | Reconnaissance, SMB activity, authentication attempts |
| Windows VM | Target / monitored endpoint | Process activity, persistence activity, firewall logs |
| Sysmon | Endpoint telemetry source | Process creation, image loads, file and registry events |
| Olaf Hartong sysmon-modular | Telemetry configuration | Modular, ATT&CK-aware ruleset, tuned rather than "log everything" |
| Splunk Universal Forwarder | Transport | Moved Windows/Sysmon data to Splunk |
| Splunk Enterprise | SIEM | Ingestion, search, investigation, SPL |
| MITRE ATT&CK | Behavioral framework | Common language connecting simulated behavior to detection intent |

---

## Lessons learned

- Enabling logging is not the same as confirming ingestion. The firewall log gap made this concrete rather than theoretical.
- SIEM field extraction can't be assumed. Working from raw XML when fields are missing is a normal part of the job, not a failure state.
- A failed attack attempt is still valid detection material. The point of the lab is whether the SOC can see the behavior, not whether the attacker succeeded.
- Separating the attack path and telemetry path on the same target VM required deliberate network configuration, which was part of the actual engineering work, not just setup overhead.

---

## Repository structure

```
01_environment/       architecture, Kali, Windows, adapters, IP config, Sysmon, Splunk setup
02_reconnaissance/    ping, Nmap command and output, open/filtered ports
03_smb_enumeration/   port 445 verification, smbclient, authentication failure
04_telemetry/         Sysmon install, event IDs, raw XML, baseline search, forwarder config
05_attack_activity/   PowerShell, process creation, scheduled task, persistence evidence
06_detection_engineering/  SPL searches, filtering, detection results, ATT&CK mapping
07_troubleshooting/   network issues, firewall ingestion gap, field extraction issue
08_final_story/       attack timeline, detection summary, lessons learned, this README
```

Each screenshot in the numbered folders should carry a short caption answering four things: what it shows, why that step was taken, what it proves, and what it led to next. That's what turns a folder of screenshots into a readable case file instead of a dump.
