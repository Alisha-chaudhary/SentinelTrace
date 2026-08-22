# SOC Detection Lab: Attack Simulation to Detection Engineering

A self-built SOC environment where a simulated attack against a Windows endpoint is captured with Sysmon, forwarded to Splunk, and investigated using custom SPL detections mapped to MITRE ATT&CK.

**Attacker action → endpoint telemetry → SIEM ingestion → detection engineering → ATT&CK-aligned investigation**

## Summary

I built a small SOC lab with a Kali attacker VM and a Windows target VM, then ran a controlled attack against the Windows endpoint: reconnaissance, SMB enumeration, several authentication attempts, PowerShell execution, and persistence through a scheduled task. Endpoint activity was captured with Sysmon, configured using Olaf Hartong's modular ruleset, and forwarded to Splunk for investigation.

I wrote and tuned SPL searches against the resulting telemetry, and where Splunk didn't auto-extract the fields I expected, I went back to the raw Sysmon XML and worked from there instead of assuming a field existed. I mapped the observed behaviors to MITRE ATT&CK where the mapping was genuinely supported by evidence, not just because a technique ID sounded like a good fit. I also kept a telemetry gap I ran into with Windows Firewall log ingestion in the writeup instead of quietly dropping it, because it turned out to be one of the more useful findings in the whole lab.

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

The Windows VM had two separate networking jobs at once: an attack path from Kali, and a telemetry path to Splunk. Getting the attacker connected without quietly breaking the telemetry path was one of the first real engineering problems in this project, before a single detection got written.

## Why Sysmon, and why Olaf Hartong's config specifically

Network telemetry alone only shows what an attacker sent. It doesn't show what happened on the endpoint after that packet landed. Sysmon was chosen to get process-level visibility, so the investigation could follow the attack past the network layer and into process creation, image loads, file activity, and registry changes.

For the configuration itself, I used Olaf Hartong's `sysmon-modular` ruleset rather than a generic Sysmon XML, for three reasons.

It's built modularly, which made it easier for me to actually reason about what each rule was doing, instead of treating Sysmon as a black box I just pointed at the endpoint.

It's tuned to avoid the "log everything" trap. The more verbose configurations in that repo are explicitly documented as research-grade and not meant for production as-is, which matched what I needed: useful signal without flooding an 8GB lab machine with noise.

It ties configuration choices to MITRE ATT&CK, treating specific event types as *potential* detection-relevant sources for specific techniques, not claiming any single event detects a technique outright. That framing is exactly how I wanted to structure my own detections, so the config and my SPL ended up speaking the same language.

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

Everything else, 22, 80, 135, 139, 443, 3389, 5985, came back filtered. That single open port decided the rest of the attack. SMB was the only exposed service, so SMB became the target.

I followed up with targeted NSE scripts against port 445: `smb2-security-mode`, `smb2-time`, and the `smb-enum*` family. All of them either failed or errored out instead of returning enumeration data. That's worth sitting with for a second, because it shows the target's SMB configuration resisted casual NSE-script enumeration. It doesn't mean the scripts were pointed at the wrong thing. A service being open doesn't mean it's easy to enumerate, and knowing which scripts fail against a hardened config is itself a piece of recon.

### 2. SMB enumeration and authentication attempts

With scripted enumeration going nowhere, I moved to direct authentication attempts using `smbclient`, trying several username formats against the same target: `alish`, `BHIM\alish`, `.\alish`, `Bhim\alish`. All four came back with:

```
session setup failed: NT_STATUS_LOGON_FAILURE
```

I also tested a null session:

```
smbclient -L //192.168.1.44 -N
session setup failed: NT_STATUS_ACCESS_DENIED
```

Both results stayed in the writeup as they are. SMB was open and reachable, but neither username guessing nor an anonymous session got in. The null session being rejected is actually a positive finding about the target, not just another failed attack step. It means anonymous SMB enumeration was locked down properly. A SOC has to be able to see attempted activity whether or not it succeeds, and these failures are real evidence of that.

After the unknown-credential attempts failed, I tried authenticating with a credential I already knew was correct for the account, to separate "wrong password" from something else going on at the protocol or policy level:

```
smbclient //192.168.1.44/C$ -U alish
```

```
session setup failed: NT_STATUS_ACCESS_DENIED
```

Access was still denied, with a *known-correct* credential. That rules out a bad password as the explanation and points instead at something like account lockout, restricted network logon rights, or SMB signing getting in the way. This is a more useful result than a simple failed login, because it narrows down what's actually blocking access rather than just confirming that guessing didn't work.

### 3. Credential attack at scale

Hydra was used to brute-force SMB authentication against the same host using the rockyou wordlist:

```
hydra -l alish -P /usr/share/wordlists/rockyou.txt -t 2 -f smb://192.168.1.44
[ERROR] invalid reply from target smb://192.168.1.44:445/
```

This is a more specific failure than "wrong credentials." Hydra never got a valid SMB protocol reply to work with, which points at something happening at the protocol or negotiation level, possibly SMB signing enforcement or a version mismatch, rather than a simple rejection. That distinction matters for the writeup. The attack didn't fail because the wordlist was wrong. It failed before it ever got the exchange it needed.

### 4. PowerShell execution

The simulation moved from network-level activity to endpoint-level activity through PowerShell execution. This gave Sysmon's Process Creation event (Event ID 1) something concrete to capture, and gave the investigation richer telemetry to work with than network logs alone.

### 5. Persistence and privilege escalation

A scheduled task, `SOC-Lab-Persistence`, was created through `schtasks`, set to run at logon under the standard user context. A second task, `SOC-Lab-PrivilegeEsc`, was created the same way but configured with `/RU SYSTEM`, meaning it runs as `NT AUTHORITY\SYSTEM` regardless of who's logged in. Both map to MITRE ATT&CK **T1053.005** (Scheduled Task/Job: Scheduled Task), but they represent two different intents behind the same technique. One is about surviving a reboot. The other is about running with more authority than the account that created it.

## From network evidence to endpoint evidence

Sysmon telemetry for the activity above showed up in Splunk under `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, with relevant event types including:

| Event ID | Meaning |
|---|---|
| 1 | Process Creation |
| 7 | Image/DLL Load |
| 10 | Process Access |
| 11 | File Creation |
| 13 | Registry Value Set |

A real problem I ran into along the way: Splunk didn't automatically extract every Sysmon XML attribute into a usable field. Fields like `DestinationIp` weren't just sitting there ready to query. Rather than writing SPL against fields I assumed existed, I went back to the raw XML, saw what was actually there, and adjusted the searches to match. I also ran a plain baseline search (`index=main earliest=-15m`) before writing a single detection, just to see what was actually landing in Splunk instead of designing queries around what I expected to be there.

That loop, generate activity, observe telemetry, validate ingestion, inspect the raw structure, write SPL, test it, tune it, is the detection engineering workflow this project actually followed. None of it happened in the order it reads in a clean writeup.

## Detections

Each detection below is built from telemetry actually observed in the lab, not a hypothetical query.

### 1. PowerShell execution (T1059.001)

```
index=main earliest=-24h sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "powershell.exe" "T1059.001"
```

Result: 38 events over 24 hours. Captured both Event ID 1 (process creation, e.g. `powershell.exe -NoProfile -Command "Write-Output 'SOC-LAB-INITIAL-ACCESS'"`) and Event ID 11 (creation of `PSScriptPolicyTest` temp files, a known PowerShell execution artifact). Confirms PowerShell activity is visible end to end, from the command line down to its file-system side effects.

### 2. Isolating a specific simulated action

```
index=main earliest=-10m sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "SOC-LAB-INITIAL-ACCESS"
| table _time host source sourcetype _raw
| sort -_time
```

Result: 1 event, returning the full raw XML for the exact PowerShell command that generated the marker string, including the `T1059.001` tag applied by the Sysmon ruleset. This is the query I'd actually run to trace one suspicious action back to its full process context, parent process, hashes, logon ID, instead of just confirming that it happened.

### 3. LOLBin execution: rundll32 (T1218.011)

```
index=main earliest=-30m sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "<EventID>1</EventID>"
```

Result: 21 events over 30 minutes, including a `rundll32.exe` execution spawned by `svchost.exe`, tagged `technique_id=T1218.011` (Signed Binary Proxy Execution) by the Hartong ruleset. Rundll32 is a legitimate Windows binary that's also a common attacker LOLBin. This is exactly the kind of event a detection needs to surface for a human to make the actual call on.

### 4. Outbound connection flagged as Masquerading (T1036)

```
index=main earliest=-30m sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>3</EventID>" "192.168.1.44"
```

Result: 1 event, an outbound connection from `192.168.1.44` to `20.184.175.0:443`, tagged `technique_id=T1036` by the ruleset. The process involved was running from a Defender-related path, so this needed manual review rather than an automatic verdict. That's really the point of including it. A tagged event is a lead for an analyst, not a conviction.

### 5. Failed authentication volume (Event ID 4625)

```
index=main earliest=-24h "4625" | stats count
```

Result: 9 events over 24 hours, confirming failed logon attempts are landing in Splunk and can be counted and trended. This is the starting point for any brute-force or credential-attack detection, and it lines up with the smbclient and Hydra activity documented in the attack narrative above.

### 6. Registry modification tied to a specific process

```
index=main earliest=-10m "Microsoft-Windows-Sysmon" notepad.exe
```

Result: 6 events, Event ID 13 (registry SetValue) tied to a Notepad process. This confirms registry telemetry is captured and attributable to a specific process, not just logged as an anonymous system change. The matching Event ID 1 for the same Notepad launch, tagged **T1204** (User Execution), sits in `04_telemetry/` and gives this registry event its parent-process context.

### 7. Baseline validation and a real false positive

```
index=main earliest=-10m "Microsoft-Windows-Sysmon"
```

Result: 1,383 events in 10 minutes. I ran this as a baseline check before building any detection logic, to see what telemetry volume actually looked like at rest. It surfaced a legitimate Microsoft OneDrive process tagged `technique_id=T1574.002` (DLL Side-Loading) by the ruleset. This is a genuine false positive. The rule fired correctly on the pattern it was built to catch, but the process itself was benign. I kept this in the writeup because recognizing that "the rule fired" and "this is malicious" are two different statements is a real part of the job, not a flaw in the lab.

### 8. Discovery activity (T1083)

```
index=main earliest=-10m sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "<EventID>1</EventID>"
```

Result: 39 events in 10 minutes, including an `svchost.exe` process tagged `technique_id=T1083` (File and Directory Discovery) by the Hartong ruleset. Like the OneDrive event above, this is a legitimate Windows service process (`-k LocalServiceAndNoImpersonation -p -s FDResPub`). It needed the same manual review, and it's a second, independent example of a tag firing correctly on a benign process rather than a repeat of the same finding.

### 9. Privilege escalation via scheduled task (T1053.005)

```
index=main earliest=-10m sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "SOC-LAB-SYSTEM"
| table _time host source sourcetype _raw
| sort -_time
```

Result: 2 events. Shows `schtasks.exe` creating `SOC-Lab-PrivilegeEsc` with `/RU SYSTEM`, followed by a PowerShell process running as `NT AUTHORITY\SYSTEM` and writing the marker string. This maps to the same technique ID as the persistence task below, but the `RunAsUser` field is what actually separates the two in practice. A scheduled task by itself isn't suspicious. One configured to run as SYSTEM no matter who's logged in is a different story, and that's the detail an analyst would need to catch here.

### 10. Persistence via scheduled task, full chain (T1053.005)

```
index=main earliest=-10m sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "SOC-LAB-PERSISTENCE"
| table _time host source sourcetype _raw
| sort -_time
```

Result: 9 events, covering the whole chain: `schtasks /Create` for `SOC-Lab-Persistence`, the PowerShell process it triggers at logon, and the later `schtasks /Query` used to confirm it. This is the direct SPL evidence for the persistence stage described in the attack narrative, not just a description of what happened.

### 11. Testing and ruling out a hypothesis

```
index=main earliest=-30m sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>3</EventID>"
| search "192.168.1.45" "192.168.1.44"
```

Result: 0 events. I ran this to check for a network connection between two specific hosts and got nothing back. It's included on purpose. Ruling something out with evidence is as much a part of an investigation as finding something, and a negative result from a real query is worth more than an assumption.

## Telemetry gap: Windows Firewall logging

Windows Firewall logging was enabled and pointed at `pfirewall.log`:

```
Set-NetFirewallProfile -Profile Domain,Private,Public `
-LogAllowed True `
-LogBlocked True `
-LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
```

The log file itself was generated correctly, and local review of it (`07_troubleshooting/`) shows real traffic being written, including what looks like scan activity from a second host. But those same records never showed up in Splunk. I've documented this as a gap between log generation and log forwarding rather than quietly leaving it out of the writeup. It turned out to be one of the more useful findings in the lab: enabling logging on an endpoint doesn't automatically mean the SIEM is receiving it, and the collection pipeline has to be checked on its own, separately from the logging config.

## Attack timeline

| Stage | Attacker activity | Evidence | SOC visibility |
|---|---|---|---|
| 01 | Host reconnaissance | Nmap | Network activity |
| 02 | Service discovery | TCP/445 open, rest filtered | SMB exposure |
| 03 | SMB enumeration | NSE scripts, smbclient | Network/service activity |
| 04 | Authentication attempts, unknown creds | `NT_STATUS_LOGON_FAILURE` | Failed authentication |
| 05 | Authentication attempt, known creds | `NT_STATUS_ACCESS_DENIED` | Failed authentication, policy-level |
| 06 | Credential attack at scale | Hydra protocol error | Failed authentication, protocol-level |
| 07 | PowerShell execution | Sysmon Event ID 1 | Process telemetry |
| 08 | Persistence | Scheduled task, standard user | Endpoint telemetry |
| 09 | Privilege escalation | Scheduled task, `/RU SYSTEM` | Endpoint telemetry |
| 10 | Investigation | SPL | SIEM visibility |
| 11 | Detection | Detection searches | Analyst conclusion |

## What each component contributed

| Component | Role | What it produced |
|---|---|---|
| Kali Linux | Attacker | Reconnaissance, SMB activity, authentication attempts |
| Windows VM | Target / monitored endpoint | Process activity, persistence and privesc activity, firewall logs |
| Sysmon | Endpoint telemetry source | Process creation, image loads, file and registry events |
| Olaf Hartong sysmon-modular | Telemetry configuration | Modular, ATT&CK-aware ruleset, tuned rather than "log everything" |
| Splunk Universal Forwarder | Transport | Moved Windows/Sysmon data to Splunk |
| Splunk Enterprise | SIEM | Ingestion, search, investigation, SPL |
| MITRE ATT&CK | Behavioral framework | Common language connecting simulated behavior to detection intent |

## Lessons learned

Enabling logging isn't the same as confirming ingestion. The firewall log gap made this concrete instead of theoretical. I had the log file sitting right there on disk and still had to go prove it wasn't reaching the SIEM.

SIEM field extraction can't be assumed. Going back to raw XML when a field is missing is a normal part of the job, not something going wrong.

A failed attack attempt is still valid detection material. Whether the attacker got in isn't really the question a SOC lab needs to answer. Whether the SOC can see the attempt is.

A denied login with a known-correct credential is a different finding than a denied login with an unknown one. The first points at policy or protocol. The second just means the guess was wrong. Telling those apart mattered more than I expected going in.

Separating the attack path and the telemetry path on the same target VM took deliberate network configuration. That was part of the actual engineering work here, not setup overhead to get past before the "real" project started.

## Repository structure

```
01_environment/       VM baseline snapshot, host/network enumeration, Sysmon install,
                       firewall logging setup, pre-attack privilege baseline
02_reconnaissance/    Ping, Nmap (top-100, targeted ports, service version),
                       filtered-port evidence
03_smb_enumeration/   NSE SMB scripts, smbclient auth attempts (unknown and known
                       credentials), null session, Hydra brute-force attempt
04_telemetry/         Sysmon event examples showing endpoint-level process capture
05_attack_activity/   Persistence and privilege-escalation scheduled tasks
                       (creation and verification)
06_detection_engineering/  SPL searches, detection results, ATT&CK-tagged findings,
                       false positives, ruled-out hypotheses
07_troubleshooting/   Local firewall log evidence vs. Splunk ingestion gap,
                       raw XML field inspection
08_final_story/       Attack timeline, detection summary, lessons learned, this README
```

Each screenshot in the numbered folders carries a short caption answering four things: what it shows, why that step was taken, what it proves, and what it led to next. That's what turns a folder of screenshots into a readable case file instead of a dump.
