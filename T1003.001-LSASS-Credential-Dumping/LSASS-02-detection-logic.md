# Detection Rule Documentation
## T1003.001 — OS Credential Dumping: LSASS Memory

---

| Field | Detail |
|---|---|
| **Document ID** | DET-2026-002 |
| **Date** | May 5, 2026 |
| **Analyst** | Olayinka Daniel Oyetade |
| **MITRE ATT&CK** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Tactic** | Credential Access (TA0006) |
| **Detection Tool** | Splunk + Sysmon |
| **Log Source** | Sysmon Event ID 10 (ProcessAccess), Event ID 11 (FileCreate) |
| **Severity** | HIGH |

---

## 1. Technique Overview

LSASS (Local Security Authority Subsystem Service) is a Windows process that manages authentication and stores credential material including NTLM password hashes, Kerberos tickets, and plaintext passwords (in older configurations) in memory.

Attackers with local administrator access target LSASS to extract these credentials without needing to crack passwords. Extracted credentials can be used immediately for pass-the-hash attacks, Kerberos ticket abuse, or direct authentication to other systems on the network.

Common tools used to dump LSASS in real-world attacks include Mimikatz, ProcDump, Task Manager, comsvcs.dll, and CrackMapExec. This rule detects the underlying behaviour — suspicious process access to lsass.exe — rather than targeting specific tool names, making it effective against known and unknown dumping methods.

---

## 2. Detection Logic

### Primary Rule — ProcessAccess (Sysmon Event ID 10)

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=10
TargetImage="*lsass.exe"
NOT SourceImage IN (
  "*\\svchost.exe",
  "*\\wininit.exe",
  "*\\csrss.exe",
  "*\\services.exe",
  "*\\MsMpEng.exe",
  "*\\lsm.exe",
  "*\\WerFault.exe"
)
| table _time, SourceImage, TargetImage, GrantedAccess, CallTrace, ComputerName
| sort -_time
```

### Secondary Rule — Dump File Creation (Sysmon Event ID 11)

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11
TargetFilename="*lsass*.dmp"
OR TargetFilename="*\\Temp\\*.dmp"
| table _time, Image, TargetFilename, ComputerName
| sort -_time
```

**Running both rules together provides layered coverage.** The ProcessAccess rule catches the memory access. The FileCreate rule catches the dump file being written. An attacker who evades one will likely trigger the other.

---

## 3. Key Fields Explained

| Field | Description | Why It Matters |
|---|---|---|
| `EventCode` | Sysmon event type | 10 = ProcessAccess (memory read attempt) |
| `TargetImage` | Process being accessed | lsass.exe is the credential store |
| `SourceImage` | Process doing the accessing | Should only be known system processes |
| `GrantedAccess` | Access rights requested | High values signal credential dumping intent |
| `CallTrace` | Stack trace of the access | Helps identify the tool or method used |

---

## 4. GrantedAccess Values Reference

| Value | Meaning | Severity |
|---|---|---|
| `0x1fffff` | PROCESS_ALL_ACCESS — maximum access | CRITICAL |
| `0x1010` | Read + query access | HIGH |
| `0x143a` | Common Mimikatz access mask | CRITICAL |
| `0x0410` | Read process information | MEDIUM |

**In this simulation:** GrantedAccess was `0x1fffff` (PROCESS_ALL_ACCESS), the highest possible value. This is the value produced when Task Manager creates a dump file.

---

## 5. Exclusion Logic

The following processes are excluded because they legitimately access LSASS as part of normal Windows operation:

| Excluded Process | Reason |
|---|---|
| `svchost.exe` | Windows service host, regularly queries LSASS |
| `wininit.exe` | Starts the LSASS process on boot |
| `csrss.exe` | Windows subsystem process, interacts with LSASS |
| `services.exe` | Windows Service Control Manager |
| `MsMpEng.exe` | Microsoft Defender antivirus engine |
| `lsm.exe` | Local Session Manager |
| `WerFault.exe` | Windows error reporting — may access LSASS on crash |

**Tuning note:** In a production environment, security software (AV, EDR agents) will also access LSASS legitimately. The exclusion list should be expanded based on the tools deployed in the specific environment to reduce false positives.

---

## 6. Alert Configuration

| Setting | Value |
|---|---|
| **Schedule** | Every 5 minutes |
| **Trigger condition** | Results count > 0 |
| **Trigger once** | Per result |
| **Alert action** | Send email to analyst |
| **Email subject** | CRITICAL: Possible LSASS Credential Dump Detected |
| **Severity label** | HIGH |

---

## 7. False Positive Analysis

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Security software accessing LSASS | HIGH | Add security tool process names to exclusion list |
| Windows Defender scanning LSASS | MEDIUM | MsMpEng.exe already excluded |
| Legitimate crash dump from WerFault | LOW | WerFault.exe already excluded |
| Task Manager opened by administrator for legitimate reason | LOW | Investigate GrantedAccess value — legitimate use rarely requests 0x1fffff |

**False positive rate in this lab:** 0 (isolated environment with no security software beyond Sysmon)

---

## 8. Investigation Runbook

When this alert fires, follow these steps in order:

1. **Identify the SourceImage.** Is it a known system process or security tool? If yes, update the exclusion list. If no, proceed.
2. **Check GrantedAccess.** Values of 0x1fffff, 0x143a, or 0x1010 are high-risk. Lower values may indicate legitimate diagnostic access.
3. **Correlate with Event ID 11.** Check if a .dmp file was created in Temp or any user-accessible directory in the same timeframe.
4. **Check for lateral movement.** Query for authentication events (Event ID 4624, 4625) from the affected host to other hosts within the previous 30 minutes.
5. **Escalate or close.** If SourceImage is unknown and GrantedAccess is high-risk, escalate to IR. Document findings in the ticketing system regardless of outcome.

---

## 9. MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Technique** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Tactic** | Credential Access (TA0006) |
| **Sub-technique** | LSASS Memory |
| **Data source** | Process Access (DS0009) |
| **Detection** | Monitor for processes accessing lsass.exe with high GrantedAccess values |

---

## 10. Detection Coverage Assessment

| Attack Tool | Detected by This Rule |
|---|---|
| Task Manager (taskmgr.exe) | YES |
| ProcDump (procdump.exe) | YES |
| Mimikatz (sekurlsa::logonpasswords) | YES |
| comsvcs.dll MiniDump | YES |
| Custom shellcode injector | PARTIAL (depends on GrantedAccess value) |

This rule detects behaviour rather than tool signatures, giving it broad coverage across known and unknown LSASS dumping methods.
