# Incident Report
## T1003.001 — OS Credential Dumping: LSASS Memory

---

| Field | Detail |
|---|---|
| **Report ID** | IR-2026-002 |
| **Date of Incident** | May 5, 2026 |
| **Date Report Issued** | May 5, 2026 |
| **Analyst** | Olayinka Daniel Oyetade |
| **Classification** | Internal Use Only |
| **Severity** | HIGH |
| **Status** | Resolved (Simulation Confirmed) |
| **MITRE ATT&CK** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Tactic** | Credential Access (TA0006) |
| **Environment** | SOC Home Lab — Windows 10 VM (WINDOWSVM10) |

---

## 1. Executive Summary

On May 5, 2026, a simulated credential theft attack was executed against a controlled Windows 10 endpoint to validate the lab's detection capabilities. The attacker used the built-in Windows Task Manager to create a memory dump of the LSASS process — the Windows component responsible for storing active user credentials in memory.

The activity was detected within three minutes by a Splunk detection rule consuming Sysmon Event ID 10 (ProcessAccess). An automated email alert fired with full context including source process, target process, and access rights requested. No real credentials were exposed as the exercise was conducted in an isolated lab environment. The detection pipeline performed as designed.

---

## 2. Incident Overview

LSASS (Local Security Authority Subsystem Service) is a core Windows process that handles authentication and stores credential material including NTLM hashes and Kerberos tickets in memory. Attackers who gain local administrator access to a Windows machine routinely target LSASS to extract credentials and use them for lateral movement across the network.

This technique is used in real-world attacks by ransomware groups, APT operators, and commodity malware families including Mimikatz, ProcDump, and CrackMapExec. Detecting LSASS access is a Tier 1 SOC priority because it frequently indicates an attacker has already established a foothold and is preparing to move laterally.

This simulation was conducted to validate that the home lab detection pipeline could identify the attack, generate an alert, and support a structured investigation response.

---

## 3. Attack Narrative

**Attack method:** Windows Task Manager (taskmgr.exe)

**Step-by-step execution:**

1. Attacker opened Task Manager on the Windows 10 endpoint with local administrator privileges.
2. Located `lsass.exe` in the Processes tab.
3. Right-clicked `lsass.exe` and selected "Create dump file."
4. Windows wrote the dump file to: `C:\Users\[username]\AppData\Local\Temp\lsass.DMP`
5. Sysmon captured the memory access event (Event ID 10) and the file creation event (Event ID 11).
6. Splunk ingested both events and the detection rule matched within the next scheduled search cycle.
7. Automated email alert generated with full event context.

**Timeline:**

| Time | Event |
|---|---|
| T+00:00 | Attacker opens Task Manager |
| T+00:45 | lsass.DMP written to Temp directory |
| T+01:00 | Sysmon Event ID 10 and 11 generated |
| T+03:00 | Splunk scheduled search fires, alert matched |
| T+03:10 | Email alert delivered to analyst inbox |

---

## 4. Detection Details

**Log source:** Sysmon Event ID 10 — ProcessAccess

**Key event fields:**

| Field | Value |
|---|---|
| EventCode | 10 |
| SourceImage | C:\Windows\System32\taskmgr.exe |
| TargetImage | C:\Windows\System32\lsass.exe |
| GrantedAccess | 0x1fffff |
| CallTrace | Confirmed memory read access |

**GrantedAccess 0x1fffff** represents PROCESS_ALL_ACCESS — the maximum access rights that can be requested against a process. This value is highly suspicious when the target is lsass.exe and the source is not a known system process.

**Secondary indicator:** Sysmon Event ID 11 (FileCreate) logged the creation of `lsass.DMP` in the Temp directory, corroborating the ProcessAccess event.

---

## 5. Splunk Alert Details

**Search query:**

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=10
TargetImage="*lsass.exe"
NOT SourceImage IN (
  "*\\svchost.exe",
  "*\\wininit.exe",
  "*\\csrss.exe",
  "*\\services.exe",
  "*\\MsMpEng.exe"
)
| table _time, SourceImage, TargetImage, GrantedAccess, CallTrace, ComputerName
| sort -_time
```

**Alert configuration:**

| Setting | Value |
|---|---|
| Schedule | Every 5 minutes |
| Trigger condition | Results count > 0 |
| Alert action | Send email to analyst |
| Severity | HIGH |

---

## 6. Investigation Steps

1. Confirmed SourceImage (taskmgr.exe) — not a known legitimate accessor of lsass.
2. Verified GrantedAccess value (0x1fffff) — PROCESS_ALL_ACCESS, highly suspicious.
3. Correlated with Event ID 11 — confirmed dump file written to Temp directory.
4. Checked for lateral movement indicators across other hosts — none found (isolated lab environment).
5. Confirmed no real credentials at risk — simulation environment only.
6. Documented findings and closed the case as Confirmed True Positive.

---

## 7. Impact Assessment

| Category | Assessment |
|---|---|
| **Confidentiality** | HIGH — LSASS dump exposes all cached credentials |
| **Integrity** | MEDIUM — No system modification beyond dump file creation |
| **Availability** | LOW — No service disruption |
| **Scope** | Single endpoint (isolated lab) |
| **Real-world risk** | CRITICAL — In a live environment, extracted credentials enable immediate lateral movement |

---

## 8. Response Actions

| Action | Status |
|---|---|
| Alert confirmed as True Positive | Complete |
| Dump file located and logged as forensic evidence | Complete |
| Host isolation recommended (not executed — lab environment) | Noted |
| Force password reset for all accounts cached on affected host | Recommended |
| Escalation to IR team | Recommended for real-world scenario |
| Rule validated as operational | Complete |

---

## 9. Recommendations

1. **Restrict LSASS access at the OS level.** Enable Protected Process Light (PPL) for lsass.exe via Group Policy or registry. This prevents most userland tools from accessing LSASS memory.
2. **Enable Windows Credential Guard** on supported hardware to store credential material in a virtualised environment isolated from the main OS.
3. **Monitor for GrantedAccess values** of 0x1fffff, 0x1010, and 0x143a against lsass.exe — these are the most common values used by credential dumping tools.
4. **Alert on dump file creation** in Temp directories (Event ID 11, filename matching `*.dmp`) as a secondary detection layer.
5. **Implement application whitelisting** to prevent non-approved processes from accessing sensitive system processes.

---

## 10. Conclusion

The detection rule performed as designed. The simulated LSASS credential dump was detected within three minutes of execution, an automated alert was generated, and the investigation was completed following a structured SOC workflow. The pipeline is validated and operational for this technique.

**Detection status:** CONFIRMED TRUE POSITIVE
**Case status:** RESOLVED
