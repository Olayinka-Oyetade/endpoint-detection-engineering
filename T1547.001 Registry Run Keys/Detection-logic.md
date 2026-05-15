# Detection Rule Documentation
## T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys

---

| Field | Detail |
|---|---|
| **Document ID** | DET-2026-001 |
| **Date** | May 5, 2026 |
| **Analyst** | Olayinka Daniel Oyetade |
| **MITRE ATT&CK** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |
| **Tactic** | Persistence (TA0003) |
| **Detection Tool** | Splunk + Sysmon |
| **Log Source** | Sysmon Event ID 13 (RegistryValueSet) |
| **Severity** | HIGH |

---

## 1. Technique Overview

Windows Registry Run keys are a built-in mechanism that tells Windows to execute a specified program automatically when a user logs in. The most commonly abused paths are:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (user-level, no admin required)
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (system-level, admin required)
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` (executes once on next login)
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce` (executes once, system-wide)

Writing to the HKCU path requires only standard user privileges, making this technique accessible to any attacker who has achieved initial access — no privilege escalation needed. The payload runs silently on every login, and the key name can be disguised to look like a legitimate Windows entry.

This technique is used by Emotet, TrickBot, Remcos RAT, Agent Tesla, and numerous ransomware families. It is one of the most frequently observed persistence mechanisms in real-world incident investigations.

---

## 2. Detection Logic

### Primary Rule — Run Key Modification (Sysmon Event ID 13)

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13
TargetObject="*\\CurrentVersion\\Run*"
NOT Image IN (
  "*\\msiexec.exe",
  "*\\MicrosoftEdgeUpdate.exe",
  "*\\OneDriveSetup.exe",
  "*\\SteamSetup.exe"
)
| eval Risk=case(
    match(Image, "(?i)(powershell|cmd\.exe|wscript|cscript|regsvr32)"), "CRITICAL",
    match(Details, "(?i)(temp|appdata\\local\\temp|users\\public)"), "CRITICAL",
    true(), "HIGH"
  )
| table _time, host, User, Image, TargetObject, Details, Risk
| sort -_time
```

### Extended Coverage — RunOnce Keys

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13
TargetObject IN (
  "*\\CurrentVersion\\Run\\*",
  "*\\CurrentVersion\\RunOnce\\*"
)
| table _time, host, User, Image, TargetObject, Details
| sort -_time
```

---

## 3. Key Fields Explained

| Field | Description | Why It Matters |
|---|---|---|
| `EventCode` | Sysmon event type | 13 = RegistryValueSet (a value was written to the registry) |
| `TargetObject` | Full registry path being modified | Identifies the Run key being targeted |
| `Details` | Value written — the executable path | This is the payload that will run on next login |
| `Image` | Process performing the write | PowerShell writing to Run keys is suspicious |
| `User` | User account context | Identifies whose profile is being persisted against |
| `RuleName` | Sysmon rule tag | Sysmon auto-tags T1547.001 when configured correctly |

---

## 4. High-Risk Source Processes

Certain processes writing to Run keys are immediately suspicious:

| Process | Risk | Reason |
|---|---|---|
| `powershell.exe` | CRITICAL | Legitimate software does not use raw PowerShell to set startup entries |
| `cmd.exe` | CRITICAL | Same reasoning as PowerShell |
| `wscript.exe` | CRITICAL | Script-based persistence — common in phishing-delivered malware |
| `cscript.exe` | CRITICAL | Same as wscript |
| `regsvr32.exe` | HIGH | Used in LOLBin abuse to execute payloads |
| `msiexec.exe` | LOW | Legitimate installer — exclude but verify binary path |

---

## 5. High-Risk Payload Paths

The Details field (the executable path being registered) is equally important:

| Path Pattern | Risk | Reason |
|---|---|---|
| `C:\Users\Public\*` | CRITICAL | World-writable, no admin needed, not a standard install location |
| `*\AppData\Local\Temp\*` | CRITICAL | Temporary directory — malware drops payloads here |
| `*\AppData\Roaming\*` | HIGH | User-writable, used by commodity malware |
| `*\Downloads\*` | HIGH | Common phishing payload landing zone |
| `C:\Windows\System32\*` | LOW | Trusted path — verify but unlikely malicious |
| `C:\Program Files\*` | LOW | Trusted path — verify but unlikely malicious |

---

## 6. Exclusion Logic

| Excluded Process | Reason |
|---|---|
| `msiexec.exe` | Windows Installer — legitimate software deployments |
| `MicrosoftEdgeUpdate.exe` | Microsoft Edge auto-updater |
| `OneDriveSetup.exe` | OneDrive client installer |

**Production tuning note:** The exclusion list will be significantly longer in a real enterprise environment. Software deployment tools, endpoint management agents, and commercial software installers all write to Run keys legitimately. Build the exclusion list from a known-good baseline of your environment rather than guessing.

---

## 7. Alert Configuration

| Setting | Value |
|---|---|
| **Schedule** | Every 5 minutes |
| **Trigger condition** | Results count > 0 |
| **Trigger once** | Per result |
| **Alert action** | Send email to analyst |
| **Alert name** | Suspicious Registry Run Key Modification |
| **Severity** | HIGH / CRITICAL (based on eval logic) |

---

## 8. False Positive Analysis

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Software installer writing a Run key | HIGH | Add installer process to exclusion list after verifying legitimacy |
| IT deployment tool pushing startup scripts | MEDIUM | Whitelist deployment tool paths |
| Legitimate application self-updating via Run key | MEDIUM | Verify binary path is in trusted directory, then exclude |
| Antivirus or EDR agent writing a Run key | LOW | Add security tool to exclusion list |

**False positive rate in this lab:** 0 (clean environment with no commercial software beyond Sysmon and Splunk)

---

## 9. Investigation Runbook

When this alert fires:

1. **Check the Image field first.** PowerShell, cmd.exe, or any script interpreter writing to a Run key is immediately suspicious. Proceed directly to escalation assessment.
2. **Check the Details field.** A payload path in Public, Temp, or AppData with no recognisable software name is high-confidence malicious. A path in Program Files pointing to a named application is likely legitimate.
3. **Check the key name.** Attackers choose names like "WindowsUpdate", "SecurityScan", or "SystemCheck" to blend in. Compare against the known software baseline.
4. **Look for corroborating events.** Query Event ID 11 (FileCreate) for the same payload path — was malware.exe dropped to Public before the Run key was created? This confirms the full attack chain.
5. **Check for execution.** Query Event ID 1 (Process Creation) for the payload path. Has it already run? If yes, the investigation scope expands significantly.
6. **Remediate.** Remove the registry key. Confirm removal. Scan for additional persistence mechanisms.

---

## 10. MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Technique** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |
| **Tactic** | Persistence (TA0003) |
| **Permissions required** | User (HKCU), Administrator (HKLM) |
| **Data source** | Windows Registry (DS0024) |
| **Detection** | Monitor writes to Run and RunOnce keys from non-installer processes |

---

## 11. Detection Coverage Assessment

| Attack Method | Detected |
|---|---|
| PowerShell New-ItemProperty | YES |
| reg.exe add command | YES |
| cmd.exe registry modification | YES |
| Direct API write (RegSetValueEx) | YES — Sysmon captures the write regardless of originating API |
| Malware writing via its own process | YES — Image will show malware process, making detection even clearer |
