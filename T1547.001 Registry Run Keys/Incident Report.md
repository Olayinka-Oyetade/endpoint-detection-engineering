# Incident Report
## T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys

---

| Field | Detail |
|---|---|
| **Report ID** | IR-2026-001 |
| **Date of Incident** | May 5, 2026 |
| **Date Report Issued** | May 5, 2026 |
| **Analyst** | Olayinka Daniel Oyetade |
| **Classification** | Internal Use Only |
| **Severity** | HIGH |
| **Status** | Resolved (Simulation Confirmed) |
| **MITRE ATT&CK** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |
| **Tactic** | Persistence (TA0003) |
| **Environment** | SOC Home Lab — Windows 10 VM (WINDOWSVM10) |

---

## 1. Executive Summary

A simulated persistence attack was executed against a controlled Windows 10 endpoint. The attacker used PowerShell to plant a malicious registry Run key entry named "WindowsUpdate" — chosen to appear indistinguishable from a legitimate Windows process — configured to execute a payload (`malware.exe`) on every user login.

Registry Run keys are one of the most widely abused persistence mechanisms in real-world attacks. They require no administrator privileges when written to the HKCU hive, survive reboots, and are used by malware families including Emotet, TrickBot, Remcos RAT, and multiple ransomware variants.

The attack was detected by Sysmon Event ID 13 (RegistryValueSet) within 5 minutes of execution. An automated Splunk alert fired with full context including source process, registry path, and the value written. The detection pipeline performed as designed.

---

## 2. Timeline of Events

| Time | Event |
|---|---|
| T+00:00 | Attack initiated — PowerShell opened on Windows 10 VM |
| T+00:20 | PowerShell command executed to write malicious Run key |
| T+00:21 | Registry key written: HKCU\...\Run\WindowsUpdate = C:\Users\Public\malware.exe |
| T+00:22 | Sysmon Event ID 13 captured — RegistryValueSet with full field context |
| T+03:00 | Splunk scheduled search fired, alert matched |
| T+03:10 | Automated email alert delivered to analyst inbox |
| T+15:00 | Investigation completed, remediation performed, case closed |

---

## 3. Attack Narrative

Windows Registry Run keys instruct the operating system to execute a specified program automatically whenever a user logs in. They are a native Windows feature designed for legitimate software (startup applications, update agents) but are routinely abused by attackers to maintain persistent access.

**What makes this technique particularly effective:**
- Writing to the HKCU hive requires no administrator privileges — any standard user account can do it
- The key name ("WindowsUpdate") is indistinguishable from legitimate Windows entries without investigation
- The payload executes automatically on every login without any further attacker action
- The technique leaves no obvious file-system indicator — the only evidence is the registry entry and the Sysmon log

**Attack command executed:**

```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "WindowsUpdate" `
    -Value "C:\Users\Public\malware.exe" `
    -PropertyType String `
    -Force
```

**What this command does:**
- Writes a new value called "WindowsUpdate" to the HKCU Run key
- Points to `malware.exe` located in C:\Users\Public — a directory any user can write to
- The `-Force` flag overwrites any existing entry with the same name
- On next login, Windows reads this key and executes malware.exe automatically

---

## 4. Detection Details

**Log source:** Sysmon Event ID 13 — RegistryValueSet

**Key event fields captured:**

| Field | Value |
|---|---|
| EventCode | 13 |
| RuleName | technique_id=T1547.001, technique_name=Boot or Logon Autostart Execution |
| Image | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| TargetObject | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate |
| Details | C:\Users\Public\malware.exe |
| User | WINDOWSVM10\mrdaniel198 |

**Key indicators:**
- Source process is PowerShell — a standard user should not be modifying Run keys via PowerShell
- TargetObject is the Run key — a well-known persistence location
- Details points to C:\Users\Public — a world-writable directory, not a standard software installation path
- Sysmon's own RuleName field tagged this as T1547.001, confirming the technique mapping

---

## 5. Splunk Alert Details

**Detection query:**

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13
TargetObject="*\\CurrentVersion\\Run*"
NOT Image IN (
  "*\\msiexec.exe",
  "*\\MicrosoftEdgeUpdate.exe",
  "*\\OneDriveSetup.exe"
)
| table _time, host, User, Image, TargetObject, Details
| sort -_time
```

**Alert configuration:**

| Setting | Value |
|---|---|
| Schedule | Every 5 minutes |
| Trigger condition | Results count > 0 |
| Alert action | Send email to analyst |
| Alert name | Suspicious Registry Run Key Modification |
| Severity | HIGH |

---

## 6. Investigation Steps

1. Confirmed TargetObject — HKCU\...\Run\WindowsUpdate matches a known persistence path.
2. Reviewed Image — powershell.exe modifying a Run key is not expected behaviour for a standard user.
3. Checked Details — `C:\Users\Public\malware.exe` is in a world-writable directory, not a trusted software installation path. Definitive indicator.
4. Verified RuleName field — Sysmon's own tagging confirmed T1547.001 mapping.
5. Assessed whether the key had already triggered on login — no subsequent execution events found in the investigation window.
6. Remediated: removed the malicious registry entry.
7. Confirmed removal via follow-up Splunk query — no further Event ID 13 matches on the same path.
8. Closed as Confirmed True Positive.

---

## 7. Impact Assessment

| Category | Assessment |
|---|---|
| **Confidentiality** | HIGH — Persistent malware with user-level access can exfiltrate data |
| **Integrity** | HIGH — Payload executes in user context on every login |
| **Availability** | MEDIUM — Depends on payload behaviour |
| **Privilege level** | User (HKCU) — no admin rights required |
| **Scope** | Single endpoint (isolated lab) |
| **Real-world risk** | HIGH — Technique used by Emotet, TrickBot, Remcos RAT, and ransomware families |

---

## 8. Response Actions

| Action | Status |
|---|---|
| Alert confirmed as True Positive | Complete |
| Malicious registry key identified and documented | Complete |
| Registry key removed via PowerShell | Complete |
| Removal confirmed via Splunk follow-up query | Complete |
| Scan for additional persistence mechanisms recommended | Recommended |
| Credential reset for affected user account | Recommended |
| Disk image preservation for forensic analysis | Recommended for real-world scenario |

**Remediation command used:**

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate"
```

---

## 9. Recommendations

1. **Alert on all PowerShell-sourced Run key modifications.** PowerShell writing to the Run key should always trigger an alert. Legitimate software uses installers (msiexec), not raw PowerShell, to set startup entries.
2. **Monitor both HKCU and HKLM Run keys.** HKCU requires only user access. HKLM requires admin but affects all users. Both should be covered.
3. **Extend monitoring to RunOnce keys.** Attackers also use RunOnce (`HKCU\...\RunOnce`) for persistence that executes only on the next login. The detection logic applies equally.
4. **Correlate with file creation events.** The malware.exe payload was written to C:\Users\Public before the Run key was created. Event ID 11 (FileCreate) in that directory, followed by an Event ID 13 pointing to the same file, is a high-confidence attack pattern.
5. **Review all existing Run key entries as a baseline.** In a production environment, document what should be in the Run key and alert on any deviation.

---

## 10. Conclusion

The detection rule identified the malicious registry persistence entry within 5 minutes of execution. PowerShell as the source process combined with a payload path in a world-writable directory made this a high-confidence true positive with no ambiguity. Investigation, remediation, and documentation were completed following a structured SOC workflow.

**Detection status:** CONFIRMED TRUE POSITIVE
**Case status:** RESOLVED
