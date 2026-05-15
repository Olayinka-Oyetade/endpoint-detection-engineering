# Incident Report
## T1543.003 — Create or Modify System Process: Windows Service

---

| Field | Detail |
|---|---|
| **Report ID** | IR-2026-003 |
| **Date of Incident** | May 13, 2026 |
| **Date Report Issued** | May 13, 2026 |
| **Analyst** | Olayinka Daniel Oyetade |
| **Classification** | Internal Use Only |
| **Severity** | HIGH |
| **Status** | Resolved (Simulation Confirmed) |
| **MITRE ATT&CK** | T1543.003 — Create or Modify System Process: Windows Service |
| **Tactic** | Persistence (TA0003) |
| **Environment** | SOC Home Lab — Windows 10 VM (WINDOWSVM10) |

---

## 1. Executive Summary

A simulated persistence attack was executed against a controlled Windows 10 endpoint. The attacker created a malicious Windows service called "WindowsHealthSvc" — a name chosen to blend in with legitimate Windows background processes — configured to execute automatically at every system boot with SYSTEM-level privileges.

Unlike registry run keys that require a user to log in, a malicious service survives reboots, runs silently in the background, and operates with the highest available privileges on the machine, making it one of the most durable persistence mechanisms available to an attacker.

Sysmon detected the attack via Event ID 13 (Registry modification) targeting the Windows service registry path. The Splunk detection rule fired within minutes and an automated email alert was delivered to the analyst inbox with full evidence. The detection pipeline performed as designed.

---

## 2. Timeline of Events

| Time | Event |
|---|---|
| T+00:00 | Attack initiated — PowerShell opened with administrator privileges |
| T+00:45 | sc.exe executed to create malicious service "WindowsHealthSvc" |
| T+00:50 | Service registered in Windows Service Control Manager |
| T+01:00 | Sysmon captured Event ID 13 — registry modification to CurrentControlSet\Services |
| T+03:00 | Splunk scheduled search fired, alert matched |
| T+03:10 | Automated email alert delivered to analyst inbox |
| T+15:00 | Investigation completed, case documented and closed |

---

## 3. Attack Narrative

A Windows service is a program that runs in the background, managed by the Windows Service Control Manager (SCM). Services are designed to start automatically at boot, run without user interaction, and operate independently of who is logged in. This makes them an ideal persistence mechanism for attackers — the malicious payload runs every time the machine starts, whether or not the target user is present.

**Attack command executed:**

```powershell
sc.exe create "WindowsHealthSvc" binPath= "cmd.exe /c malware.exe" start= auto
```

**What this command does:**
- Creates a new service named "WindowsHealthSvc" — chosen to appear legitimate among real Windows services
- Sets the binary path to cmd.exe launching malware.exe — the malicious payload
- Sets start type to auto — the service launches automatically at every boot
- Registers the service in the Windows registry under: `HKLM\SYSTEM\CurrentControlSet\Services\WindowsHealthSvc`

**Why this is dangerous in a real environment:**
- The service runs as SYSTEM — the highest privilege level on a Windows machine
- No user login is required for the payload to execute
- The service name is designed to blend into the legitimate service list
- Standard users cannot delete or stop a SYSTEM-level service without administrator rights

---

## 4. Detection Details

**Primary log source:** Sysmon Event ID 13 — RegistryValueSet

**Key event fields:**

| Field | Value |
|---|---|
| EventCode | 13 |
| Image | C:\Windows\System32\services.exe |
| TargetObject | HKLM\SYSTEM\CurrentControlSet\Services\WindowsHealthSvc\ImagePath |
| Details | cmd.exe /c malware.exe |

**Important investigative note:** The Image field showed `services.exe` rather than PowerShell or sc.exe. This is expected behaviour. The Service Control Manager (services.exe) acts as the intermediary that physically writes the registry entry — it does not mean PowerShell was not involved. Understanding this distinction is critical for accurate investigation and prevents a false conclusion that the detection missed the originating process.

The binary path in the Details field (`cmd.exe /c malware.exe`) was the definitive indicator. No legitimate software installs a service pointing to cmd.exe or a temp-directory executable.

---

## 5. Splunk Alert Details

**Detection query:**

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13
TargetObject="*\\CurrentControlSet\\Services\\*\\ImagePath"
NOT Details IN (
  "*\\svchost.exe*",
  "*\\System32\\*",
  "*\\SysWOW64\\*",
  "*\\Program Files\\*",
  "*\\Program Files (x86)\\*"
)
| eval Severity=case(
    match(Details, "(?i)(cmd\.exe|powershell|temp|appdata|malware)"), "CRITICAL",
    true(), "HIGH"
  )
| table _time, Image, TargetObject, Details, Severity, ComputerName
| sort -_time
```

**Alert configuration:**

| Setting | Value |
|---|---|
| Schedule | Every 5 minutes |
| Trigger condition | Results count > 0 |
| Alert action | Send email to analyst |
| Severity | HIGH |

**Tuning note:** An earlier version of the rule included a LocalSystem filter that introduced false positives — legitimate Windows services also run under LocalSystem. Removing that filter and focusing purely on the binary path reduced noise to zero while maintaining full detection coverage.

---

## 6. Investigation Steps

1. Confirmed Event ID 13 firing on `CurrentControlSet\Services\WindowsHealthSvc\ImagePath`.
2. Reviewed the Details field — `cmd.exe /c malware.exe` immediately identified as malicious. No legitimate service uses this binary path pattern.
3. Understood services.exe as the Image — recognised this is the SCM acting as intermediary, not the actual attack origin.
4. Verified service registration via Windows Service Control Manager — `WindowsHealthSvc` confirmed present with auto-start configuration.
5. Checked for service execution indicators — Event ID 7045 (System log, new service installed) corroborated the Sysmon finding.
6. Assessed scope — no evidence of lateral movement in isolated lab environment.
7. Documented findings and closed as Confirmed True Positive.

---

## 7. Impact Assessment

| Category | Assessment |
|---|---|
| **Confidentiality** | MEDIUM — Service executes payload with SYSTEM privileges, potential data access |
| **Integrity** | HIGH — SYSTEM-level service can modify any file or registry key on the host |
| **Availability** | MEDIUM — Malicious service running at boot consumes resources and may destabilise the host |
| **Scope** | Single endpoint (isolated lab) |
| **Real-world risk** | CRITICAL — Persistent SYSTEM-level access enables full host compromise and lateral movement |

---

## 8. Response Actions

| Action | Status |
|---|---|
| Alert confirmed as True Positive | Complete |
| Malicious service identified and documented | Complete |
| Service stopped and removed (`Stop-Service`, `Remove-Service`) | Complete |
| Host isolation recommended for real-world scenario | Noted |
| Full disk scan recommended to identify malware.exe payload | Recommended |
| Review of other hosts for same service name | Recommended |
| Rule validated as operational | Complete |

---

## 9. Recommendations

1. **Monitor all new service installations in production.** Windows Event ID 7045 (System log) logs every new service installed. This should feed directly into the SIEM as a standard detection source alongside Sysmon.
2. **Flag binary paths outside of standard directories.** Any service pointing to cmd.exe, PowerShell, Temp folders, AppData, or user-writable locations should trigger an immediate alert.
3. **Implement application control policies.** AppLocker or Windows Defender Application Control (WDAC) can prevent unauthorised executables from running as services.
4. **Audit the service list regularly.** In a production environment, establish a baseline of known good services and alert on any additions that deviate from it.
5. **Correlate with process creation events.** Linking Event ID 13 with Event ID 1 (Process Creation) would surface the originating process (sc.exe or PowerShell) alongside the registry modification, providing full attack chain visibility.

---

## 10. Conclusion

The detection rule correctly identified the malicious service creation within minutes of execution. The binary path analysis was definitive — no false positive risk when filtering for cmd.exe and non-standard directories as service executable paths. The investigation followed a structured SOC workflow from alert to closure.

**Detection status:** CONFIRMED TRUE POSITIVE
**Case status:** RESOLVED
