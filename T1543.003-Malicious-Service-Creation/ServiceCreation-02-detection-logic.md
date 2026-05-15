# Detection Rule Documentation
## T1543.003 — Create or Modify System Process: Windows Service

---

| Field | Detail |
|---|---|
| **Document ID** | DET-2026-003 |
| **Date** | May 13, 2026 |
| **Analyst** | Olayinka Daniel Oyetade |
| **MITRE ATT&CK** | T1543.003 — Create or Modify System Process: Windows Service |
| **Tactic** | Persistence (TA0003) |
| **Detection Tool** | Splunk + Sysmon |
| **Log Source** | Sysmon Event ID 13 (RegistryValueSet), Windows Event ID 7045 |
| **Severity** | HIGH |

---

## 1. Technique Overview

Windows services are background processes managed by the Service Control Manager (SCM). They can be configured to start automatically at boot, run under SYSTEM privileges, and operate without any user interaction. These properties make services a prime persistence target for attackers.

Creating a malicious service requires only administrator access and a single command. The service then survives reboots, runs silently, and is invisible to most users. Real-world threat actors including ransomware groups, APT operators, and commodity malware families (Emotet, WannaCry, Cobalt Strike) all use Windows service creation as a persistence mechanism.

This detection targets the registry write that occurs when a new service is registered — specifically monitoring for binary paths that fall outside trusted directories, which is the definitive indicator of a malicious service regardless of the tool used to create it.

---

## 2. Detection Logic

### Primary Rule — Registry Modification (Sysmon Event ID 13)

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

### Secondary Rule — Windows System Log (Event ID 7045)

```spl
index=* sourcetype="WinEventLog:System"
EventCode=7045
NOT ServiceFileName IN (
  "*\\System32\\*",
  "*\\SysWOW64\\*",
  "*\\Program Files\\*",
  "*\\Program Files (x86)\\*"
)
| table _time, ServiceName, ServiceFileName, ServiceType, StartType, ComputerName
| sort -_time
```

Running both rules together provides layered coverage across two independent log sources. An attacker who bypasses Sysmon instrumentation will still trigger the Windows System log, and vice versa.

---

## 3. Key Fields Explained

| Field | Description | Why It Matters |
|---|---|---|
| `EventCode` | Sysmon event type | 13 = RegistryValueSet (a registry key was written) |
| `TargetObject` | Registry key path being modified | Services register their binary path under CurrentControlSet\Services |
| `Details` | Value written to the registry key | This is the executable that will run — the most important field |
| `Image` | Process that performed the registry write | Usually services.exe acting as SCM intermediary |
| `ServiceName` | Name of the new service (Event ID 7045) | Used to identify disguised service names |
| `StartType` | When the service starts (Event ID 7045) | Auto-start is the most dangerous configuration |

---

## 4. The Binary Path as Primary Indicator

The Details field (binary path) is the most reliable indicator for this technique. The logic is simple:

**Legitimate services always point to executables in trusted locations:**
- `C:\Windows\System32\`
- `C:\Windows\SysWOW64\`
- `C:\Program Files\`
- `C:\Program Files (x86)\`

**Malicious services commonly point to:**
- `cmd.exe` or `powershell.exe` used as launchers
- Executables in `Temp`, `AppData`, or user-writable directories
- Files with random or generic names (malware.exe, update.exe, svc.exe)
- UNC paths pointing to network shares

This single check — is the binary path in a trusted location — has near-zero false positive rate and catches the full range of service-based persistence regardless of what tool created the service.

---

## 5. Exclusion Logic

| Excluded Path | Reason |
|---|---|
| `*\System32\*` | Core Windows system executables |
| `*\SysWOW64\*` | 32-bit Windows system executables |
| `*\Program Files\*` | Standard software installation directory |
| `*\Program Files (x86)\*` | 32-bit software installation directory |
| `*\svchost.exe*` | Windows service host — legitimate services route through svchost |

**Tuning note:** In a production environment, additional trusted paths for third-party enterprise software (antivirus, EDR agents, backup solutions) should be added to the exclusion list. Start with the paths above and expand based on the environment's software baseline.

**What was removed during tuning:** An initial version of the rule filtered on `LocalSystem` account to narrow results. This filter was removed after testing showed it generated false positives — many legitimate Windows services also run under LocalSystem. Filtering on binary path alone proved more precise.

---

## 6. Alert Configuration

| Setting | Value |
|---|---|
| **Schedule** | Every 5 minutes |
| **Trigger condition** | Results count > 0 |
| **Trigger once** | Per result |
| **Alert action** | Send email to analyst |
| **Email subject** | HIGH: Suspicious Windows Service Created |
| **Severity label** | HIGH / CRITICAL (based on eval logic) |

---

## 7. False Positive Analysis

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Software installer creating a service in a non-standard path | MEDIUM | Add the software's install path to exclusions after verification |
| Admin creating a custom service for legitimate automation | LOW | Investigate service name and binary — legitimate services should be documented |
| EDR or security tools creating services | LOW | Add security tool paths to exclusion list |
| Windows Update creating a temporary service | LOW | Update-related services typically use System32 paths |

**False positive rate in this lab:** 0 after removing the LocalSystem filter and focusing on binary path alone.

---

## 8. Investigation Runbook

When this alert fires:

1. **Review the Details field first.** The binary path tells you almost everything. cmd.exe, PowerShell, or a Temp directory path = immediate escalation.
2. **Note that Image will show services.exe.** This is normal. The SCM writes the registry entry on behalf of whatever tool created the service. Do not treat services.exe as a false positive signal.
3. **Cross-reference with Event ID 7045** in the Windows System log to get the ServiceName, ServiceType, and StartType in one view.
4. **Check for the service on other hosts.** If an attacker creates a service on one machine, they may have done the same across the network. Search for the same ServiceName or binary path across all endpoints.
5. **Look for the originating process.** Query Event ID 1 (Process Creation) around the same timestamp for sc.exe or PowerShell with service-creation arguments. This surfaces the tool the attacker used.
6. **Escalate or document.** Unknown binary path outside trusted directories = escalate to IR. Known software = add to exclusions and document.

---

## 9. MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Technique** | T1543.003 — Create or Modify System Process: Windows Service |
| **Tactic** | Persistence (TA0003) |
| **Also maps to** | Privilege Escalation (TA0004) — services run as SYSTEM |
| **Data source** | Windows Registry (DS0024), Process (DS0009) |
| **Detection** | Monitor registry writes to CurrentControlSet\Services with non-standard binary paths |

---

## 10. Detection Coverage Assessment

| Attack Method | Detected by This Rule |
|---|---|
| sc.exe create (command line) | YES |
| PowerShell New-Service cmdlet | YES |
| Direct registry write via reg.exe | YES |
| Custom malware writing to SCM registry key | YES |
| Legitimate software with non-standard path | POSSIBLE (investigate, then exclude) |

This rule detects the outcome (registry write with suspicious binary path) rather than the tool, giving it broad coverage across all service creation methods.
