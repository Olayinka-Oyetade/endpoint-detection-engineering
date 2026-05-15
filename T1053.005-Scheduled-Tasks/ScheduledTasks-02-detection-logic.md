# Detection Rule Documentation
## T1053.005 — Scheduled Task/Job: Scheduled Task

---

| Field | Detail |
|---|---|
| **Document ID** | DET-2026-004 |
| **Date** | May 13, 2026 |
| **Analyst** | Olayinka Daniel Oyetade |
| **MITRE ATT&CK** | T1053.005 — Scheduled Task/Job: Scheduled Task |
| **Tactic** | Persistence (TA0003) |
| **Detection Tool** | Splunk + Sysmon |
| **Log Sources** | Sysmon Event ID 1 (Process Creation), Sysmon Event ID 11 (FileCreate) |
| **Severity** | HIGH |

---

## 1. Technique Overview

Windows Task Scheduler is a built-in system component that allows programs to execute automatically based on configured triggers — time intervals, system startup, user login, or specific system events. Unlike registry run keys that only fire on login, scheduled tasks can be configured to run on any trigger, making them significantly more flexible as a persistence mechanism.

Attackers with administrator access can register tasks that run under SYSTEM privileges, execute payloads on a repeating timer without any user interaction, and disguise the task with names that mimic legitimate Windows or software vendor entries.

This technique is used extensively by Emotet, TrickBot, APT29, Cobalt Strike-based intrusions, and ransomware operators. It appears in the majority of sophisticated intrusion investigations because of its reliability, stealth, and the high privilege level it provides.

---

## 2. Detection Logic

### Primary Rule — PowerShell Task Registration (Sysmon Event ID 1)

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
Image="*\\powershell.exe"
CommandLine="*Register-ScheduledTask*"
NOT CommandLine IN (
  "*\\WindowsPowerShell\\Modules\\*",
  "*ScheduledTasks\\*"
)
| eval Risk=case(
    match(CommandLine, "(?i)(temp|appdata|public|users\\\\[^\\\\]+\\\\)"), "CRITICAL",
    match(CommandLine, "(?i)(Highest|SYSTEM)"), "HIGH",
    true(), "MEDIUM"
  )
| table _time, host, User, CommandLine, ParentImage, IntegrityLevel, Risk
| sort -_time
```

### Secondary Rule — schtasks.exe Usage (Sysmon Event ID 1)

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
Image="*\\schtasks.exe"
CommandLine="*/create*"
NOT ParentImage IN (
  "*\\msiexec.exe",
  "*\\TrustedInstaller.exe",
  "*\\WmiPrvSE.exe"
)
| eval Risk=case(
    match(CommandLine, "(?i)(temp|appdata|public|cmd\.exe|powershell)"), "CRITICAL",
    match(CommandLine, "(?i)(SYSTEM|Highest|/ru system)"), "HIGH",
    true(), "MEDIUM"
  )
| table _time, host, User, CommandLine, ParentImage, Risk
| sort -_time
```

### Tertiary Rule — Task XML File Creation (Sysmon Event ID 11)

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11
TargetFilename="*\\System32\\Tasks\\*"
NOT Image IN (
  "*\\svchost.exe",
  "*\\taskeng.exe",
  "*\\taskhostw.exe",
  "*\\TaskSchedulerHelper.dll"
)
| table _time, host, Image, TargetFilename
| sort -_time
```

**Why three rules:** Attackers use different methods to create tasks. PowerShell Register-ScheduledTask, schtasks.exe from cmd, and direct COM API calls all produce different log signatures. The task XML file creation rule catches all methods through a single shared outcome — every registered task writes a file to `System32\Tasks\` regardless of how it was created.

---

## 3. Key Fields Explained

| Field | Description | Why It Matters |
|---|---|---|
| `EventCode` | Sysmon event type | 1 = Process Creation, 11 = FileCreate |
| `Image` | Process creating the task | PowerShell or schtasks.exe registering tasks is suspicious |
| `CommandLine` | Full command line arguments | Contains task name, payload path, trigger, and privilege level |
| `ParentImage` | Process that spawned the creator | cmd.exe or Office spawning PowerShell is a red flag |
| `IntegrityLevel` | Process privilege context | High = administrator context |
| `TargetFilename` | Task XML file path (Event ID 11) | Every registered task creates a file in System32\Tasks |

---

## 4. High-Risk Indicators in CommandLine

| Indicator | Risk | Reason |
|---|---|---|
| Payload in `C:\Windows\Temp\` | CRITICAL | Standard install location for attacker-dropped files |
| Payload in `AppData\` | CRITICAL | User-writable, common malware staging location |
| Payload in `C:\Users\Public\` | CRITICAL | World-writable, no admin needed |
| `RunLevel Highest` or `SYSTEM` | HIGH | Maximum privilege — legitimate software rarely needs this |
| `cmd.exe` or `powershell.exe` as payload | CRITICAL | No legitimate task launches cmd or PowerShell directly as payload |
| Repetition interval under 10 minutes | HIGH | Legitimate software does not poll every few minutes |

---

## 5. Exclusion Logic

| Excluded Process/Path | Reason |
|---|---|
| `msiexec.exe` as ParentImage | Windows Installer creating tasks during software deployment |
| `TrustedInstaller.exe` as ParentImage | Windows Update component |
| `svchost.exe` writing task files | Normal — SCM writes task XML via svchost |
| `WindowsPowerShell\Modules\*` in CommandLine | Module-based task management by IT tools |

**Tuning note:** In a production environment, enterprise software deployment tools (SCCM, Intune, PDQ Deploy) regularly create scheduled tasks. These should be identified in the environment and added to exclusions. Build exclusions from a known-good baseline rather than guessing.

---

## 6. Alert Configuration

| Setting | Value |
|---|---|
| **Schedule** | Every 5 minutes |
| **Trigger condition** | Results count > 0 |
| **Trigger once** | Per result |
| **Alert action** | Send email to analyst |
| **Severity label** | CRITICAL / HIGH / MEDIUM (based on eval logic) |

---

## 7. False Positive Analysis

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Software installer creating a scheduled task | HIGH | Add installer parent process to exclusions |
| IT deployment tool creating maintenance tasks | HIGH | Whitelist deployment tool processes |
| Antivirus or EDR creating update tasks | MEDIUM | Add security tool paths to exclusions |
| Developer registering a task during testing | LOW | Alert on task payload path — legitimate paths are in Program Files |
| Windows Update creating temporary tasks | LOW | TrustedInstaller and svchost already excluded |

**False positive rate in this lab:** 0 (clean environment with no enterprise software deployment tools)

---

## 8. Investigation Runbook

When this alert fires:

1. **Read the CommandLine in full.** The entire attack is visible: task name, payload path, trigger interval, privilege level. This is the most information-dense field in the alert.
2. **Assess the payload path.** Temp, AppData, or Public directories are immediate escalation triggers. Program Files or System32 warrants verification but is lower risk.
3. **Check the task name.** Compare against a known-good task list. Names that mimic Microsoft or vendor patterns (MicrosoftEdgeUpdateTaskCore, WindowsDefenderUpdate) require confirmation they are legitimate.
4. **Review ParentImage.** PowerShell spawned by cmd.exe, Office applications, or browser processes is a high-confidence attack chain indicator.
5. **Correlate with Event ID 11.** Confirm the task XML file was written to System32\Tasks — this confirms successful registration, not just an attempt.
6. **Check for payload execution.** Query Event ID 1 for the payload process. Has it already run? If yes, expand the investigation scope to include network connections and file modifications.
7. **Remediate.** Unregister the task, remove the payload file, verify the host is clean.

---

## 9. MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Technique** | T1053.005 — Scheduled Task/Job: Scheduled Task |
| **Tactic** | Persistence (TA0003) |
| **Also maps to** | Privilege Escalation (TA0004) — tasks run under SYSTEM |
| **Data sources** | Scheduled Job (DS0003), Process (DS0009), File (DS0022) |
| **Detection** | Monitor process creation for task registration tools with suspicious payload paths |

---

## 10. Detection Coverage Assessment

| Attack Method | Detected |
|---|---|
| PowerShell Register-ScheduledTask | YES — Primary rule |
| schtasks.exe /create from cmd.exe | YES — Secondary rule |
| schtasks.exe /create from PowerShell | YES — Both primary and secondary |
| COM-based task creation (direct API) | YES — Tertiary rule (task file always written) |
| Task created with legitimate binary path | PARTIAL — Flags for review, may be false positive |
| Task created via WMI | YES — Process creation event captured |
