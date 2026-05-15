# Portfolio Case Study
## Detecting Malicious Scheduled Task Persistence with Splunk and Sysmon

---

| Field | Detail |
|---|---|
| **Document ID** | CS-2026-004 |
| **Date** | May 13, 2026 |
| **Analyst** | Olayinka Daniel Oyetade |
| **MITRE ATT&CK** | T1053.005 — Scheduled Task/Job: Scheduled Task |
| **Tactic** | Persistence (TA0003) |
| **Tools** | Splunk, Sysmon, Windows Event Logs |
| **Outcome** | Detection confirmed, alert validated, investigation completed |

---

## The Problem

Scheduled tasks are one of the most powerful persistence mechanisms available on Windows because they are not tied to user activity. A registry run key waits for a user to log in. A scheduled task fires on a timer — every 5 minutes, every hour, at boot — regardless of whether anyone is logged in, regardless of who is logged in, and regardless of what they are doing.

An attacker who registers a scheduled task and disconnects from the network will still receive a payload callback at the next trigger interval. The machine does the work for them.

This technique is used by Emotet, TrickBot, APT29, and ransomware operators. It appears in sophisticated intrusion investigations because it combines reliability, stealth, and SYSTEM-level privilege into a single command.

The question this simulation set out to answer: **can the detection pipeline identify a malicious scheduled task within the first trigger interval — before the payload executes?**

---

## The Setup

**Environment:** Windows 10 virtual machine running in an isolated lab network.

**Telemetry:** Sysmon capturing process creation (Event ID 1) with full command line logging, and file creation (Event ID 11) for task XML files written to System32\Tasks. All logs forwarded to Splunk via the Universal Forwarder.

**Detection:** Three complementary Splunk rules:
- Primary: PowerShell Register-ScheduledTask with payload path risk scoring
- Secondary: schtasks.exe /create from cmd.exe or non-standard parent processes
- Tertiary: Task XML file written to System32\Tasks by a non-standard process

**Alerting:** Automated email with CRITICAL, HIGH, or MEDIUM severity based on payload path and privilege level analysis.

---

## The Attack

The attacker registered a malicious scheduled task in four PowerShell lines:

```powershell
$action = New-ScheduledTaskAction -Execute "C:\Windows\Temp\payload.exe"
$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskCore" -Action $action -Trigger $trigger -Principal $principal -Force
```

**The task name:** "MicrosoftEdgeUpdateTaskCore" mirrors the naming pattern of real Microsoft tasks. On any standard Windows machine, Task Scheduler contains entries like "MicrosoftEdgeUpdateTaskMachineCore" and "GoogleUpdateTaskMachineCore". The attacker chose this name to blend into the task list and evade casual inspection.

**The payload:** `C:\Windows\Temp\payload.exe` — placed in the Windows Temp directory, a commonly overlooked location that does not immediately raise suspicion the way a file in AppData\Roaming might.

**The trigger:** Every 5 minutes from the moment of creation. Indefinitely.

**The privilege:** SYSTEM with RunLevel Highest — maximum access to the machine.

From this point, the attacker could disconnect entirely. payload.exe would run as SYSTEM every 5 minutes until discovered and removed.

---

## The Detection

**Time from attack execution to alert: under 3 minutes — before the first trigger interval elapsed.**

Sysmon Event ID 1 captured the PowerShell process with the full command line:

- **Image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **CommandLine:** Full Register-ScheduledTask command including task name, payload path, SYSTEM principal, and RunLevel Highest
- **ParentImage:** `C:\Windows\System32\cmd.exe`
- **IntegrityLevel:** High

Sysmon Event ID 11 independently confirmed the task was successfully registered by logging the XML file written to `C:\Windows\System32\Tasks\MicrosoftEdgeUpdateTaskCore`.

The Splunk detection rule matched on the next scheduled search cycle. The eval logic assigned CRITICAL severity based on the payload path in `C:\Windows\Temp\`. The alert email included the full command line, giving the analyst the complete picture before opening a single dashboard.

---

## The Investigation

**Step 1 — Read the CommandLine.**
The full attack was visible in one field: task name, payload path, every-5-minutes trigger, SYSTEM principal, RunLevel Highest. Immediate escalation signal on every dimension.

**Step 2 — Assess the payload path.**
`C:\Windows\Temp\payload.exe` — a temp directory is not a legitimate software installation location. CRITICAL severity confirmed.

**Step 3 — Evaluate the task name.**
"MicrosoftEdgeUpdateTaskCore" is designed to look legitimate. Compared against the known task baseline for this environment — no legitimate software with this exact task name. Confirmed as attacker-created.

**Step 4 — Corroborate with Event ID 11.**
Task XML file confirmed written to System32\Tasks. Task successfully registered — not just an attempt.

**Step 5 — Check for payload execution.**
Queried Event ID 1 for payload.exe process creation. No execution events found — detection was pre-execution. The 5-minute trigger interval had not elapsed before the alert fired and investigation began.

**Step 6 — Remediate and close.**
Task unregistered via PowerShell. Removal confirmed. Incident documented and closed as Confirmed True Positive.

---

## The Result

| Metric | Result |
|---|---|
| **Detection time** | Under 3 minutes from task registration |
| **Detection stage** | Pre-execution — payload had not yet fired |
| **Alert accuracy** | True Positive confirmed |
| **False positives** | 0 after payload path filtering |
| **Investigation time** | Under 15 minutes from alert to closure |
| **Remediation** | Task removed, removal verified |

---

## What This Demonstrates

**Pre-execution detection against a timer-based persistence mechanism.** The task was registered to fire every 5 minutes. The detection fired in under 3. In a real environment, this means the analyst has a window to contain the threat before the payload executes a single time. That window matters.

**Task name disguise does not evade behaviour-based detection.** The attacker chose a task name designed to look like a Microsoft entry. The detection rule does not check the task name — it checks the payload path and the process creating the task. An attacker can name a task anything and the rule still fires.

**Three detection rules for one technique reflects production thinking.** Attackers use PowerShell, schtasks.exe, COM APIs, and WMI to register tasks — each producing different log signatures. A single rule has blind spots. This simulation validated three complementary rules that together cover every documented execution path for T1053.005.

**Full attack visibility from a single event field.** The CommandLine field in Sysmon Event ID 1 contained the task name, payload, trigger, privilege level, and user context in one string. Analysts who can parse command lines quickly will triage these alerts significantly faster. Building that skill is directly applicable to day-one Tier 1 SOC work.

---

## Next Steps

1. Add Windows Security Event ID 4698 (scheduled task created) as a third independent log source, providing detection coverage in environments without Sysmon.
2. Build a task name allowlist for the lab environment and alert on any registration not in the approved list.
3. Test detection coverage against COM-based task creation (direct API, no PowerShell or schtasks.exe) to validate that the Event ID 11 tertiary rule alone is sufficient.
4. Write a Sigma version of all three detection rules for portability across SIEM platforms.
5. Integrate network flow correlation into the investigation runbook to assess payload command-and-control activity at the point of alert.
