# T1053.005 — Malicious Scheduled Task Persistence

**Tactic:** Persistence (TA0003)
**Tool:** Splunk + Sysmon
**Log Sources:** Sysmon Event ID 1 (Process Creation), Sysmon Event ID 11 (FileCreate)
**Detection Status:** Confirmed True Positive
**Report ID:** IR-2026-004

---

## Overview

This folder documents the full detection engineering workflow for MITRE ATT&CK technique T1053.005 — Scheduled Task Persistence.

The attacker used PowerShell to register a malicious scheduled task named "MicrosoftEdgeUpdateTaskCore" — chosen to mirror the naming pattern of legitimate Microsoft tasks and evade casual inspection. The task was configured to execute a payload from the Windows Temp directory every 5 minutes under SYSTEM privileges with RunLevel Highest.

Unlike registry run keys that require a user to log in, this task fires on a timer regardless of user activity. Detection was achieved within 3 minutes of task registration — before the first trigger interval elapsed and before the payload executed a single time.

---

## Why This Technique Matters

Scheduled tasks are among the most dangerous persistence mechanisms on Windows:

- Fire on a timer — no user login required
- Run under SYSTEM privilege with RunLevel Highest
- Survive reboots indefinitely
- Task names can be disguised to mimic legitimate Windows entries
- Used by Emotet, TrickBot, APT29, Cobalt Strike, and ransomware operators

Detection before the first trigger interval is the goal. This simulation achieved it.

---

## Attack Summary

| Field | Detail |
|---|---|
| **Attack method** | PowerShell Register-ScheduledTask cmdlet |
| **Task name** | MicrosoftEdgeUpdateTaskCore (disguised as legitimate) |
| **Payload path** | C:\Windows\Temp\payload.exe |
| **Trigger** | Every 5 minutes from time of creation |
| **Privileges** | SYSTEM / RunLevel Highest |
| **Task XML written to** | C:\Windows\System32\Tasks\MicrosoftEdgeUpdateTaskCore |

---

## Detection Summary

| Field | Detail |
|---|---|
| **Primary detection** | Sysmon Event ID 1 — PowerShell Register-ScheduledTask with suspicious payload path |
| **Secondary detection** | Sysmon Event ID 11 — Task XML file written to System32\Tasks |
| **Key indicator** | Payload in C:\Windows\Temp (non-standard installation location) |
| **Alert time** | Under 3 minutes from task registration |
| **Detection stage** | Pre-execution — payload had not yet fired |
| **False positives** | 0 after payload path filtering |
| **Severity** | CRITICAL |

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Technique** | T1053.005 — Scheduled Task/Job: Scheduled Task |
| **Tactic** | Persistence (TA0003) |
| **Also relevant** | Privilege Escalation (TA0004) — tasks execute as SYSTEM |
| **Data sources** | Scheduled Job (DS0003), Process (DS0009), File (DS0022) |

---

## Files in This Folder

| File | Description |
|---|---|
| `ScheduledTasks-01-incident-report.md` | Full incident report following SOC documentation standards |
| `ScheduledTasks-02-detection-logic.md` | Three SPL detection rules, field explanations, false positive analysis, investigation runbook |
| `ScheduledTasks-03-lessons-learned.md` | What worked, what needed tuning, and what to do differently |
| `ScheduledTasks-04-portfolio-case-study.md` | End to end investigation walkthrough from alert to resolution |

---

## Key Finding

Pre-execution detection was achieved. The task was identified and removed before the 5-minute trigger interval elapsed and before payload.exe ran a single time. The disguised task name did not evade detection because the rule targets payload path behaviour, not task name strings — making it effective against any task pointing to a non-standard executable location regardless of how it is named.
