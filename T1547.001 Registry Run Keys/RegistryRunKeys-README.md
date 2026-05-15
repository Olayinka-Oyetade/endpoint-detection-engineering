# T1547.001 — Registry Run Key Persistence

**Tactic:** Persistence (TA0003)
**Tool:** Splunk + Sysmon
**Log Source:** Sysmon Event ID 13 (RegistryValueSet)
**Detection Status:** Confirmed True Positive
**Report ID:** IR-2026-001

---

## Overview

This folder documents the full detection engineering workflow for MITRE ATT&CK technique T1547.001 — Registry Run Key Persistence.

The attacker used PowerShell to write a malicious entry named "WindowsUpdate" to the HKCU Run key, pointing to a payload in C:\Users\Public. The key name was chosen to appear indistinguishable from a legitimate Windows entry. The payload would execute automatically on every user login — no administrator privileges required, no further attacker action needed.

Detection was achieved through Sysmon Event ID 13 monitoring registry writes to the Run key path, with source process and payload path analysis used to confirm the true positive. Alert fired within 5 minutes of attack execution, before the payload had run.

---

## Why This Technique Matters

Registry Run keys are one of the most widely abused persistence mechanisms in real-world attacks:

- No administrator privileges required (HKCU path)
- Survives reboots indefinitely
- Executes automatically on every user login
- Key name can be disguised as any legitimate Windows entry
- Used by Emotet, TrickBot, Remcos RAT, Agent Tesla, and ransomware families

Detecting unauthorised Run key modifications is a foundational SOC capability. This technique appears in incident investigations across organisations of every size, every week.

---

## Attack Summary

| Field | Detail |
|---|---|
| **Attack method** | PowerShell New-ItemProperty |
| **Registry path** | HKCU\Software\Microsoft\Windows\CurrentVersion\Run |
| **Key name** | WindowsUpdate (disguised as legitimate) |
| **Payload path** | C:\Users\Public\malware.exe |
| **Privileges required** | Standard user — no admin needed |
| **Trigger** | Executes automatically on every user login |

---

## Detection Summary

| Field | Detail |
|---|---|
| **Primary detection** | Sysmon Event ID 13 — RegistryValueSet on Run key path |
| **Key indicators** | PowerShell as source process + payload in world-writable directory |
| **Alert time** | Under 5 minutes from attack execution |
| **Detection stage** | Pre-execution — payload had not yet run |
| **False positives** | 0 after source process filtering |
| **Severity** | CRITICAL |

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Technique** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |
| **Tactic** | Persistence (TA0003) |
| **Permissions required** | User (HKCU), Administrator (HKLM) |
| **Data source** | Windows Registry (DS0024) |

---

## Files in This Folder

| File | Description |
|---|---|
| `RegistryRunKeys-01-incident-report.md` | Full incident report following SOC documentation standards |
| `RegistryRunKeys-02-detection-logic.md` | SPL queries, field explanations, false positive analysis, investigation runbook |
| `RegistryRunKeys-03-lessons-learned.md` | What worked, what needed tuning, and what to do differently |
| `RegistryRunKeys-04-portfolio-case-study.md` | End to end investigation walkthrough from alert to resolution |

---

## Key Finding

Pre-execution detection was achieved. The Run key was identified and removed before the payload executed on login. Source process context (PowerShell) combined with a world-writable payload path (C:\Users\Public) made this a zero-ambiguity true positive, demonstrating that behaviour-based detection catches this technique regardless of the malware family or payload used.
