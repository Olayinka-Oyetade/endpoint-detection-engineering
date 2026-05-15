# T1543.003 — Malicious Windows Service Creation

**Tactic:** Persistence (TA0003)
**Tool:** Splunk + Sysmon
**Log Sources:** Sysmon Event ID 13, Windows Event ID 7045
**Detection Status:** Confirmed True Positive
**Report ID:** IR-2026-003

---

## Overview

This folder documents the full detection engineering workflow for MITRE ATT&CK technique T1543.003 — Windows Service Creation used as a persistence mechanism.

The attacker created a malicious Windows service called "WindowsHealthSvc" — named to blend in with legitimate system services — configured to execute a payload automatically at every system boot under SYSTEM privileges. No user interaction required. No login needed.

Detection was achieved through Sysmon registry monitoring (Event ID 13) targeting the Windows service registry path, with the binary path as the primary indicator. Alert fired within 5 minutes of attack execution.

---

## Why This Technique Matters

A malicious service is one of the most durable persistence mechanisms on Windows:

- Survives reboots indefinitely
- Runs under SYSTEM — the highest privilege level on the machine
- Requires no user to be logged in
- Can be disguised with a legitimate-looking service name

Real-world threat actors that use this technique include ransomware operators, APT groups, and commercial offensive frameworks like Cobalt Strike. Detecting it early — before the payload executes at next reboot — is a Tier 1 SOC priority.

---

## Attack Summary

| Field | Detail |
|---|---|
| **Attack method** | sc.exe via PowerShell with administrator access |
| **Service name** | WindowsHealthSvc |
| **Binary path** | cmd.exe /c malware.exe |
| **Start type** | Auto (executes at every boot) |
| **Privileges** | SYSTEM |
| **Registry key** | HKLM\SYSTEM\CurrentControlSet\Services\WindowsHealthSvc\ImagePath |

---

## Detection Summary

| Field | Detail |
|---|---|
| **Primary detection** | Sysmon Event ID 13 — RegistryValueSet on Services path |
| **Secondary detection** | Windows Event ID 7045 — New service installed |
| **Key indicator** | Binary path (cmd.exe) outside trusted system directories |
| **Alert time** | Under 5 minutes from attack execution |
| **False positives** | 0 after tuning |
| **Severity** | CRITICAL (cmd.exe binary path) |

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| **Technique** | T1543.003 — Create or Modify System Process: Windows Service |
| **Tactic** | Persistence (TA0003) |
| **Also relevant** | Privilege Escalation (TA0004) — services execute as SYSTEM |
| **Data sources** | Windows Registry (DS0024), Process (DS0009) |

---

## Files in This Folder

| File | Description |
|---|---|
| `ServiceCreation-01-incident-report.md` | Full incident report following SOC documentation standards |
| `ServiceCreation-02-detection-logic.md` | SPL queries, field explanations, false positive analysis, investigation runbook |
| `ServiceCreation-03-lessons-learned.md` | What worked, what needed tuning, and what to do differently |
| `ServiceCreation-04-portfolio-case-study.md` | End to end investigation walkthrough from alert to resolution |

---

## Key Finding

The binary path in the Details field of Sysmon Event ID 13 is the highest-fidelity indicator for this technique. No legitimate Windows service or commercial software installs itself by pointing to cmd.exe, PowerShell, or a user-writable directory. This single check delivers near-zero false positives while catching the full range of service-based persistence methods regardless of the tool used to create the service.
