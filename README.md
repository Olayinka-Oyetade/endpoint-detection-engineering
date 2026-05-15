# Endpoint Detection Engineering | Splunk, Sysmon, MITRE ATT&CK

A Windows endpoint detection engineering project built to simulate, detect, and investigate real-world adversary persistence and credential access techniques using Splunk, Sysmon, and Windows Event Logs.

This project documents four complete attack simulations mapped to MITRE ATT&CK. Each simulation covers the full detection engineering workflow: lab setup, attack execution, Splunk detection rule development, alert validation, structured incident documentation, and lessons learned.

---

## Project Overview

| Technique | MITRE ID | Tactic | Detection Method |
|---|---|---|---|
| LSASS Credential Dumping | T1003.001 | Credential Access | Sysmon Event ID 10 (ProcessAccess) |
| Malicious Service Creation | T1543.003 | Persistence | Sysmon Event ID 13 (RegistryValueSet) |
| Registry Run Key Persistence | T1547.001 | Persistence | Sysmon Event ID 13 (RegistryValueSet) |
| Scheduled Task Persistence | T1053.005 | Persistence | Sysmon Event ID 1 (Process Creation) |

All four simulations resulted in confirmed true positive detections. Zero false positives after tuning.

---

## Environment

| Component | Detail |
|---|---|
| **OS** | Windows 10 (WINDOWSVM10) |
| **SIEM** | Splunk (Free Tier) |
| **Telemetry** | Sysmon with custom ruleset |
| **Log forwarding** | Splunk Universal Forwarder |
| **Detection framework** | MITRE ATT&CK |
| **Documentation standard** | ServiceNow-style incident reporting |

---

## Repository Structure

Each folder contains a complete investigation package for one attack simulation:

```
endpoint-detection-engineering/
│
├── T1003.001-LSASS-Credential-Dumping/
│   ├── README.md
│   ├── LSASS-01-incident-report.md
│   ├── LSASS-02-detection-logic.md
│   ├── LSASS-03-lessons-learned.md
│   └── LSASS-04-portfolio-case-study.md
│
├── T1543.003-Malicious-Service-Creation/
│   ├── README.md
│   ├── ServiceCreation-01-incident-report.md
│   ├── ServiceCreation-02-detection-logic.md
│   ├── ServiceCreation-03-lessons-learned.md
│   └── ServiceCreation-04-portfolio-case-study.md
│
├── T1547.001-Registry-Run-Keys/
│   ├── README.md
│   ├── RegistryRunKeys-01-incident-report.md
│   ├── RegistryRunKeys-02-detection-logic.md
│   ├── RegistryRunKeys-03-lessons-learned.md
│   └── RegistryRunKeys-04-portfolio-case-study.md
│
└── T1053.005-Scheduled-Tasks/
    ├── README.md
    ├── ScheduledTasks-01-incident-report.md
    ├── ScheduledTasks-02-detection-logic.md
    ├── ScheduledTasks-03-lessons-learned.md
    └── ScheduledTasks-04-portfolio-case-study.md
```

---

## Simulations

### T1003.001 — LSASS Credential Dumping

LSASS (Local Security Authority Subsystem Service) stores active user credentials in memory. An attacker with local administrator access used Windows Task Manager to create a full memory dump of the LSASS process, exposing all cached credentials on the machine.

**Detection:** Sysmon Event ID 10 (ProcessAccess) flagged a non-system process accessing lsass.exe with GrantedAccess value 0x1fffff (PROCESS_ALL_ACCESS). Corroborated by Event ID 11 (FileCreate) logging the dump file written to the Temp directory.

**Result:** Alert fired within 3 minutes. True positive confirmed. Zero false positives.

---

### T1543.003 — Malicious Service Creation

A Windows service named "WindowsHealthSvc" was created using sc.exe, configured to execute a payload automatically at every system boot under SYSTEM privileges. The service name was chosen to blend in with legitimate Windows background processes.

**Detection:** Sysmon Event ID 13 (RegistryValueSet) caught the service binary path written to `HKLM\SYSTEM\CurrentControlSet\Services\WindowsHealthSvc\ImagePath`. The binary path (cmd.exe /c malware.exe) was the definitive indicator — no legitimate service points to cmd.exe.

**Result:** Alert fired within 5 minutes. True positive confirmed. Zero false positives after removing LocalSystem filter.

---

### T1547.001 — Registry Run Key Persistence

PowerShell wrote a malicious entry named "WindowsUpdate" to the HKCU Run key, pointing to a payload in C:\Users\Public. The entry name was chosen to appear indistinguishable from a legitimate Windows startup entry. No administrator privileges were required.

**Detection:** Sysmon Event ID 13 (RegistryValueSet) captured the source process (powershell.exe), full registry path, and payload location in a single event. PowerShell modifying a Run key with a payload in a world-writable directory is a zero-ambiguity true positive.

**Result:** Alert fired within 5 minutes. Pre-execution detection — payload had not yet run. Zero false positives.

---

### T1053.005 — Scheduled Task Persistence

A scheduled task named "MicrosoftEdgeUpdateTaskCore" was registered via PowerShell, configured to execute a payload every 5 minutes under SYSTEM privileges with RunLevel Highest. The task name mirrors the naming convention of legitimate Microsoft scheduled tasks.

**Detection:** Sysmon Event ID 1 (Process Creation) captured the full PowerShell command including task name, payload path, trigger interval, and privilege level. Corroborated by Event ID 11 logging the task XML file written to C:\Windows\System32\Tasks\.

**Result:** Alert fired within 3 minutes — before the first 5-minute trigger elapsed. Pre-execution detection. Zero false positives.

---

## Documentation Standard

Each simulation includes four documents:

| Document | Contents |
|---|---|
| **Incident Report** | Executive summary, timeline, attack narrative, detection details, impact assessment, response actions, recommendations |
| **Detection Logic** | SPL queries, key field explanations, exclusion logic, false positive analysis, alert configuration, investigation runbook, MITRE mapping |
| **Lessons Learned** | What worked, what needed tuning, what to do differently, key takeaways for SOC work |
| **Portfolio Case Study** | End to end investigation walkthrough written for a security hiring audience |

---

## Skills Demonstrated

- Splunk SPL detection rule development and alert configuration
- Sysmon event log analysis across Event ID 1, 10, 11, and 13
- MITRE ATT&CK technique mapping and triage
- Detection tuning and false positive reduction
- Structured incident documentation to SOC standard
- Behaviour-based detection over signature-based detection
- End to end investigation workflow: alert, triage, investigation, containment, documentation

---

## Analyst

**Olayinka Daniel Oyetade** | SOC Analyst | Toronto, Canada

[LinkedIn](https://www.linkedin.com/in/olayinka-oyetade-0120171a2/) · [Portfolio](https://olayinkaoyetade.com)
