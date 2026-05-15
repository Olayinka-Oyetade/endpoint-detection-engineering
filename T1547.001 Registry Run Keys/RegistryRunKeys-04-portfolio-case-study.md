# Portfolio Case Study
## Detecting Registry Run Key Persistence with Splunk and Sysmon

---

| Field | Detail |
|---|---|
| **Document ID** | CS-2026-001 |
| **Date** | May 5, 2026 |
| **Analyst** | Olayinka Daniel Oyetade |
| **MITRE ATT&CK** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |
| **Tactic** | Persistence (TA0003) |
| **Tools** | Splunk, Sysmon, Windows Event Logs |
| **Outcome** | Detection confirmed, alert validated, investigation completed |

---

## The Problem

After gaining initial access to a machine, an attacker's next priority is persistence — ensuring they can return even after the user logs out or the machine reboots. Registry Run keys are one of the oldest and most widely abused persistence mechanisms in Windows because they are simple, reliable, and require no administrator privileges when written to the HKCU hive.

A single PowerShell command is enough. The key survives reboots, executes silently on every login, and can be named anything the attacker wants — making it trivially easy to disguise as a legitimate Windows entry.

Malware families including Emotet, TrickBot, Remcos RAT, and Agent Tesla all use this technique. It appears in incident investigations every week across organisations of every size.

The question this simulation set out to answer: **can the detection pipeline identify a malicious Run key before the payload executes on first login?**

---

## The Setup

**Environment:** Windows 10 virtual machine running in an isolated lab network, user account WINDOWSVM10\mrdaniel198.

**Telemetry:** Sysmon configured with a rule set that captures registry value modifications (Event ID 13) with full field context. Logs forwarded to Splunk via the Universal Forwarder.

**Detection:** Splunk rule monitoring writes to `CurrentVersion\Run` and `CurrentVersion\RunOnce` paths, with source process and payload path risk scoring to separate high-confidence true positives from routine software installer activity.

**Alerting:** Automated email notification with CRITICAL or HIGH severity label based on source process and payload path analysis.

---

## The Attack

One PowerShell command, no administrator access required:

```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "WindowsUpdate" `
    -Value "C:\Users\Public\malware.exe" `
    -PropertyType String `
    -Force
```

The key name "WindowsUpdate" was chosen deliberately. In a real attack, an analyst doing a quick visual scan of the Run key would see "WindowsUpdate" and assume it is a legitimate Microsoft entry. Investigation would be required to confirm it is not.

The payload path pointed to `C:\Users\Public\malware.exe` — a directory any user can write to, requiring no elevated privileges to place a file there.

From this point, the attacker has persistent access. Every time the target user logs in, Windows reads the Run key and executes malware.exe automatically. The attacker can disconnect entirely and return whenever the payload calls home.

---

## The Detection

**Time from attack execution to alert: under 5 minutes.**

Sysmon captured the registry write as Event ID 13 with the following fields:

- **Image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **TargetObject:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate`
- **Details:** `C:\Users\Public\malware.exe`
- **RuleName:** `technique_id=T1547.001, technique_name=Boot or Logon Autostart Execution`

The Splunk detection rule matched on the next scheduled search cycle. The eval logic assigned CRITICAL severity based on two factors: PowerShell as the source process, and a payload path in C:\Users\Public. The alert email communicated urgency before the analyst opened a single dashboard.

---

## The Investigation

**Step 1 — Triage the alert.**
Image = powershell.exe modifying a Run key. Not normal behaviour for standard user activity. Investigation warranted.

**Step 2 — Assess the payload path.**
Details = `C:\Users\Public\malware.exe`. Public is a world-writable directory with no association to legitimate software installations. Combined with PowerShell as the source, this is a confirmed high-confidence true positive.

**Step 3 — Review the key name.**
"WindowsUpdate" is designed to appear legitimate. Cross-referencing against the known software baseline confirmed no legitimate software uses this exact key name in this environment.

**Step 4 — Check for execution.**
Queried Event ID 1 (Process Creation) for malware.exe. No execution events found — the payload had not yet run because no login occurred after the key was written. Detection was pre-execution.

**Step 5 — Check for corroborating file creation.**
Queried Event ID 11 (FileCreate) for C:\Users\Public\malware.exe. Confirmed the file was written to Public before the Run key was created — the full attack chain was visible in the logs.

**Step 6 — Remediate and close.**
Registry key removed via PowerShell. Removal confirmed by follow-up Splunk query. Incident documented and closed as Confirmed True Positive.

---

## The Result

| Metric | Result |
|---|---|
| **Detection time** | Under 5 minutes from attack execution |
| **Detection stage** | Pre-execution — payload had not yet run |
| **Alert accuracy** | True Positive confirmed |
| **False positives** | 0 after source process filtering |
| **Investigation time** | Under 15 minutes from alert to closure |
| **Remediation** | Registry key removed, removal verified |

---

## What This Demonstrates

**Pre-execution detection is the goal.** The most valuable outcome of this simulation was detecting the persistence mechanism before the payload executed. In a real investigation, catching a Run key before the user logs in means the attacker never gets their foothold. Detection at this stage prevents the entire attack chain from progressing.

**No admin rights required does not mean no detection.** The HKCU path is accessible to standard users. Defenders who only monitor HKLM (which requires admin) miss a large proportion of real persistence activity. This simulation validated that the detection covers both hives.

**Source process context is the primary triage signal.** PowerShell writing to a Run key is the signal that moves this from "possible" to "probable" before any other analysis. Building source process risk scoring into the alert means analysts receive pre-triaged information rather than raw event data, reducing time-to-decision significantly.

**Behaviour-based detection catches known and unknown threats.** The detection rule does not know about the specific malware family or payload. It detects the behaviour — a suspicious process writing to a persistence path with a non-standard payload location. Emotet and a novel malware variant written yesterday would both trigger this alert if they use the same technique.

---

## Next Steps

1. Add a lookup table of known good Run key entries for the lab environment and alert on any key not in the approved list — catches evasion attempts using trusted binary paths.
2. Build automatic correlation between Event ID 11 (FileCreate) and Event ID 13 (RegistryValueSet) for the same file path, surfacing the full attack chain in a single alert.
3. Test detection coverage against obfuscated PowerShell (Base64-encoded commands) to confirm the rule fires on the registry write regardless of how the command is disguised.
4. Write a Sigma version of the detection rule for portability across SIEM platforms.
5. Extend coverage to RunOnce, RunServices, and RunServicesOnce keys — all abused for persistence using the same underlying mechanism.
