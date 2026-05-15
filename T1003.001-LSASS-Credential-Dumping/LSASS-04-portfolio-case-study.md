# Portfolio Case Study
## Detecting LSASS Credential Dumping with Splunk and Sysmon

---

| Field | Detail |
|---|---|
| **Document ID** | CS-2026-002 |
| **Date** | May 5, 2026 |
| **Analyst** | Olayinka Daniel Oyetade |
| **MITRE ATT&CK** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Tactic** | Credential Access (TA0006) |
| **Tools** | Splunk, Sysmon, Windows Event Logs |
| **Outcome** | Detection confirmed, alert validated, investigation completed |

---

## The Problem

Credential theft is one of the most damaging actions an attacker can take after gaining initial access. Windows stores active user credentials in a process called LSASS — Local Security Authority Subsystem Service. Any attacker with local administrator access can dump the memory of that process and extract password hashes, Kerberos tickets, or in some configurations, plaintext credentials.

Those credentials do not need to be cracked. They can be used immediately to authenticate to other systems on the network as the affected user. This is how a single compromised endpoint becomes a network-wide breach.

The question this simulation set out to answer: **can the detection pipeline catch this before the credentials are used?**

---

## The Setup

**Environment:** Windows 10 virtual machine running in an isolated lab network.

**Telemetry:** Sysmon configured with a custom rule set to capture process creation, process access, file creation, and registry modification events. Logs forwarded to Splunk via the Universal Forwarder.

**Detection:** Two Splunk rules running on a 5-minute schedule:
- Primary: Sysmon Event ID 10 (ProcessAccess) filtering for lsass.exe as the target with suspicious GrantedAccess values.
- Secondary: Sysmon Event ID 11 (FileCreate) looking for .dmp files created in user-accessible directories.

**Alerting:** Automated email notification triggered on any result match.

---

## The Attack

The attack used Windows Task Manager — a built-in tool present on every Windows machine, requiring no malware download, no custom tooling, and no antivirus evasion. The attacker right-clicked lsass.exe in the Task Manager process list and selected "Create dump file."

Windows wrote a complete memory dump of the LSASS process to `C:\Users\[username]\AppData\Local\Temp\lsass.DMP`.

This file contains all credential material currently cached on the machine. In a real attack, the next step is exfiltrating this file and running it through Mimikatz or a similar tool offline to extract the hashes.

The simplicity of the attack method is the point. Defenders who only look for known attack tools miss this entirely. The detection rule targets the behaviour — a non-system process accessing LSASS with maximum access rights — not the tool name.

---

## The Detection

**Time from attack execution to alert: under 3 minutes.**

Sysmon Event ID 10 fired immediately when Task Manager accessed LSASS. The key fields in the event:

- **SourceImage:** `C:\Windows\System32\taskmgr.exe`
- **TargetImage:** `C:\Windows\System32\lsass.exe`
- **GrantedAccess:** `0x1fffff` (PROCESS_ALL_ACCESS)

The Splunk detection rule matched on the next scheduled search cycle. The exclusion list confirmed taskmgr.exe is not a known legitimate accessor of LSASS. GrantedAccess 0x1fffff is the maximum possible value — no legitimate diagnostic tool requests this level of access to the credential store.

Sysmon Event ID 11 corroborated the detection by logging the creation of `lsass.DMP` in the Temp directory within seconds of the ProcessAccess event.

The automated email alert delivered both events to the analyst inbox with full context.

---

## The Investigation

The investigation followed a structured Tier 1 SOC workflow:

**Step 1 — Triage the alert.**
Confirmed the SourceImage (taskmgr.exe) is not on the exclusion list and is not a known security tool. Escalation threshold met.

**Step 2 — Assess the GrantedAccess value.**
0x1fffff = PROCESS_ALL_ACCESS. This is not a value seen in legitimate system operations. Confirmed high-confidence true positive.

**Step 3 — Corroborate with secondary event.**
Matched the ProcessAccess event timestamp against Event ID 11. Dump file confirmed written to Temp directory 45 seconds after the access event. Two independent log sources confirming the same attack.

**Step 4 — Scope the incident.**
Checked for authentication events (Windows Event ID 4624) originating from the affected host to other lab machines. No lateral movement detected — isolated lab environment with no other hosts to pivot to.

**Step 5 — Document and close.**
Incident report written following SOC documentation standards. Case closed as Confirmed True Positive.

---

## The Result

| Metric | Result |
|---|---|
| **Detection time** | Under 3 minutes from attack execution |
| **Alert accuracy** | True Positive confirmed |
| **False positives** | 0 during simulation window |
| **Investigation time** | Under 15 minutes from alert to closure |
| **Documentation** | Completed to SOC standard |

---

## What This Demonstrates

**Behaviour-based detection over signature-based detection.** The rule does not look for Mimikatz, ProcDump, or any named tool. It looks for the action: a non-system process accessing LSASS with high access rights. This approach catches known tools, modified tools, and novel tools that exhibit the same behaviour.

**Log correlation as an investigation multiplier.** Combining Event ID 10 and Event ID 11 gave two independent data points confirming the same attack. Either alone is sufficient to alert. Together they make the investigation conclusion airtight.

**Alert enrichment reduces investigation time.** Because the Splunk alert included SourceImage, TargetImage, GrantedAccess, and a file path in the alert email itself, the analyst did not need to go back into Splunk to begin the investigation. Context in the alert equals faster response.

**Structured documentation under operational conditions.** The incident report, detection documentation, lessons learned, and this case study were completed following the same format used in professional SOC environments. Clean documentation is a force multiplier across shifts — the next analyst who sees this alert knows exactly what to look for and what it means.

---

## Next Steps

1. Expand the simulation to use comsvcs.dll (a signed Windows binary) to test rule coverage against Living Off the Land techniques.
2. Write a Sigma version of the detection rule to make it portable across SIEM platforms.
3. Add parent process tracking to the investigation workflow to capture attack chain context.
4. Integrate network log correlation to detect credential use for lateral movement following a successful dump.
