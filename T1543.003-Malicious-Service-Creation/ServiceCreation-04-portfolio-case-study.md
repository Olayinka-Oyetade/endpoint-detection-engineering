# Portfolio Case Study
## Detecting Malicious Windows Service Creation with Splunk and Sysmon

---

| Field | Detail |
|---|---|
| **Document ID** | CS-2026-003 |
| **Date** | May 13, 2026 |
| **Analyst** | Olayinka Daniel Oyetade |
| **MITRE ATT&CK** | T1543.003 — Create or Modify System Process: Windows Service |
| **Tactic** | Persistence (TA0003) |
| **Tools** | Splunk, Sysmon, Windows Event Logs |
| **Outcome** | Detection confirmed, alert validated, investigation completed |

---

## The Problem

Once an attacker has initial access to a Windows machine, their next priority is persistence — ensuring they can return even if the user logs out, the machine reboots, or the initial access vector is closed. Windows services are one of the most powerful persistence mechanisms available because they run automatically at boot, operate under SYSTEM privileges, and require no user interaction.

A single sc.exe command is all it takes. The service registers itself in the Windows registry, survives reboots indefinitely, and runs silently in the background with the highest privileges available on the machine. This technique is used by ransomware groups, nation-state operators, and commercial offensive tools like Cobalt Strike.

The question this simulation set out to answer: **can the detection pipeline identify a malicious service before it executes its payload at next reboot?**

---

## The Setup

**Environment:** Windows 10 virtual machine running in an isolated lab network.

**Telemetry:** Sysmon configured to capture registry value modifications (Event ID 13) alongside Windows System log forwarding (Event ID 7045 — new service installed). All logs forwarded to Splunk via the Universal Forwarder.

**Detection strategy:** Two complementary rules:
- Primary: Sysmon Event ID 13 monitoring registry writes to `CurrentControlSet\Services\*\ImagePath` with binary paths outside trusted system directories.
- Secondary: Windows System Event ID 7045 monitoring new service installations with non-standard executable paths.

**Alerting:** Automated email with severity label (CRITICAL for cmd.exe/PowerShell paths, HIGH for other non-standard paths).

---

## The Attack

The attack required one PowerShell command with administrator access:

```powershell
sc.exe create "WindowsHealthSvc" binPath= "cmd.exe /c malware.exe" start= auto
```

The service name "WindowsHealthSvc" was chosen to appear legitimate — a casual glance at the service list would not raise suspicion. The binary path pointed to cmd.exe launching malware.exe. The start type was set to auto, meaning the payload would execute automatically at every system boot without any further attacker action.

Once registered, the attacker could disconnect entirely. The service would run malware.exe as SYSTEM on every reboot until the service was discovered and removed.

---

## The Detection

**Time from attack execution to alert: under 5 minutes.**

When sc.exe registered the service, the Service Control Manager (services.exe) wrote the service configuration to the Windows registry. Sysmon captured this as Event ID 13 with the following fields:

- **TargetObject:** `HKLM\SYSTEM\CurrentControlSet\Services\WindowsHealthSvc\ImagePath`
- **Details:** `cmd.exe /c malware.exe`
- **Image:** `C:\Windows\System32\services.exe`

The Splunk detection rule matched on the next scheduled search cycle. The binary path (`cmd.exe /c malware.exe`) triggered the CRITICAL severity label. The exclusion list confirmed this path is not in any trusted system directory.

Windows System Event ID 7045 simultaneously logged the new service installation, providing a second independent confirmation from a different log source.

---

## The Investigation

**Step 1 — Triage the alert.**
Reviewed the Details field immediately: `cmd.exe /c malware.exe`. No legitimate Windows service or commercial software uses this binary path pattern. Escalation threshold met without further analysis needed.

**Step 2 — Understand the Image field.**
Image showed services.exe rather than PowerShell or sc.exe. Recognised this as the Service Control Manager acting as intermediary — it physically writes the registry entry on behalf of whatever process called it. This is expected Windows behaviour and does not indicate the detection missed the originating process.

**Step 3 — Cross-reference with Event ID 7045.**
Confirmed the Windows System log also captured the service installation with matching ServiceName (WindowsHealthSvc), ServiceType (own process), and StartType (Auto Start). Two independent log sources confirming the same event.

**Step 4 — Verify service registration.**
Confirmed the service was present and registered in the Service Control Manager with auto-start configuration.

**Step 5 — Scope the incident.**
Checked for the same service name across other lab hosts and for signs of payload execution. No lateral movement in the isolated lab environment.

**Step 6 — Remediate and document.**
Service stopped and removed using PowerShell. Incident report and supporting documentation completed to SOC standard. Case closed as Confirmed True Positive.

---

## The Result

| Metric | Result |
|---|---|
| **Detection time** | Under 5 minutes from attack execution |
| **Alert accuracy** | True Positive confirmed |
| **False positives** | 0 after removing LocalSystem filter |
| **Investigation time** | Under 15 minutes from alert to closure |
| **Remediation** | Service removed, host validated clean |

---

## What This Demonstrates

**Outcome-based detection is more durable than tool-based detection.**
The rule does not look for sc.exe, PowerShell, or any specific attack tool. It looks for the outcome: a registry write to the services path with a non-standard binary. This approach catches sc.exe, PowerShell New-Service, direct registry writes, and any other method that produces the same registry entry.

**Tuning decisions are as important as detection logic.**
The LocalSystem filter that was removed during testing is a clear example. Adding a filter that seems logical but increases false positives makes a rule less useful in production. The decision to remove it — and the reasoning behind it — is documented because the next analyst maintaining this rule needs to understand why it is written the way it is.

**Two log sources are better than one.**
Using Sysmon Event ID 13 alongside Windows Event ID 7045 created a detection that does not rely on a single telemetry source. In production environments where Sysmon may not be deployed on every host, the Windows System log provides a fallback. Defence in depth applies to detection architecture as much as it applies to network controls.

**The binary path is the highest-fidelity indicator for service-based persistence.**
After testing and tuning, the binary path check proved to be both necessary and sufficient for high-confidence detection. Analysts investigating any service-related alert should review the ImagePath registry value first. If it points anywhere outside System32, Program Files, or SysWOW64 — that is the investigation.

---

## Next Steps

1. Build a parent process correlation query linking Event ID 13 to the originating sc.exe or PowerShell process via Event ID 1, giving full attack chain visibility in a single alert.
2. Create a service name allowlist for the lab environment and alert on any new service not in the approved list — this catches evasive service creation even when the binary path appears legitimate.
3. Test detection coverage against more evasive service creation methods including direct Windows API calls and COM-based service installation.
4. Write a Sigma version of the detection rule for portability across SIEM platforms.
