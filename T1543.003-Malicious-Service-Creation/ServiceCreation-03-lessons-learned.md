# Lessons Learned
## T1543.003 — Create or Modify System Process: Windows Service

---

| Field | Detail |
|---|---|
| **Document ID** | LL-2026-003 |
| **Date** | May 13, 2026 |
| **Analyst** | Olayinka Daniel Oyetade |
| **Related Report** | IR-2026-003 |
| **MITRE ATT&CK** | T1543.003 — Create or Modify System Process: Windows Service |

---

## 1. What Worked

**The binary path was the definitive indicator.**
Filtering on the Details field (the binary path written to the registry) proved to be the single most reliable indicator for this technique. The moment cmd.exe appeared as a service executable, the detection was unambiguous. No legitimate Windows service or commercial software installs itself by pointing to cmd.exe. This one field eliminated any doubt about whether the alert was a true positive.

**Sysmon Event ID 13 provided rich context.**
The RegistryValueSet event captured the full registry path being modified, the value written, and the process performing the write — all in one event. This meant the alert email contained everything needed to begin the investigation without returning to Splunk for additional queries.

**Layered detection across two log sources added resilience.**
Using both Sysmon Event ID 13 and Windows System Event ID 7045 meant the detection had two independent confirmation points from different log pipelines. If one source had a gap, the other would still catch it.

**The eval severity labelling worked as intended.**
Adding an eval statement that labelled cmd.exe and PowerShell paths as CRITICAL and other non-standard paths as HIGH meant the alert email immediately communicated urgency without the analyst needing to assess it from scratch. Context in the alert reduces time-to-decision.

**Detection-to-alert time was under 5 minutes.**
Fast enough to catch the attack before a simulated attacker could execute the payload or move laterally.

---

## 2. What Needed Tuning

**The LocalSystem filter introduced false positives.**
An early version of the detection rule filtered on `LocalSystem` as the service account, assuming malicious services would always run under SYSTEM privileges. Testing showed this was wrong — many legitimate Windows services also run under LocalSystem. The filter caused 6 additional results, all legitimate. Removing it and relying on binary path alone reduced results to 3 (the actual simulated attacks) with zero false positives.

**services.exe as Image caused initial confusion.**
When reviewing the alert, seeing services.exe as the process that wrote the registry entry was unexpected. The initial assumption was that sc.exe or PowerShell would appear directly. Understanding that the Service Control Manager acts as the intermediary for all registry writes to the Services key required additional investigation. This is a normal Windows behaviour but not intuitive without prior exposure to how the SCM works internally.

**No parent process visibility in the primary detection.**
The Sysmon Event ID 13 rule correctly identified the registry modification but did not surface the originating process (PowerShell calling sc.exe). Correlating with Event ID 1 (Process Creation) was a manual step. Building this correlation into the detection query would provide full attack chain visibility in a single alert.

---

## 3. What I Would Do Differently

**Correlate Event ID 13 with Event ID 1 in the same query.**
Adding a subsearch or join to surface the sc.exe or PowerShell process that triggered the service creation would give the analyst the full picture in one view — originating process, command line arguments, user context, and the resulting registry write. This is how production-grade detection rules are built.

**Add a service name allowlist.**
In a production environment, the baseline set of installed services is known and stable. Building a lookup table of approved service names and alerting on any new service not in that list would catch service-based persistence even if the attacker uses a trusted binary path. Binary path filtering plus name allowlisting would be nearly impossible to evade silently.

**Test with more evasive service creation methods.**
sc.exe is the most obvious method and the easiest to detect. Production adversaries use direct API calls, COM-based service installation, or existing malware frameworks that create services through indirect means. The next iteration of this simulation should test those methods to validate rule coverage against more sophisticated attackers.

**Include network indicators.**
A malicious service that beacons out to a command-and-control server would produce network flow events alongside the registry modification. Adding network log correlation to the detection workflow would allow the analyst to assess whether the payload had already made external contact by the time the alert fired.

---

## 4. Key Takeaways for SOC Work

**Precision beats volume.** A detection rule that returns 3 real attacks and 0 false positives is more operationally valuable than one that returns 3 real attacks and 6 false positives. Alert fatigue from false positives causes analysts to tune out alerts — which is exactly how real attacks get missed. Tuning is not optional.

**The binary path is the smoking gun for service-based persistence.** In any investigation involving Windows services, reviewing the ImagePath registry value is the first and most important step. No further analysis is needed if that path points to cmd.exe, PowerShell, or a user-writable directory.

**Understand your log sources before writing detection rules.** Knowing that services.exe acts as the SCM intermediary prevented a false conclusion during the investigation. Detection engineers who do not understand the systems they are monitoring will misread events and produce unreliable rules.

**Document the tuning process.** The decision to remove the LocalSystem filter was as important as the original detection logic. Recording why a filter was added, why it was removed, and what evidence drove that decision is part of professional detection engineering. It allows the next analyst to understand the rule without starting from scratch.
