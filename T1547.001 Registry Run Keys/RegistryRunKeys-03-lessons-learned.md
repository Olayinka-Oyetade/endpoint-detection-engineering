# Lessons Learned
## T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys

---

| Field | Detail |
|---|---|
| **Document ID** | LL-2026-001 |
| **Date** | May 5, 2026 |
| **Analyst** | Olayinka Daniel Oyetade |
| **Related Report** | IR-2026-001 |
| **MITRE ATT&CK** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |

---

## 1. What Worked

**Sysmon Event ID 13 captured everything needed in a single event.**
The RegistryValueSet event provided the source process (powershell.exe), the full registry path being modified, and the value written (the malware path) — all in one log entry. No correlation across multiple events was needed to confirm the attack. This made the investigation fast and unambiguous.

**Sysmon's own RuleName field confirmed the MITRE mapping.**
When Sysmon is configured correctly, it tags events with the corresponding MITRE ATT&CK technique ID in the RuleName field. Seeing `technique_id=T1547.001` in the raw event removed any doubt about classification and demonstrated the value of a well-configured Sysmon ruleset.

**PowerShell as the source process was an immediate red flag.**
In a clean Windows environment, PowerShell should not be modifying Run keys. The moment the Image field showed powershell.exe, the alert was credible without needing to analyse the payload path. This demonstrates why monitoring source process context matters as much as monitoring the registry path itself.

**The payload path in C:\Users\Public was definitive.**
No legitimate software installs to a world-writable directory and registers itself in the Run key from there. The combination of PowerShell as the source and Public as the payload location made this a zero-doubt true positive.

**Detection-to-alert under 5 minutes.**
The scheduled search interval was fast enough to catch the attack before a simulated login would have triggered the payload.

---

## 2. What Needed Tuning

**The initial query was too broad.**
The first version of the detection rule matched every registry modification to any Run key path with no process filtering. In a real environment this would generate significant false positive volume from software installers, update agents, and endpoint management tools — all of which legitimately write to Run keys. Adding source process exclusions and payload path risk scoring narrowed the results to actionable alerts.

**No automatic correlation with file creation.**
The malware.exe payload was written to C:\Users\Public before the Run key was created. The detection caught the Run key modification but did not automatically surface the file drop event. Building a correlation between Event ID 11 (FileCreate) and Event ID 13 for the same file path would provide the full attack chain in a single alert without manual follow-up queries.

**No coverage of RunOnce keys in the initial rule.**
The first version only monitored `CurrentVersion\Run`. Attackers also use `RunOnce` and `RunServices` paths for persistence. The extended coverage query was added after this gap was identified during review.

---

## 3. What I Would Do Differently

**Build payload path risk scoring into the alert from the start.**
Rather than treating all Run key modifications as equal severity, the eval logic that labels Temp and Public paths as CRITICAL should be in the initial rule. This immediately communicates urgency to the analyst without requiring them to assess the payload path manually.

**Add a baseline lookup for known good Run key entries.**
In a production environment, documenting what should be in the Run key — and alerting on anything outside that list — would catch attacker entries even when they use trusted binary paths. A lookup table approach is more durable than process exclusions alone.

**Correlate with network events post-detection.**
If the payload had executed before detection, the next visible signal would be a network connection from malware.exe to a command-and-control server. Adding network flow monitoring to the investigation workflow would allow the analyst to determine whether the payload had already called home by the time the alert fired.

**Test against obfuscated PowerShell.**
The simulation used a clear, readable PowerShell command. Real attackers encode their commands in Base64 or use aliases to evade script-based detection. A follow-up simulation using obfuscated PowerShell would test whether the detection rule still fires when the command line is not human-readable — it should, because Sysmon monitors the registry write itself, not the PowerShell syntax.

---

## 4. Key Takeaways for SOC Work

**Registry Run keys are a foundational detection priority.** This is one of the first techniques analysts learn and one of the most commonly seen in real investigations. Any SOC that is not monitoring Run key modifications is missing a significant percentage of real attacks.

**No admin privileges required means lower barrier for attackers.** The HKCU path is accessible to any logged-in user. An attacker who achieves only user-level access through a phishing email can still establish durable persistence using this technique. Detection must cover HKCU as thoroughly as HKLM.

**Source process context separates true positives from noise.** The same registry path modified by msiexec.exe during a software installation is routine. Modified by powershell.exe with a payload in Public is a confirmed attack. The what (registry path) matters, but the who (source process) and where (payload path) make the difference between an alert that requires investigation and one that does not.

**Good detection rules scale.** The rule built here detects any process modifying a Run key with a suspicious payload path — not just the specific PowerShell command used in this simulation. Emotet, TrickBot, and a new malware family the analyst has never seen before would all trigger the same alert if they write to the same registry path. Behaviour-based detection compounds in value over time.
