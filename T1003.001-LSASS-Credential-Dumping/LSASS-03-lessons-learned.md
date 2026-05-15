# Lessons Learned
## T1003.001 — OS Credential Dumping: LSASS Memory

---

| Field | Detail |
|---|---|
| **Document ID** | LL-2026-002 |
| **Date** | May 5, 2026 |
| **Analyst** | Olayinka Daniel Oyetade |
| **Related Report** | IR-2026-002 |
| **MITRE ATT&CK** | T1003.001 — OS Credential Dumping: LSASS Memory |

---

## 1. What Worked

**Sysmon Event ID 10 is highly reliable for this technique.**
The ProcessAccess event captured the exact source process, target process, access rights requested, and a full call trace. This gave the investigation everything needed to confirm the attack without ambiguity. No log gaps, no missing context.

**Layered detection added confidence.**
Using Event ID 11 (FileCreate) alongside Event ID 10 (ProcessAccess) meant the detection had two independent confirmation points. The dump file appearing in the Temp directory corroborated the memory access event and made the true positive call straightforward.

**The exclusion list worked as intended.**
Known legitimate processes (svchost, wininit, csrss, services) did not trigger the alert. There were zero false positives during the simulation window.

**Alert-to-investigation time was under 5 minutes.**
The scheduled search running every 5 minutes meant the analyst received the email alert quickly after the attack executed. In a real SOC environment this would translate to a fast time-to-detect.

**GrantedAccess value was immediately informative.**
Seeing 0x1fffff in the alert email removed any ambiguity about intent. A legitimate process accessing LSASS for diagnostic purposes would not request maximum access rights.

---

## 2. What Needed Tuning

**The exclusion list is not production-ready.**
In a real enterprise environment, EDR agents, AV software, and backup tools regularly access LSASS legitimately. Without expanding the exclusion list to account for those tools, this rule would generate significant false positive volume in production. The lab environment was clean by comparison.

**No process lineage tracking.**
The current rule captures the direct accessor of LSASS but does not track parent-child process relationships. In a real attack, the dumping tool might be spawned by a malicious parent (e.g., a macro-enabled document spawning powershell.exe, which then accesses LSASS). Adding parent process tracking would improve investigation context.

**5-minute search interval introduces detection lag.**
An attacker who dumps LSASS and immediately begins using the credentials could act within the 5-minute detection window. In a production environment, real-time alerting via Splunk streaming or an EDR alert would close this gap.

---

## 3. What I Would Do Differently

**Enable PPL (Protected Process Light) for lsass.exe.**
PPL prevents most userland processes from accessing LSASS memory at all, which would have stopped this attack at the OS level before detection was even needed. Defence-in-depth means not relying solely on detection when prevention is available.

**Add a Sigma rule alongside the SPL.**
Sigma is a vendor-neutral detection format widely used in enterprise SOCs. Writing a Sigma version of this rule would make it portable across SIEM platforms (Elastic, Microsoft Sentinel, QRadar) and demonstrate detection engineering skills beyond Splunk-specific syntax.

**Simulate a more evasive dumping method.**
Task Manager is the most obvious and easily detected method. A more realistic test would use comsvcs.dll (a signed Windows binary) or a custom injector, which are harder to detect and more commonly used by real threat actors. The next iteration of this simulation will use a Living Off the Land (LOL) method to test rule robustness.

**Capture network traffic alongside host logs.**
If an attacker successfully dumps LSASS and begins using the credentials, the next visible signal is lateral movement over the network. Adding network flow logs or packet capture to the lab environment would allow end-to-end attack simulation from credential theft through to lateral movement detection.

---

## 4. Key Takeaways for SOC Work

**LSASS access alerts are high priority and low tolerance for delay.** In a real SOC this would not wait in a queue. The moment an unknown process accesses LSASS with high access rights, the analyst should be on it.

**Context collapses investigation time.** Having the GrantedAccess value, SourceImage, and a corroborating file creation event in the same alert cut investigation time significantly. Alert enrichment is as important as the detection rule itself.

**Exclusion lists require ongoing maintenance.** A rule that fires constantly on false positives gets ignored or disabled. Keeping exclusions current is part of detection engineering, not a one-time setup task.

**Know the technique before you build the rule.** Understanding what LSASS is, why attackers target it, and what legitimate access looks like made it possible to write an exclusion list that works. Detection engineering without technique knowledge produces brittle rules.
