# 📝 Analyst Investigation Log — PowerShell Abuse Hunt

## 📌 Investigation Summary

This document records the analyst's observations, findings, and conclusions during the PowerShell Abuse threat hunt.

The investigation followed a hypothesis-driven approach using endpoint telemetry, Elastic SIEM, and behavioral analysis.

---

# 🎯 Hunting Hypothesis

Attackers may abuse PowerShell to execute malicious commands, download payloads, establish persistence, or communicate with external infrastructure.

The objective of this hunt is to identify suspicious PowerShell behavior that deviates from normal administrative activity.

---

# 🔍 Initial Investigation

The investigation began by reviewing Sysmon Process Creation events (Event ID 1) associated with PowerShell.

Key questions included:

- Was PowerShell executed?
- Which user launched the process?
- What was the parent process?
- Was the execution interactive or automated?
- Was the command line suspicious?

---

# 📊 Observations

The following behaviors were reviewed during the hunt:

- PowerShell process creation.
- Parent-child process relationships.
- Command-line arguments.
- Encoded PowerShell commands.
- Network connections initiated by PowerShell.
- Child process creation.
- Execution path.

No single indicator was considered sufficient to classify activity as malicious.

Behavioral correlation was required.

---

# 📡 Evidence Collected

Evidence was collected from multiple telemetry sources.

### Elastic SIEM

- Process Creation Events
- Network Connection Events
- Timeline Correlation

### Endpoint Telemetry

- Sysmon Event ID 1
- Sysmon Event ID 3

### Network Evidence

- Wireshark traffic captures
- Destination IP addresses
- Destination ports
- Protocol analysis

---

# 🧩 MITRE ATT&CK Assessment

Observed behavior was mapped to:

| Technique | ID |
|-----------|----|
| PowerShell | T1059.001 |

Additional techniques may apply depending on the simulated attack scenario.

---

# ⚠️ False Positive Assessment

Potential legitimate activity includes:

- Administrative PowerShell sessions
- IT automation scripts
- Configuration management tools
- Software deployment
- Scheduled maintenance

Analyst validation is required before classifying activity as malicious.

---

# 💡 Detection Improvements

Based on the investigation, future improvements may include:

- Parent-child process correlation.
- User baseline analysis.
- Frequency-based detections.
- PowerShell command-line profiling.
- Threat Intelligence enrichment.
- Sigma rule development.

---

# 📌 Analyst Assessment

The hunt successfully demonstrated that behavioral telemetry provides greater visibility than relying solely on static indicators.

Combining Sysmon telemetry with Elastic SIEM allows analysts to identify suspicious PowerShell activity, validate detections, and improve detection logic through iterative analysis.

---

# 🚀 Lessons Learned

Key takeaways from this hunt include:

- Behavioral analysis is more resilient than signature-based detection.
- Context is essential when investigating PowerShell activity.
- Event correlation significantly improves detection confidence.
- Continuous tuning reduces false positives and strengthens detection quality.
