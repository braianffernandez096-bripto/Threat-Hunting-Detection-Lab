# 🚨 Detection — Suspicious PowerShell Execution

## 📌 Overview

This detection identifies potentially malicious PowerShell activity based on behavioral indicators rather than specific malware signatures.

The objective is to detect attacker techniques commonly used during post-exploitation, execution, and lateral movement.

---

# 🎯 Detection Objective

Detect suspicious PowerShell execution that may indicate malicious activity, including:

- Encoded commands
- PowerShell execution from unusual locations
- Download cradles
- Network connections initiated by PowerShell
- Suspicious child processes

---

# 🧠 Threat Description

PowerShell is a legitimate Windows administration tool frequently abused by attackers.

Its flexibility allows adversaries to execute commands, download payloads, evade detection, and automate post-exploitation activities.

Behavioral monitoring provides higher detection resilience than signature-based approaches.

---

# 📡 Telemetry Sources

| Source | Event |
|---------|-------|
| Sysmon | Event ID 1 – Process Creation |
| Sysmon | Event ID 3 – Network Connection |
| Windows Security | Authentication Context |
| Elastic SIEM | Event Correlation |

---

# 🔍 Detection Logic

The detection focuses on:

- PowerShell process execution.
- Encoded commands.
- PowerShell network activity.
- Suspicious parent processes.
- Unusual execution paths.

---

# 📊 Detection Severity

**Severity:** High

**Confidence:** Medium–High

---

# 🧩 MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Execution | PowerShell | T1059.001 |
| Command and Control | Application Layer Protocol | T1071 |
| Defense Evasion | Obfuscated Files or Information | T1027 *(when encoded commands are observed)* |

---

# ⚠️ Potential False Positives

Legitimate activity may include:

- System administrators
- Automation scripts
- Enterprise management software
- Configuration management tools
- PowerShell maintenance scripts

Analysts should validate context before confirming malicious activity.

---

# 🔎 Investigation Guide

During the investigation, verify:

- Who executed PowerShell?
- Parent process.
- Command line arguments.
- EncodedCommand usage.
- Network destinations.
- Child processes.
- Execution path.
- User context.
- Frequency of execution.

---

# 🛡️ Analyst Recommendations

If malicious activity is confirmed:

- Isolate the affected endpoint.
- Preserve forensic evidence.
- Review authentication logs.
- Search for persistence mechanisms.
- Hunt for similar activity across the environment.

---

# 📈 Detection Improvements

Future improvements may include:

- Parent-child process correlation.
- Frequency-based detections.
- User baseline analysis.
- Command-line anomaly detection.
- Threat Intelligence enrichment.
- Sigma rule conversion.

---

# 📚 Lessons Learned

PowerShell is one of the most abused Windows utilities.

Behavior-based detections provide significantly better coverage than relying solely on known malicious commands or static indicators.

Detection logic should evolve continuously as attacker techniques change.
