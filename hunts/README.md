# 🔍 Hunt 01 — PowerShell Abuse

## 📌 Hunting Hypothesis

Attackers frequently abuse PowerShell to execute malicious commands, download payloads, establish persistence, and perform post-exploitation activities.

The objective of this hunt is to identify suspicious PowerShell execution through behavioral analysis using Sysmon telemetry and Elastic SIEM.

---

# 🎯 Hunt Objectives

- Identify suspicious PowerShell execution.
- Detect encoded PowerShell commands.
- Correlate endpoint and network telemetry.
- Validate behavioral detections.
- Reduce false positives.
- Improve detection logic.

---

# 🧠 Threat Scenario

A simulated attacker executes PowerShell commands on a Windows endpoint.

The hunt focuses on identifying suspicious behaviors rather than detecting specific malware.

Activities include:

- PowerShell execution
- Encoded commands
- Download attempts
- Network connections
- Child process creation

---

# 📡 Telemetry Sources

| Source | Purpose |
|---------|----------|
| Sysmon | Process Creation |
| Sysmon | Network Connections |
| Windows Security Logs | Authentication Context |
| Elastic SIEM | Event Correlation |
| Wireshark | Network Validation |

---

# 🔍 Hunting Questions

During this hunt the analyst attempts to answer:

- Was PowerShell executed?
- Who executed it?
- From which parent process?
- Was an encoded command used?
- Did PowerShell establish network connections?
- Was another process spawned?
- Is the behavior legitimate?

---

# 🧩 MITRE ATT&CK

| Tactic | Technique | ID |
|---------|-----------|----|
| Execution | PowerShell | T1059.001 |

---

# 📁 Hunt Structure

```text
README.md
detections/
queries/
evidence/
notes.md
```

---

# 🚀 Expected Outcome

At the end of this hunt the analyst should be able to:

- Detect suspicious PowerShell execution.
- Validate detections using Elastic SIEM.
- Correlate endpoint telemetry.
- Improve detection quality.
- Document findings using Threat Hunting methodology.
