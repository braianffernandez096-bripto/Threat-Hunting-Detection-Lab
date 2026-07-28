# 📚 Technical References

## 📌 Overview

This document contains the primary technical references used throughout this Threat Hunting and Detection Engineering laboratory.

The resources listed below support the development of hunting hypotheses, detection logic, event analysis, and MITRE ATT&CK mapping.

---

# 🧩 MITRE ATT&CK

The MITRE ATT&CK Framework is used to classify attacker behavior according to tactics and techniques.

It provides a common language for documenting adversary activity and mapping detections.

Used for:

- Technique Mapping
- Threat Classification
- Detection Coverage
- Hunting Methodology

---

# 🛡️ Microsoft Sysmon

Sysmon provides detailed endpoint telemetry beyond standard Windows Security Events.

Throughout this laboratory Sysmon is used to collect:

- Process Creation
- Network Connections
- Parent/Child Process Relationships
- Image Loads
- File Creation
- Registry Activity

---

# 🖥️ Windows Security Auditing

Windows Security Logs provide authentication and authorization events that are essential during investigations.

Important Event IDs include:

| Event ID | Description |
|-----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4672 | Special Privileges Assigned |
| 4688 | Process Creation |
| 4720 | User Created |
| 4732 | User Added to Local Administrators |
| 7045 | Service Installed |

---

# 📊 Elastic Security

Elastic Stack is used as the primary SIEM platform.

Capabilities include:

- Event Correlation
- KQL Hunting
- Timeline Analysis
- Data Visualization
- Detection Validation

---

# 🔎 KQL (Kibana Query Language)

KQL is used throughout the laboratory for:

- Threat Hunting
- Event Correlation
- IOC Searches
- Detection Development
- Investigation Support

---

# ⚔️ LOLBAS Project

The LOLBAS (Living Off The Land Binaries and Scripts) project documents legitimate Windows binaries frequently abused by attackers.

Examples covered in this laboratory include:

- PowerShell
- CertUtil
- Rundll32
- Regsvr32
- BITSAdmin
- WMI

---

# 🧪 Atomic Red Team

Atomic Red Team provides reproducible attack simulations that allow defenders to validate detection capabilities.

The simulations performed in this laboratory are inspired by controlled adversary techniques and defensive validation methodologies.

---

# 📖 Detection Engineering Best Practices

The following principles guide every detection developed in this repository:

- Detect attacker behavior instead of specific malware.
- Prefer behavioral detections over static indicators.
- Continuously validate detection logic.
- Reduce false positives through tuning.
- Document detection rationale and investigation guidance.

---

# 🚀 Continuous Learning

Threat Hunting and Detection Engineering require continuous improvement.

As new attacker techniques emerge, detections should be reviewed, tested, and updated to maintain effective visibility across the environment.
