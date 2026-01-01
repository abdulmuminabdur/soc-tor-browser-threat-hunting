# Tor Browser Threat Hunting Investigation

SOC threat-hunting investigation identifying, validating, and contextualizing Tor Browser usage on a Windows endpoint using Microsoft Defender for Endpoint (Advanced Hunting) and KQL.

---

## Overview

This project documents a proactive threat-hunting investigation focused on detecting and validating Tor Browser usage on a monitored Windows endpoint. By correlating endpoint file, process, and network telemetry, the investigation reconstructs the complete lifecycle of Tor Browser activity—from installer execution through anonymized network communication—while assessing security impact within an enterprise environment.

The objective of this hunt was to determine whether the observed activity represented malicious behavior or a policy and visibility concern requiring containment.

---

## Environment

- **Endpoint:** `mumin-threat-hu`
- **User Account:** `mumin-threat-hunt-vm`
- **Operating System:** Windows (Virtual Machine)
- **Security Platform:** Microsoft Defender for Endpoint (Advanced Hunting)
- **Telemetry Sources:**
  - DeviceFileEvents
  - DeviceProcessEvents
  - DeviceNetworkEvents
- **Query Language:** KQL

---

## Detection & Analysis

### File-Based Detection

Threat hunting began by identifying Tor-related artifacts written to disk.

```kql
DeviceFileEvents
| where DeviceName == "mumin-threat-hu"
| where InitiatingProcessAccountName == "mumin-threat-hunt-vm"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-12-31 14:04:06)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
## Findings

- Multiple Tor-related files were copied to the Desktop directory  
- User-created file observed: `tor-shopping-list.txt`  

**Significance:**  
Indicates post-install, user-driven interaction rather than a dormant or automated installation.

---

## Process Execution Analysis

Process telemetry confirmed execution of the Tor Browser portable installer.

```kql
DeviceProcessEvents
| where DeviceName == "mumin-threat-hu"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.3.exe"
| project Timestamp, DeviceName, AccountName, FolderPath, SHA256, ProcessCommandLine
```

## Process Execution Analysis

Additional process telemetry confirmed active Tor Browser usage.

```kql
DeviceProcessEvents
| where DeviceName == "mumin-threat-hu"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
```

### Processes Observed

- **firefox.exe** (Tor Browser–bundled Firefox)
- **tor.exe**
- **tor-browser.exe**

**Significance:**  
Confirms successful execution and runtime operation of Tor Browser.

---

## Network Activity Analysis

Network telemetry was reviewed to identify Tor-specific communication.

```kql
DeviceNetworkEvents
| where DeviceName == "mumin-threat-hu"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001","9030","9040","9050","9051","9150","9151")
| project Timestamp, DeviceName, ActionType, RemotePort, RemoteIP, RemoteUrl, Account = InitiatingProcessAccountName
| order by Timestamp desc
```


### Observed

- Successful connection to **127.0.0.1** on port **9150**

**Significance:**  
Port 9150 is a known Tor Browser SOCKS proxy port. Localhost communication confirms internal Tor routing behavior consistent with standard Tor Browser operation.

---

## Chronological Timeline (UTC)

| Timestamp | Event |
|----------|------|
| 2025-12-31 19:43:57 | Tor Browser installer executed |
| 2025-12-31 19:50:14 | Tor Browser application launched |
| 2025-12-31 19:50:20 | Tor SOCKS proxy communication established |
| 2025-12-31 19:59:12 | Tor-related files created on disk |

---

## Result

Tor Browser usage was confirmed on the endpoint **mumin-threat-hu** under the account **mumin-threat-hunt-vm**. Telemetry demonstrated a complete and intentional Tor usage lifecycle including installation, execution, file interaction, and anonymized network communication. No indicators of malware delivery, persistence mechanisms, lateral movement, or data exfiltration were identified.

---

## Containment & Response

- Isolated the affected endpoint using Microsoft Defender for Endpoint  
- Executed full antimalware scans; no malicious artifacts were detected  
- Notified the user’s direct manager of confirmed Tor Browser usage  
- Maintained device isolation pending policy review  

> Device isolation was applied as a **precautionary control pending policy review**, not due to confirmed compromise.

---

## MITRE ATT&CK Mapping

- **T1090.003 – Proxy: Multi-hop Proxy (Defense Evasion):**  
  Use of the Tor network to anonymize outbound communications  

- **T1090 – Proxy (Command and Control – Potential):**  
  Anonymized proxy usage capable of obscuring malicious traffic

  ## Detection Opportunities

- Alert on execution of known Tor Browser binaries (e.g., `tor.exe`, `tor-browser.exe`, Tor-bundled `firefox.exe`)
- Monitor outbound connections to Tor SOCKS proxy ports (e.g., 9050, 9150)
- Correlate Tor-related file creation with process execution to reduce false positives


---

## Final Status

**Activity confirmed and contained with no security incident declared.**

Tor Browser usage was verified as deliberate and user-driven. No evidence of compromise, persistence, lateral movement, or malicious follow-on activity was observed. Risk was assessed as **low–moderate**, driven by reduced visibility rather than confirmed malicious intent.

---

## Key Takeaways

- Endpoint telemetry reliably detects anonymization software  
- Correlating file, process, and network data provides full activity context  
- Contextual analysis prevents false-positive incident escalation  
- Tor usage represents a policy and monitoring concern even without malware  

---

## Skills Demonstrated

- Endpoint threat hunting  
- File, process, and network telemetry correlation  
- KQL querying (Microsoft Defender Advanced Hunting)  
- Anonymization and proxy detection  
- Incident documentation and reporting  
- MITRE ATT&CK mapping  

---

## Author

**Abdul-Mumin Abdur-Rahman**  
SOC Analyst | Threat Hunting | Incident Response










