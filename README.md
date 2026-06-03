# Azure Sentinel SIEM: Global Threat Mapping & Honeyfile Detection Lab

## Project Overview
This project demonstrates the end-to-end implementation of a cloud-native security operations environment. The objective was to configure a Windows Server virtual machine as a deliberate honeypot target, stream its security log telemetry into Microsoft Sentinel via the Azure Monitoring Agent (AMA), and build high-fidelity detection rules alongside geospatial intelligence dashboards.

### Core Components
* **SIEM / Analytics Platform:** Microsoft Sentinel & Azure Log Analytics Workspaces
* **Endpoint Host:** Windows Server 2022 VM
* **Telemetry Agent:** Azure Monitoring Agent (AMA)
* **Query Language:** Kusto Query Language (KQL)

---

## Phase 1: Geospatial Inbound Attack Mapping
Using a custom workbook in Microsoft Sentinel, I engineered a live dashboard to track and correlate malicious authentication failures globally. 

### KQL Workbook Query
```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625 // Windows Event ID for Failed Logon
| extend GeoInfo = geo_info_from_ip_address(IpAddress)
| extend Country = tostring(GeoInfo.country)
| where isnotempty(Country)
| summarize count() by IpAddress, Country
