# MITRE ATT&CK Coverage Analysis
## Sysmon Workstation Configuration (sysmon-ws.xml)

**Overall Coverage:** ~30% (59/200 techniques)
**Rating:** 8/10 - Production Ready

---

## Coverage by Tactic

| Tactic | Techniques Covered | Total | Coverage |
|--------|-------------------|-------|----------|
| Execution | 6 | 14 | 43% |
| Persistence | 8 | 19 | 42% |
| Privilege Escalation | 4 | 13 | 31% |
| Defense Evasion | 10 | 42 | 24% |
| Credential Access | 5 | 17 | 29% |
| Discovery | 12 | 31 | 39% |
| Lateral Movement | 4 | 9 | 44% |
| Collection | 3 | 17 | 18% |
| Command and Control | 3 | 16 | 19% |
| Exfiltration | 2 | 9 | 22% |
| Impact | 2 | 13 | 15% |

---

## Detailed Technique Coverage

### Execution (T1059, T1203, T1204, T1047, T1053, T1218)

| Technique ID | Name | Sysmon Event | Status |
|--------------|------|--------------|--------|
| T1059.001 | PowerShell | 1, 7 | ✅ Covered |
| T1059.003 | Windows Command Shell | 1 | ✅ Covered |
| T1059.005 | Visual Basic | 1 | ✅ Covered |
| T1059.007 | JavaScript | 1 | ✅ Covered |
| T1047 | WMI | 1, 19-21 | ✅ Covered |
| T1053.005 | Scheduled Task | 1 | ✅ Covered |

### Persistence (T1547, T1546, T1543, T1137)

| Technique ID | Name | Sysmon Event | Status |
|--------------|------|--------------|--------|
| T1547.001 | Registry Run Keys | 13 | ✅ Covered |
| T1547.002 | Authentication Package | 13 | ✅ Covered |
| T1546.003 | WMI Event Subscription | 19, 20, 21 | ✅ Covered |
| T1546.010 | AppInit DLLs | 13 | ✅ Covered |
| T1546.011 | Application Shimming | 13 | ✅ Covered |
| T1546.012 | Image File Execution Options | 13 | ✅ Covered |
| T1543.003 | Windows Service | 13 | ✅ Covered |
| T1137 | Office Application Startup | 13 | ✅ Covered |

### Credential Access (T1003, T1555, T1552)

| Technique ID | Name | Sysmon Event | Status |
|--------------|------|--------------|--------|
| T1003.001 | LSASS Memory | 10, 7 | ✅ Covered |
| T1003.002 | SAM | 1, 7 | ✅ Covered |
| T1003.003 | NTDS | 1 | ✅ Covered |
| T1003.004 | LSA Secrets | 13 | ✅ Covered |
| T1003.006 | DCSync | 3 | ⚠️ Partial |

### Defense Evasion (T1218, T1070, T1112, T1055)

| Technique ID | Name | Sysmon Event | Status |
|--------------|------|--------------|--------|
| T1218.001 | Compiled HTML File | 1 | ✅ Covered |
| T1218.003 | CMSTP | 1 | ✅ Covered |
| T1218.005 | Mshta | 1, 3 | ✅ Covered |
| T1218.010 | Regsvr32 | 1, 3 | ✅ Covered |
| T1218.011 | Rundll32 | 1, 3 | ✅ Covered |
| T1070.001 | Clear Windows Event Logs | 1 | ✅ Covered |
| T1070.006 | Timestomp | 2 | ✅ Covered |
| T1112 | Modify Registry | 13 | ✅ Covered |
| T1055.001 | DLL Injection | 8 | ✅ Covered |
| T1055.012 | Process Hollowing | 8, 10 | ⚠️ Partial |

### Discovery (T1033, T1082, T1083, T1087, T1018)

| Technique ID | Name | Sysmon Event | Status |
|--------------|------|--------------|--------|
| T1033 | System Owner/User Discovery | 1 | ✅ Covered |
| T1082 | System Information Discovery | 1 | ✅ Covered |
| T1083 | File and Directory Discovery | 1 | ⚠️ Partial |
| T1087.001 | Local Account | 1 | ✅ Covered |
| T1087.002 | Domain Account | 1 | ✅ Covered |
| T1018 | Remote System Discovery | 1 | ✅ Covered |
| T1016 | System Network Configuration | 1 | ✅ Covered |
| T1049 | System Network Connections | 1 | ✅ Covered |
| T1057 | Process Discovery | 1 | ✅ Covered |
| T1069 | Permission Groups Discovery | 1 | ✅ Covered |
| T1124 | System Time Discovery | 1 | ✅ Covered |
| T1201 | Password Policy Discovery | 1 | ✅ Covered |

### Lateral Movement (T1021, T1570)

| Technique ID | Name | Sysmon Event | Status |
|--------------|------|--------------|--------|
| T1021.002 | SMB/Windows Admin Shares | 17, 18 | ✅ Covered |
| T1021.003 | DCOM | 1, 3 | ✅ Covered |
| T1021.006 | Windows Remote Management | 1, 3 | ✅ Covered |
| T1570 | Lateral Tool Transfer | 1, 11 | ✅ Covered |

### Command and Control (T1071, T1095, T1572)

| Technique ID | Name | Sysmon Event | Status |
|--------------|------|--------------|--------|
| T1071.001 | Web Protocols | 3, 22 | ⚠️ Partial |
| T1095 | Non-Application Layer Protocol | 3 | ⚠️ Partial |
| T1572 | Protocol Tunneling | 3 | ⚠️ Partial |

---

## Coverage Gaps (Requires Additional Data Sources)

| Gap Area | Recommended Data Source |
|----------|------------------------|
| Network traffic content | Zeek, Suricata, PCAP |
| Cloud/SaaS activity | Azure AD, AWS CloudTrail, O365 |
| Email-based attacks | Mail gateway, Exchange logs |
| Web proxy activity | Proxy logs (Zscaler, BlueCoat) |
| Authentication events | Windows Security logs (4624, 4625) |
| Firewall activity | Firewall logs |
| DNS detailed analysis | DNS server logs, passive DNS |

---

## Benchmark Comparison

| Configuration | Coverage | Notes |
|---------------|----------|-------|
| **This config (sysmon-ws.xml)** | **~30%** | ✅ Above average |
| Default Sysmon | 15-20% | Many gaps |
| Windows native logging | 10-15% | Basic audit only |
| Commercial EDR | 50-70% | Includes behavioral |
| Full SIEM stack | 60-80% | Multi-source |

---

## Recommendations for Improved Coverage

1. **Add Windows Security Event Logs** (+10% coverage)
   - 4624/4625: Logon events
   - 4688: Process creation with command line
   - 4698/4699: Scheduled task events

2. **Add PowerShell Logging** (+5% coverage)
   - Script Block Logging (4104)
   - Module Logging

3. **Add Network Logs** (+10% coverage)
   - Firewall logs
   - Proxy logs
   - DNS server logs

4. **Consider EDR** (+20% coverage)
   - Behavioral detection
   - Memory analysis
   - File reputation

---

**Analysis Date:** December 2025
**Sysmon Schema:** 4.50
**Framework Version:** MITRE ATT&CK v14
