# Technical Report: MITRE ATT&CK Detection Improvements

**Date:** December 17, 2025
**PR:** #1 - MITRE Coverage Improvements
**Branch:** `fix/mitre-coverage-improvements`

---

## 1. Executive Summary

This report documents the technical results of Sysmon configuration improvements targeting MITRE ATT&CK detection gaps identified during initial testing.

### Key Metrics

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| Average Detection Rate | 81.25% | 83.75% | **+2.5%** |
| Best Performing Config | exch (90%) | dc/exch (92.5%) | +2.5% |
| Worst Performing Config | sql (72.5%) | sql/iis (75%) | +2.5% |
| T1021.002 Detection | 1/6 configs | 6/6 configs | **+500%** |
| T1087.001 Detection | 0/6 configs | 0/6 configs | No change |

---

## 2. Detection Rate Comparison by Configuration

| Configuration | Before | After | Change | Status |
|---------------|--------|-------|--------|--------|
| **dc** (Domain Controller) | 87.5% | 92.5% | **+5.0%** | Improved |
| **exch** (Exchange Server) | 90.0% | 92.5% | **+2.5%** | Improved |
| **ws** (Workstation) | 85.0% | 87.5% | **+2.5%** | Improved |
| **srv** (Generic Server) | 77.5% | 80.0% | **+2.5%** | Improved |
| **sql** (SQL Server) | 72.5% | 75.0% | **+2.5%** | Improved |
| **iis** (IIS Web Server) | 75.0% | 75.0% | 0% | Stable |

### Per-Configuration Analysis

#### Domain Controller (dc) - +5.0%
- **Before:** 35/40 techniques detected
- **After:** 37/40 techniques detected
- **New detections:** T1021.002 (SMB), T1071.001 (Web Protocols)
- **Remaining gaps:** T1087.001, T1560.001, T1005

#### Exchange Server (exch) - +2.5%
- **Before:** 36/40 techniques detected
- **After:** 37/40 techniques detected
- **New detections:** T1021.002 (SMB)
- **Remaining gaps:** T1087.001, T1560.001, T1005

#### Workstation (ws) - +2.5%
- **Before:** 34/40 techniques detected
- **After:** 35/40 techniques detected
- **New detections:** T1018 (Remote System Discovery)
- **T1021.002:** Was already detected (1 event), now 3 events
- **Remaining gaps:** T1087.001, T1003.003, T1057, T1560.001, T1005

#### Generic Server (srv) - +2.5%
- **Before:** 31/40 techniques detected
- **After:** 32/40 techniques detected
- **New detections:** T1021.002 (SMB), T1570 (Lateral Tool Transfer), T1105 (Ingress Tool Transfer)
- **Remaining gaps:** T1087.001, T1003.002, T1555.003, T1016, T1560.001, T1005, T1074.001, T1071.001

#### SQL Server (sql) - +2.5%
- **Before:** 29/40 techniques detected
- **After:** 30/40 techniques detected
- **New detections:** T1021.002 (SMB), T1105 (Ingress Tool Transfer)
- **Lost detections:** T1003.003 (now NOT_DETECTED)
- **Remaining gaps:** T1087.001, T1003.002, T1003.003, T1555.003, T1016, T1570, T1560.001, T1005, T1074.001, T1071.001

#### IIS Web Server (iis) - 0% (Stable)
- **Before:** 30/40 techniques detected
- **After:** 30/40 techniques detected
- **New detections:** T1021.002 (SMB)
- **Lost detections:** T1070.001 (ERROR in new test)
- **Remaining gaps:** T1087.001, T1003.002, T1555.003, T1082 (ERROR), T1016, T1570, T1560.001, T1005, T1074.001, T1071.001

---

## 3. Targeted Technique Analysis

### T1021.002 - SMB/Windows Admin Shares (SUCCESS)

**Objective:** Improve lateral movement detection via SMB ports 445/139

| Config | Before | After | Events | Event Types |
|--------|--------|-------|--------|-------------|
| ws | DETECTED | DETECTED | 1→3 | 22→3,22 |
| srv | NOT_DETECTED | **DETECTED** | 0→2 | →3 |
| dc | NOT_DETECTED | **DETECTED** | 0→2 | →3 |
| sql | NOT_DETECTED | **DETECTED** | 0→2 | →3 |
| exch | NOT_DETECTED | **DETECTED** | 0→2 | →3 |
| iis | NOT_DETECTED | **DETECTED** | 0→2 | →3 |

**Result:** 100% improvement on server configurations. SMB port monitoring rules are working as expected.

**Implementation:**
```xml
<!-- T1021.002 - SMB/Windows Admin Shares (Lateral Movement) -->
<DestinationPort condition="is">445</DestinationPort>
<DestinationPort condition="is">139</DestinationPort>
```

### T1087.001 - Local Account Discovery (FAILED)

**Objective:** Detect local account enumeration commands

| Config | Before | After | Events | Change |
|--------|--------|-------|--------|--------|
| ALL | NOT_DETECTED | NOT_DETECTED | 0 | No change |

**Result:** No improvement despite adding CommandLine rules.

**Root Cause Analysis:**

The Atomic Red Team test for T1087.001 executes:
```powershell
net user
net user /domain
```

Our rules target:
```xml
<CommandLine condition="contains">net user</CommandLine>
```

**Potential Issues:**
1. **Case sensitivity:** The test may execute `Net User` or `NET USER`
2. **Process not spawned:** PowerShell may execute `net user` without spawning a new process (inline cmdlet)
3. **Sysmon Event ID filtering:** ProcessCreate (Event 1) may be filtered by other exclusion rules
4. **Command execution method:** The test may use direct API calls rather than command execution

**Recommendations:**
1. Add case-insensitive matching (not supported natively in Sysmon)
2. Monitor PowerShell script block logging (Event ID 4104) in addition to Sysmon
3. Review Sysmon ProcessCreate exclusion rules that may be filtering `net.exe`
4. Consider monitoring `net.exe` Image as well as CommandLine

### T1570 - Lateral Tool Transfer (MIXED)

| Config | Before | After | Change |
|--------|--------|-------|--------|
| ws | DETECTED | DETECTED | Stable |
| srv | NOT_DETECTED | **DETECTED** | +1 |
| dc | DETECTED | DETECTED | Stable |
| sql | NOT_DETECTED | NOT_DETECTED | No change |
| exch | DETECTED | DETECTED | Stable |
| iis | NOT_DETECTED | NOT_DETECTED | No change |

**Result:** Partial improvement. SMB monitoring helps but doesn't cover all lateral transfer methods.

---

## 4. Event Type Analysis

**Sysmon Event IDs observed in detection:**
- Event 1: ProcessCreate
- Event 3: NetworkConnect
- Event 7: ImageLoad
- Event 9: RawAccessRead
- Event 10: ProcessAccess
- Event 11: FileCreate
- Event 12: RegistryEvent (Object create/delete)
- Event 13: RegistryEvent (Value Set)
- Event 15: FileCreateStreamHash
- Event 19/20/21: WmiEvent
- Event 22: DNSQuery
- Event 23: FileDelete
- Event 25: ProcessTampering

**New Event Types After Changes:**
- Event 3 (NetworkConnect) now appears in T1021.002 detection due to SMB port rules

---

## 5. Configuration Changes Implemented

### Added to ALL configs:

**NetworkConnect Rules:**
```xml
<!-- T1021.002 - SMB/Windows Admin Shares (Lateral Movement) -->
<DestinationPort condition="is">445</DestinationPort>
<DestinationPort condition="is">139</DestinationPort>
```

**ProcessCreate Rules:**
```xml
<!-- T1087.001 specific - Local Account Discovery -->
<CommandLine condition="contains">net user</CommandLine>
<CommandLine condition="contains">net1 user</CommandLine>
<CommandLine condition="contains">get-localuser</CommandLine>
<CommandLine condition="contains">wmic useraccount</CommandLine>
```

### Additional per-config changes:

| Config | Additional ProcessCreate Images |
|--------|--------------------------------|
| ws | query.exe |
| dc | query.exe, quser.exe |
| sql | whoami.exe, hostname.exe, net.exe, net1.exe, systeminfo.exe, tasklist.exe, query.exe, ipconfig.exe, netstat.exe |
| exch | net1.exe, query.exe, quser.exe |
| iis | tasklist.exe, query.exe, netstat.exe, nltest.exe |

---

## 6. Remaining Detection Gaps

### Critical (0% detection across all configs)
| Technique | Name | Category |
|-----------|------|----------|
| T1087.001 | Local Account Discovery | Discovery |
| T1560.001 | Archive via Utility | Collection |
| T1005 | Data from Local System | Collection |

### Partial (detected in some configs only)
| Technique | Name | Detected In |
|-----------|------|-------------|
| T1003.002 | SAM Dump | ws, dc, exch |
| T1003.003 | NTDS | srv, dc, exch, iis |
| T1555.003 | Credentials from Web Browsers | ws, dc, exch |
| T1016 | System Network Configuration | ws, dc, exch, iis |
| T1074.001 | Local Data Staging | ws, dc, exch |
| T1071.001 | Web Protocols | ws, dc, exch |

---

## 7. Recommendations

### Immediate Actions

1. **Investigate T1087.001 failure:**
   - Review Atomic Red Team test implementation
   - Check if `net.exe` is being excluded by other rules
   - Consider adding Image-based monitoring for `net.exe` and `net1.exe`

2. **Add PowerShell logging:**
   - Enable Script Block Logging (Event 4104)
   - Correlate with Sysmon ProcessCreate events

3. **Review exclusion rules:**
   - Audit all ProcessCreate exclusion rules
   - Ensure legitimate admin tools aren't being filtered

### Future Improvements

1. **Collection technique detection:**
   - Add FileCreate rules for archive utilities (7z.exe, rar.exe, tar.exe)
   - Monitor staging directories

2. **Network detection enhancement:**
   - Add DNS query monitoring for C2 detection
   - Monitor unusual outbound connections

3. **Credential access hardening:**
   - Add LSASS memory access monitoring
   - Monitor registry SAM key access

---

## 8. Test Environment

- **Testing Framework:** Atomic Red Team
- **Test Runner:** GitHub Actions
- **Techniques Tested:** 40 from MITRE ATT&CK framework
- **Test Date (Before):** December 17, 2025, 08:57-09:07
- **Test Date (After):** December 17, 2025, 13:37-13:46

---

## Appendix A: Detection Rate Calculation

Detection Rate = (Detected Techniques / Total Techniques Tested) × 100

- Techniques returning ERROR are excluded from calculation
- A technique is DETECTED if ≥1 Sysmon event is generated during atomic test execution

## Appendix B: Files Modified

| File | Lines Changed | Primary Changes |
|------|--------------|-----------------|
| sysmon-ws.xml | ~15 | SMB ports, T1087.001 rules |
| sysmon-srv.xml | ~15 | SMB ports, T1087.001 rules |
| sysmon-dc.xml | ~15 | SMB ports, T1087.001 rules, query.exe |
| sysmon-sql.xml | ~25 | SMB ports, T1087.001 rules, discovery commands |
| sysmon-exch.xml | ~15 | SMB ports, T1087.001 rules, net1.exe |
| sysmon-iis.xml | ~20 | SMB ports, T1087.001 rules, discovery commands |
