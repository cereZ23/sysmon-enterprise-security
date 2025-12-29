# Sysmon MITRE ATT&CK Detection Coverage Report

**Generated:** December 17, 2025
**Workflow Run:** [#20295523482](https://github.com/cereZ23/sysmon/actions/runs/20295523482)
**Techniques Tested:** 40 (balanced across MITRE ATT&CK categories)

---

## Executive Summary

| Configuration | Detection Rate | Detected | Not Detected | Errors |
|--------------|----------------|----------|--------------|--------|
| **exch** (Exchange Server) | **90.0%** | 36/40 | 4 | 0 |
| **dc** (Domain Controller) | **87.5%** | 35/40 | 4 | 1 |
| **ws** (Workstation) | **85.0%** | 34/40 | 5 | 1 |
| **srv** (Generic Server) | **77.5%** | 31/40 | 9 | 0 |
| **iis** (IIS Web Server) | **75.0%** | 30/40 | 10 | 0 |
| **sql** (SQL Server) | **72.5%** | 29/40 | 11 | 0 |

**Average Detection Rate: 81.25%**

---

## Detection by MITRE ATT&CK Category

### Execution (5 techniques)
| Technique | ws | srv | dc | sql | exch | iis |
|-----------|:--:|:---:|:--:|:---:|:----:|:---:|
| T1059.001 (PowerShell) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1059.003 (Command Shell) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1047 (WMI) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1106 (Native API) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1204.002 (Malicious File) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

**Category Coverage: 100%** - All configs detect execution techniques excellently.

### Persistence (5 techniques)
| Technique | ws | srv | dc | sql | exch | iis |
|-----------|:--:|:---:|:--:|:---:|:----:|:---:|
| T1547.001 (Registry Run Keys) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1053.005 (Scheduled Task) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1543.003 (Windows Service) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1546.003 (WMI Event Sub) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1136.001 (Local Account) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

**Category Coverage: 100%** - Persistence mechanisms fully covered.

### Privilege Escalation (2 techniques)
| Technique | ws | srv | dc | sql | exch | iis |
|-----------|:--:|:---:|:--:|:---:|:----:|:---:|
| T1548.002 (Bypass UAC) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1134.001 (Token Impersonation) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

**Category Coverage: 100%** - Privilege escalation fully detected.

### Defense Evasion (8 techniques)
| Technique | ws | srv | dc | sql | exch | iis |
|-----------|:--:|:---:|:--:|:---:|:----:|:---:|
| T1218.005 (Mshta) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1218.010 (Regsvr32) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1218.011 (Rundll32) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1027 (Obfuscated Files) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1140 (Deobfuscate) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1070.001 (Clear Event Logs) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1070.004 (File Deletion) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1562.001 (Disable Security) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

**Category Coverage: 100%** - Excellent LOLBin and evasion detection.

### Credential Access (5 techniques)
| Technique | ws | srv | dc | sql | exch | iis |
|-----------|:--:|:---:|:--:|:---:|:----:|:---:|
| T1003.001 (LSASS Memory) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1003.002 (SAM) | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ |
| T1003.003 (NTDS) | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1552.001 (Creds in Files) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1555.003 (Browser Creds) | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ |

**Category Coverage: 80%** - Some gaps in credential dumping detection.

### Discovery (8 techniques)
| Technique | ws | srv | dc | sql | exch | iis |
|-----------|:--:|:---:|:--:|:---:|:----:|:---:|
| T1087.001 (Local Account) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| T1087.002 (Domain Account) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1082 (System Info) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1057 (Process Discovery) | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1018 (Remote System) | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1016 (Network Config) | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ |
| T1069.002 (Domain Groups) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1482 (Domain Trust) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

**Category Coverage: 75%** - T1087.001 not detected by any config (uses native commands without network/file activity).

### Lateral Movement (2 techniques)
| Technique | ws | srv | dc | sql | exch | iis |
|-----------|:--:|:---:|:--:|:---:|:----:|:---:|
| T1021.002 (SMB Shares) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| T1570 (Lateral Tool Transfer) | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ |

**Category Coverage: 33%** - Weak detection. Consider enabling network monitoring on servers.

### Collection (3 techniques)
| Technique | ws | srv | dc | sql | exch | iis |
|-----------|:--:|:---:|:--:|:---:|:----:|:---:|
| T1560.001 (Archive via Utility) | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| T1005 (Data from Local) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| T1074.001 (Local Data Staging) | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ |

**Category Coverage: 28%** - Poor collection detection. File monitoring rules may need tuning.

### Command & Control (2 techniques)
| Technique | ws | srv | dc | sql | exch | iis |
|-----------|:--:|:---:|:--:|:---:|:----:|:---:|
| T1105 (Ingress Tool Transfer) | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ |
| T1071.001 (Web Protocols) | ✅ | ❌ | ⚠️ | ❌ | ✅ | ❌ |

**Category Coverage: 42%** - Server configs miss C2 traffic. Enable NetworkConnect monitoring.

---

## Recommendations

### High Priority (Security Gaps)

1. **T1087.001 (Local Account Discovery)** - NOT detected by ANY config
   - **Issue:** `net user` and similar commands don't generate Sysmon events
   - **Fix:** Add ProcessCreate rules for `net.exe`, `net1.exe` with arguments containing `user`
   ```xml
   <ProcessCreate onmatch="include">
     <CommandLine condition="contains">net user</CommandLine>
     <CommandLine condition="contains">net1 user</CommandLine>
   </ProcessCreate>
   ```

2. **T1005 (Data from Local System)** - NOT detected by ANY config
   - **Issue:** File access patterns not captured
   - **Fix:** Enable FileCreate monitoring for sensitive directories or consider FileAccessedTime events

3. **Lateral Movement (T1021.002, T1570)** - Poor detection on servers
   - **Issue:** Server configs exclude too much network traffic
   - **Fix:** For srv/sql/iis configs, add rules for:
   ```xml
   <NetworkConnect onmatch="include">
     <DestinationPort condition="is">445</DestinationPort>
     <DestinationPort condition="is">139</DestinationPort>
   </NetworkConnect>
   ```

4. **C2 Detection (T1105, T1071.001)** - Missing on server configs
   - **Issue:** DNS and network events excluded for performance
   - **Fix:** Enable DnsQuery (Event 22) selectively on servers:
   ```xml
   <DnsQuery onmatch="exclude">
     <QueryName condition="end with">.microsoft.com</QueryName>
     <QueryName condition="end with">.windows.com</QueryName>
   </DnsQuery>
   ```

### Medium Priority (Coverage Improvements)

5. **T1003.002 (SAM)** - Missing on sql, iis
   - Consider enabling RawAccessRead (Event 9) for these configs

6. **T1555.003 (Browser Credentials)** - Missing on srv, sql, iis
   - Add FileCreate rules for browser credential stores

7. **T1016 (Network Config Discovery)** - Missing on srv, sql
   - Enable ProcessCreate rules for `ipconfig`, `route`, `netstat`

### Low Priority (Fine-tuning)

8. Review exclusion lists to ensure legitimate security tools aren't hiding malicious activity
9. Consider adding Process Tampering (Event 25) to ws and srv configs
10. Evaluate FileDeleteDetected (Event 23) coverage for anti-forensics detection

---

## Event Type Distribution

| Event ID | Name | ws | srv | dc | sql | exch | iis |
|----------|------|:--:|:---:|:--:|:---:|:----:|:---:|
| 1 | ProcessCreate | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 3 | NetworkConnect | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 7 | ImageLoad | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 9 | RawAccessRead | - | ✅ | ✅ | ✅ | ✅ | ✅ |
| 10 | ProcessAccess | ✅ | - | ✅ | ✅ | ✅ | ✅ |
| 11 | FileCreate | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 12 | RegistryAddDelete | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 13 | RegistryValueSet | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 22 | DnsQuery | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 23 | FileDelete | - | ✅ | ✅ | ✅ | ✅ | ✅ |
| 25 | ProcessTampering | - | - | ✅ | - | - | ✅ |

---

## Files Location

### Local Artifacts (Mac)
```
/Users/cere/sysmon-repo/sysmon/test-results/
├── detection-results-dc/
│   ├── atomic-events-dc.csv      # Raw Sysmon events from Atomic tests
│   ├── detection-coverage-dc.csv  # Per-technique detection results
│   └── detection-report-dc.md     # Detailed report
├── detection-results-exch/
│   └── ...
├── detection-results-iis/
│   └── ...
├── detection-results-sql/
│   └── ...
├── detection-results-srv/
│   └── ...
├── detection-results-ws/
│   └── ...
├── sysmon-events-dc/
│   └── sysmon-events-dc.csv       # Base test events
└── sysmon-events-*/
    └── ...
```

### GitHub Artifacts
- **URL:** https://github.com/cereZ23/sysmon/actions/runs/20295523482
- Artifacts available for 90 days

---

## Testing Methodology

- **Tool:** Atomic Red Team (Red Canary)
- **Platform:** Windows Server 2025 (GitHub Actions runner)
- **Techniques:** 40 selected across 9 MITRE ATT&CK categories
- **Detection Method:** Sysmon event count before/after technique execution
- **Criteria:** Technique marked "DETECTED" if ≥1 Sysmon event generated

### Techniques Tested
```
Execution:      T1059.001, T1059.003, T1047, T1106, T1204.002
Persistence:    T1547.001, T1053.005, T1543.003, T1546.003, T1136.001
Priv Esc:       T1548.002, T1134.001
Defense Evas:   T1218.005, T1218.010, T1218.011, T1027, T1140, T1070.001, T1070.004, T1562.001
Cred Access:    T1003.001, T1003.002, T1003.003, T1552.001, T1555.003
Discovery:      T1087.001, T1087.002, T1082, T1057, T1018, T1016, T1069.002, T1482
Lateral Mov:    T1021.002, T1570
Collection:     T1560.001, T1005, T1074.001
C2:             T1105, T1071.001
```

---

## Conclusion

The Sysmon configurations provide **strong detection coverage (81.25% average)** for:
- Execution techniques (100%)
- Persistence mechanisms (100%)
- Privilege escalation (100%)
- Defense evasion/LOLBins (100%)

**Areas requiring attention:**
- Collection techniques (28%)
- Lateral movement (33%)
- C2 communication on servers (42%)
- Local account discovery (0%)

The **Exchange** and **Domain Controller** configs have the best coverage due to their more comprehensive monitoring rules. Server-specific configs (sql, iis, srv) sacrifice some detection capability for reduced noise in production environments.
