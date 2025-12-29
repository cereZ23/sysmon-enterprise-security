# Executive Summary: Sysmon MITRE ATT&CK Detection Improvements

**Date:** December 17, 2025
**Status:** Partially Successful
**PR:** #1

---

## Overview

We implemented configuration improvements to our Windows Sysmon monitoring system to address detection gaps identified during security testing. The changes target lateral movement techniques commonly used by advanced threat actors.

---

## Results at a Glance

| Metric | Result |
|--------|--------|
| Overall Detection Improvement | **+2.5%** (81.25% → 83.75%) |
| Lateral Movement Detection (T1021.002) | **+500%** (1/6 → 6/6 systems) |
| Account Discovery Detection (T1087.001) | No change (requires investigation) |
| Configurations Improved | **5 of 6** |

---

## Business Impact

### Positive Outcomes

1. **Lateral Movement Visibility:** All server types now detect SMB-based lateral movement, a technique used in 78% of ransomware attacks. Previously only workstations had this capability.

2. **Domain Controller Protection:** Our most critical asset (Domain Controller) achieved the highest detection rate at **92.5%**, up from 87.5%.

3. **Server Coverage:** Generic servers improved from 77.5% to 80%, reducing blind spots for attackers moving through the network.

### Areas Requiring Attention

1. **Local Account Discovery (T1087.001):** This technique remains undetected despite rule additions. Attackers use this to enumerate local users before privilege escalation. Requires further investigation.

2. **Data Collection Techniques:** Archive and data staging techniques remain undetected across all configurations.

---

## Detection Coverage by System Type

```
Domain Controller:  ████████████████████████████████████░░░ 92.5% (+5.0%)
Exchange Server:    ████████████████████████████████████░░░ 92.5% (+2.5%)
Workstation:        ██████████████████████████████████░░░░░ 87.5% (+2.5%)
Generic Server:     ████████████████████████████████░░░░░░░ 80.0% (+2.5%)
SQL Server:         ██████████████████████████████░░░░░░░░░ 75.0% (+2.5%)
IIS Web Server:     ██████████████████████████████░░░░░░░░░ 75.0% (0%)
```

---

## Key Improvements

### Before Changes
- Only **1 of 6** configurations could detect SMB lateral movement
- Server-to-server attacks were largely invisible
- Average detection rate: 81.25%

### After Changes
- **6 of 6** configurations detect SMB lateral movement
- Cross-server attacks are now visible to SOC
- Average detection rate: 83.75%

---

## Risk Assessment

| Risk Area | Before | After | Trend |
|-----------|--------|-------|-------|
| Lateral Movement | High | **Low** | Improved |
| Account Enumeration | High | High | No change |
| Data Exfiltration | Medium | Medium | No change |
| Credential Theft | Low | Low | Stable |

---

## Recommendations

### Immediate (This Week)
1. **Merge PR #1** to deploy improvements to production
2. **Investigate T1087.001** detection failure with security engineering

### Short-term (This Month)
1. Add PowerShell script block logging integration
2. Review and tune exclusion rules

### Long-term (This Quarter)
1. Expand collection technique detection
2. Implement continuous MITRE ATT&CK coverage testing
3. Target 90%+ detection rate across all configurations

---

## Investment Summary

| Item | Effort | Impact |
|------|--------|--------|
| Configuration changes | 2 hours | Immediate |
| Testing & validation | 4 hours | Validation |
| Documentation | 1 hour | Compliance |
| **Total** | **7 hours** | **+2.5% coverage** |

---

## Conclusion

The implemented changes represent a meaningful improvement in our detection capabilities, particularly for lateral movement techniques. The 500% improvement in SMB detection coverage addresses a critical gap in our security monitoring.

However, the failure to detect local account discovery (T1087.001) indicates a need for deeper investigation into our detection rules and testing methodology.

**Recommended Action:** Approve and merge PR #1 to production, with follow-up investigation on T1087.001.

---

*Report prepared by Security Engineering Team*
*Testing conducted using MITRE ATT&CK Framework and Atomic Red Team*
