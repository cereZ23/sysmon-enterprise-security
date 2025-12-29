# Sysmon Configuration: Generic Windows Server

**File:** `sysmon-srv.xml`
**Target:** Windows Server 2016/2019/2022
**Focus:** Lateral movement, persistence, unauthorized access

## Overview

Aggressive monitoring posture for Windows Servers based on the principle that servers run automated workloads without interactive user sessions. Any discovery command, PowerShell activity, or user profile file creation is highly suspicious.

## Key Threats Detected

| Threat | Detection Method |
|--------|-----------------|
| Lateral Movement | PsExec, RDP client usage, remote execution |
| Credential Access | LSASS dumping, ntdsutil, mimikatz patterns |
| Persistence | Registry, Services, Scheduled Tasks, WMI |
| Defense Evasion | Shadow copy deletion, log clearing, AV tampering |
| Discovery | ALL discovery commands monitored |

## Event ID Coverage

| Event ID | Name | Status | Notes |
|----------|------|--------|-------|
| 1 | ProcessCreate | Active | Context-aware AND rules |
| 2 | FileCreateTime | Active | Timestomping detection |
| 3 | NetworkConnect | Active | User profile connections suspicious |
| 5 | ProcessTerminate | Active | Security tool + critical services |
| 6 | DriverLoad | Active | Unsigned/BYOVD drivers |
| 7 | ImageLoad | Active | Credential DLLs, temp locations |
| 8 | CreateRemoteThread | Active | Include-based on targets |
| 9 | RawAccessRead | Active | Raw disk access |
| 10 | ProcessAccess | Active | 8 LSASS masks + CallTrace |
| 11 | FileCreate | Active | Path-scoped with AND rules |
| 13 | RegistryEvent | Active | 50+ persistence mechanisms |
| 15 | FileCreateStreamHash | Active | ADS detection |
| 17/18 | PipeEvent | Active | C2 frameworks, PsExec |
| 19/20/21 | WmiEvent | Active | WMI persistence |
| 22 | DnsQuery | Active | Include-based (LOLBins only) |
| 25 | ProcessTampering | Active | Hollowing/herpaderping |
| 26 | FileDelete | Active | Anti-forensics detection |

## Server-Specific Philosophy

**Servers should have predictable, automated behavior:**
- No interactive user sessions
- No discovery commands (whoami, net, systeminfo)
- No PowerShell download cradles
- No file creation in user profiles
- No RDP client usage (mstsc.exe)

Any deviation = potential indicator of compromise.

## MITRE ATT&CK Coverage

| Technique | ID | Coverage |
|-----------|-----|----------|
| Remote Services | T1021 | Full |
| Lateral Tool Transfer | T1570 | Full |
| Boot or Logon Autostart | T1547 | Full |
| Event Triggered Execution | T1546 | Full (COM, AppInit, IFEO) |
| OS Credential Dumping | T1003 | Full |
| Indicator Removal | T1070 | Full |
| Impair Defenses | T1562 | Full |

## Registry Monitoring (Expanded)

```
Persistence Mechanisms:
├── Run/RunOnce Keys (T1547.001)
├── Winlogon Shell/Userinit (T1547.004)
├── Services (T1543.003)
├── COM Hijacking (T1546.015)
├── AppInit DLLs (T1546.010)
├── AppCompat Shim (T1546.011)
├── IFEO Debugging (T1546.012)
├── Print Drivers (PrintNightmare)
└── Scheduled Tasks

Security Tampering:
├── LSA Protection
├── Security Packages
├── Windows Defender Exclusions
├── Firewall Policy
├── Event Log Settings
└── Cryptography Settings
```

## Installation

```powershell
# New installation
sysmon.exe -accepteula -i sysmon-srv.xml

# Update existing
sysmon.exe -c sysmon-srv.xml
```

## Customization

### Backup Software Exclusions
```xml
<!-- Uncomment and customize for your environment -->
<ParentImage condition="begin with">C:\Program Files\Veeam\</ParentImage>
<ParentImage condition="begin with">C:\Program Files\Commvault\</ParentImage>
```

### Management Tools
- SCCM client paths
- Monitoring agent paths
- Patching solution paths

## Splunk Queries

**Discovery Command Burst:**
```spl
index=sysmon EventCode=1 Computer=*-SRV*
| search Image IN ("*whoami.exe", "*net.exe", "*nltest.exe", "*systeminfo.exe")
| bucket _time span=5m
| stats count by _time, Computer, User
| where count > 3
```

**RDP Pivoting Detection:**
```spl
index=sysmon EventCode=1 Computer=*-SRV*
| search Image="*mstsc.exe"
| table _time, Computer, User, CommandLine
```

**Shadow Copy Deletion:**
```spl
index=sysmon EventCode=1
| search CommandLine="*vssadmin*delete*" OR CommandLine="*wmic*shadowcopy*"
| table _time, Computer, User, CommandLine
```

## Security Fixes Applied (v2.1)

### Volume Optimization
1. **ProcessCreate** - Context-aware AND rules for shells from suspicious parents
2. **DnsQuery** - Include-based: only LOLBins and suspicious paths
3. **FileCreate** - exe/dll/scripts restricted to suspicious paths only
4. **CreateRemoteThread** - Include-based on sensitive targets (lsass, winlogon, csrss, svchost) + AV/EDR exclusions

### Detection Improvements
5. **ProcessAccess** - 8 LSASS masks (0x40, 0x1000, 0x1010, 0x1038, 0x1410, 0x1438, 0x143a, 0x1fffff)
6. **Added Event 6** - DriverLoad for BYOVD/rootkit detection
7. **Added Event 9** - RawAccessRead for raw disk access
8. **Added Event 25** - ProcessTampering for hollowing/herpaderping
9. **Added Event 26** - FileDelete for anti-forensics detection

## Maintenance

- Servers should generate fewer events than workstations
- High event volume indicates misconfiguration or attack
- Review exclusions after software deployments
- Monitor for new management tool deployments

---
**Version:** 2.1
**Last Updated:** December 2025
