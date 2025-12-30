# Splunk Alert Queries - Windows Security Events

Raccolta esaustiva di query Splunk per il monitoraggio e alerting di Windows Security Events.

**Versione:** 1.0.0
**Data:** 30 Dicembre 2025
**Index consigliato:** `index=wineventlog` o `index=windows`

---

## Indice

1. [Account Management](#1-account-management)
2. [Authentication & Logon](#2-authentication--logon)
3. [Privilege Escalation](#3-privilege-escalation)
4. [Lateral Movement](#4-lateral-movement)
5. [Persistence](#5-persistence)
6. [Credential Access](#6-credential-access)
7. [Defense Evasion](#7-defense-evasion)
8. [Discovery](#8-discovery)
9. [PowerShell Logging](#9-powershell-logging)
10. [Active Directory](#10-active-directory)
11. [File & Object Access](#11-file--object-access)
12. [Network & Firewall](#12-network--firewall)
13. [System Integrity](#13-system-integrity)

---

## 1. Account Management

### 1.1 User Account Created (T1136.001)
```spl
index=wineventlog EventCode=4720
| eval risk_score=case(
    match(TargetUserName, "(?i)(admin|svc|service|backup)"), 80,
    true(), 50)
| table _time, Computer, SubjectUserName, TargetUserName, risk_score
| sort -_time
```
**Severity:** High | **MITRE:** T1136.001

### 1.2 User Account Deleted
```spl
index=wineventlog EventCode=4726
| table _time, Computer, SubjectUserName, TargetUserName
| sort -_time
```
**Severity:** Medium | **MITRE:** T1531

### 1.3 User Account Enabled
```spl
index=wineventlog EventCode=4722
| table _time, Computer, SubjectUserName, TargetUserName
```
**Severity:** Low | **MITRE:** T1098

### 1.4 User Account Disabled
```spl
index=wineventlog EventCode=4725
| table _time, Computer, SubjectUserName, TargetUserName
```
**Severity:** Medium | **MITRE:** T1531

### 1.5 Password Reset Attempt (T1098)
```spl
index=wineventlog EventCode=4724
| stats count by SubjectUserName, TargetUserName, Computer
| where count > 1
| sort -count
```
**Severity:** Medium | **MITRE:** T1098

### 1.6 Password Change Attempt
```spl
index=wineventlog EventCode=4723
| table _time, Computer, TargetUserName, SubjectUserName
```
**Severity:** Low | **MITRE:** T1098

### 1.7 User Added to Privileged Group (T1098)
```spl
index=wineventlog (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| search TargetUserName IN ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Backup Operators", "Account Operators", "Server Operators", "Print Operators")
| eval severity="CRITICAL"
| table _time, Computer, MemberName, TargetUserName, SubjectUserName, severity
```
**Severity:** Critical | **MITRE:** T1098

### 1.8 User Removed from Group
```spl
index=wineventlog (EventCode=4729 OR EventCode=4733 OR EventCode=4757)
| table _time, Computer, MemberName, TargetUserName, SubjectUserName
```
**Severity:** Medium | **MITRE:** T1098

### 1.9 Security Group Created
```spl
index=wineventlog (EventCode=4727 OR EventCode=4731 OR EventCode=4754)
| table _time, Computer, TargetUserName, SubjectUserName
```
**Severity:** Medium | **MITRE:** T1136.002

### 1.10 Account Lockout
```spl
index=wineventlog EventCode=4740
| stats count by TargetUserName, TargetDomainName
| where count >= 1
| sort -count
```
**Severity:** Medium | **MITRE:** T1110

---

## 2. Authentication & Logon

### 2.1 Brute Force Detection - Failed Logons (T1110)
```spl
index=wineventlog EventCode=4625
| stats count by TargetUserName, IpAddress, LogonType
| where count >= 5
| eval attack_type=case(
    count >= 100, "Brute Force Attack",
    count >= 20, "Password Spray",
    count >= 5, "Suspicious Failed Logons")
| sort -count
```
**Severity:** High | **MITRE:** T1110

### 2.2 Failed Logon - Specific Error Codes
```spl
index=wineventlog EventCode=4625
| eval failure_reason=case(
    SubStatus="0xC000006A", "Wrong Password",
    SubStatus="0xC0000064", "User Does Not Exist",
    SubStatus="0xC000006D", "Bad Username or Password",
    SubStatus="0xC000006E", "Account Restriction",
    SubStatus="0xC000006F", "Outside Logon Hours",
    SubStatus="0xC0000070", "Workstation Restriction",
    SubStatus="0xC0000071", "Password Expired",
    SubStatus="0xC0000072", "Account Disabled",
    SubStatus="0xC00000DC", "Server in Wrong State",
    SubStatus="0xC0000133", "Clocks Out of Sync",
    SubStatus="0xC000015B", "No Logon Servers Available",
    SubStatus="0xC000018C", "Trust Relationship Failed",
    SubStatus="0xC0000192", "NetLogon Service Not Started",
    SubStatus="0xC0000193", "Account Expired",
    SubStatus="0xC0000224", "Password Must Change",
    SubStatus="0xC0000234", "Account Locked",
    true(), SubStatus)
| stats count by TargetUserName, failure_reason, IpAddress
| sort -count
```
**Severity:** Medium | **MITRE:** T1110

### 2.3 Successful Logon from New Location
```spl
index=wineventlog EventCode=4624 LogonType=10
| stats earliest(_time) as first_seen, latest(_time) as last_seen, count by TargetUserName, IpAddress, Computer
| where first_seen > relative_time(now(), "-24h")
| convert ctime(first_seen), ctime(last_seen)
```
**Severity:** Medium | **MITRE:** T1078

### 2.4 Logon Outside Business Hours
```spl
index=wineventlog EventCode=4624 LogonType IN (2, 10, 11)
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| eval day=strftime(_time, "%A")
| where day IN ("Saturday", "Sunday") OR hour < 6 OR hour > 22
| table _time, Computer, TargetUserName, IpAddress, LogonType
```
**Severity:** Medium | **MITRE:** T1078

### 2.5 Pass-the-Hash Detection (T1550.002)
```spl
index=wineventlog EventCode=4624 LogonType=9 LogonProcessName=seclogo
| table _time, Computer, TargetUserName, IpAddress, LogonProcessName
```
**Severity:** Critical | **MITRE:** T1550.002

### 2.6 Explicit Credentials Used (T1078)
```spl
index=wineventlog EventCode=4648
| stats count by SubjectUserName, TargetUserName, TargetServerName, ProcessName
| where SubjectUserName!=TargetUserName
| sort -count
```
**Severity:** Medium | **MITRE:** T1078

### 2.7 Kerberos TGT Request (T1558.003)
```spl
index=wineventlog EventCode=4768
| stats count by TargetUserName, IpAddress, ServiceName
| where ServiceName="krbtgt"
```
**Severity:** Low | **MITRE:** T1558.003

### 2.8 Kerberos Service Ticket Request - Kerberoasting (T1558.003)
```spl
index=wineventlog EventCode=4769 TicketEncryptionType=0x17
| stats count by TargetUserName, ServiceName, IpAddress
| where count > 10
| sort -count
```
**Severity:** High | **MITRE:** T1558.003

### 2.9 Kerberos Pre-Authentication Failed (T1558.004)
```spl
index=wineventlog EventCode=4771
| stats count by TargetUserName, IpAddress
| where count >= 5
| sort -count
```
**Severity:** Medium | **MITRE:** T1558.004

### 2.10 NTLM Authentication Used
```spl
index=wineventlog EventCode=4624 AuthenticationPackageName=NTLM
| stats count by TargetUserName, Computer, IpAddress
| sort -count
```
**Severity:** Low | **MITRE:** T1550.002

### 2.11 Interactive Logon to Server
```spl
index=wineventlog EventCode=4624 LogonType=2
| search Computer IN ("*SRV*", "*DC*", "*SQL*", "*EXCH*")
| table _time, Computer, TargetUserName, IpAddress
```
**Severity:** Medium | **MITRE:** T1078

### 2.12 Network Logon from Unusual Source
```spl
index=wineventlog EventCode=4624 LogonType=3
| stats count by TargetUserName, IpAddress, Computer
| where NOT match(IpAddress, "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.")
| sort -count
```
**Severity:** High | **MITRE:** T1078

---

## 3. Privilege Escalation

### 3.1 Special Privileges Assigned (T1134)
```spl
index=wineventlog EventCode=4672
| search PrivilegeList IN ("*SeDebugPrivilege*", "*SeTcbPrivilege*", "*SeBackupPrivilege*", "*SeRestorePrivilege*", "*SeTakeOwnershipPrivilege*", "*SeLoadDriverPrivilege*")
| where SubjectUserName!="SYSTEM" AND NOT match(SubjectUserName, "\$$")
| table _time, Computer, SubjectUserName, PrivilegeList
```
**Severity:** High | **MITRE:** T1134

### 3.2 SeDebugPrivilege Used
```spl
index=wineventlog EventCode=4672 PrivilegeList="*SeDebugPrivilege*"
| where SubjectUserName!="SYSTEM"
| table _time, Computer, SubjectUserName, LogonId
```
**Severity:** Critical | **MITRE:** T1134

### 3.3 Security Log Cleared (T1070.001)
```spl
index=wineventlog EventCode=1102 OR (EventCode=104 AND LogName="Security")
| table _time, Computer, SubjectUserName
```
**Severity:** Critical | **MITRE:** T1070.001

### 3.4 Audit Policy Changed (T1562.002)
```spl
index=wineventlog EventCode=4719
| table _time, Computer, SubjectUserName, SubcategoryGuid, AuditPolicyChanges
```
**Severity:** High | **MITRE:** T1562.002

### 3.5 System Audit Policy Changed
```spl
index=wineventlog EventCode=4902
| table _time, Computer, SubjectUserName
```
**Severity:** High | **MITRE:** T1562.002

### 3.6 Token Manipulation (T1134.001)
```spl
index=wineventlog EventCode=4624 LogonType=9
| table _time, Computer, TargetUserName, SubjectUserName, LogonProcessName
```
**Severity:** High | **MITRE:** T1134.001

---

## 4. Lateral Movement

### 4.1 Remote Desktop Connection (T1021.001)
```spl
index=wineventlog EventCode=4624 LogonType=10
| stats count by TargetUserName, IpAddress, Computer
| sort -count
```
**Severity:** Medium | **MITRE:** T1021.001

### 4.2 SMB/Windows Admin Shares (T1021.002)
```spl
index=wineventlog EventCode=5140
| search ShareName IN ("\\*\ADMIN$", "\\*\C$", "\\*\IPC$")
| stats count by SubjectUserName, IpAddress, ShareName, Computer
| sort -count
```
**Severity:** High | **MITRE:** T1021.002

### 4.3 Admin Share Access
```spl
index=wineventlog EventCode=5145 RelativeTargetName="*ADMIN$*" OR RelativeTargetName="*C$*"
| table _time, Computer, SubjectUserName, IpAddress, ShareName, RelativeTargetName
```
**Severity:** High | **MITRE:** T1021.002

### 4.4 PsExec-like Activity (T1021.002)
```spl
index=wineventlog EventCode=5145 RelativeTargetName="*.exe" ShareName="\\*\ADMIN$"
| table _time, Computer, SubjectUserName, IpAddress, RelativeTargetName
```
**Severity:** Critical | **MITRE:** T1021.002, T1570

### 4.5 WMI Remote Execution (T1047)
```spl
index=wineventlog EventCode=4624 LogonType=3 ProcessName="*WmiPrvSE*"
| table _time, Computer, TargetUserName, IpAddress
```
**Severity:** High | **MITRE:** T1047

### 4.6 WinRM Remote Execution (T1021.006)
```spl
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="Negotiate"
| search ProcessName="*wsmprovhost*"
| table _time, Computer, TargetUserName, IpAddress
```
**Severity:** High | **MITRE:** T1021.006

### 4.7 Lateral Movement Detection - Multiple Hosts
```spl
index=wineventlog EventCode=4624 LogonType IN (3, 10)
| stats dc(Computer) as hosts_accessed, values(Computer) as target_hosts by TargetUserName, IpAddress
| where hosts_accessed > 3
| sort -hosts_accessed
```
**Severity:** High | **MITRE:** T1021

---

## 5. Persistence

### 5.1 Service Installed (T1543.003)
```spl
index=wineventlog EventCode=4697
| eval suspicious=if(match(ServiceFileName, "(?i)(cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32)"), "HIGH", "MEDIUM")
| table _time, Computer, SubjectUserName, ServiceName, ServiceFileName, ServiceType, suspicious
```
**Severity:** High | **MITRE:** T1543.003

### 5.2 Suspicious Service Installation
```spl
index=wineventlog EventCode=4697
| search ServiceFileName="*cmd*" OR ServiceFileName="*powershell*" OR ServiceFileName="*\\Temp\\*" OR ServiceFileName="*\\AppData\\*"
| table _time, Computer, ServiceName, ServiceFileName, SubjectUserName
```
**Severity:** Critical | **MITRE:** T1543.003

### 5.3 Scheduled Task Created (T1053.005)
```spl
index=wineventlog EventCode=4698
| rex field=TaskContent "<Command>(?<Command>[^<]+)</Command>"
| rex field=TaskContent "<Arguments>(?<Arguments>[^<]+)</Arguments>"
| table _time, Computer, SubjectUserName, TaskName, Command, Arguments
```
**Severity:** High | **MITRE:** T1053.005

### 5.4 Suspicious Scheduled Task
```spl
index=wineventlog EventCode=4698
| search TaskContent="*powershell*" OR TaskContent="*cmd.exe*" OR TaskContent="*wscript*" OR TaskContent="*cscript*" OR TaskContent="*mshta*" OR TaskContent="*\\Temp\\*"
| table _time, Computer, SubjectUserName, TaskName, TaskContent
```
**Severity:** Critical | **MITRE:** T1053.005

### 5.5 Scheduled Task Deleted (T1070.004)
```spl
index=wineventlog EventCode=4699
| table _time, Computer, SubjectUserName, TaskName
```
**Severity:** Medium | **MITRE:** T1070.004

### 5.6 Scheduled Task Enabled/Disabled
```spl
index=wineventlog EventCode IN (4700, 4701)
| eval action=if(EventCode=4700, "Enabled", "Disabled")
| table _time, Computer, SubjectUserName, TaskName, action
```
**Severity:** Low | **MITRE:** T1053.005

### 5.7 Registry Modification - Run Keys (T1547.001)
```spl
index=wineventlog EventCode=4657
| search ObjectName="*\\CurrentVersion\\Run*" OR ObjectName="*\\CurrentVersion\\RunOnce*"
| table _time, Computer, SubjectUserName, ObjectName, ObjectValueName, NewValue
```
**Severity:** High | **MITRE:** T1547.001

---

## 6. Credential Access

### 6.1 Credential Dumping - LSASS Access (T1003.001)
```spl
index=wineventlog EventCode=4663 ObjectName="*\\lsass.exe*"
| table _time, Computer, SubjectUserName, ProcessName, ObjectName, AccessMask
```
**Severity:** Critical | **MITRE:** T1003.001

### 6.2 SAM Database Access (T1003.002)
```spl
index=wineventlog EventCode=4663
| search ObjectName="*\\SAM" OR ObjectName="*\\SECURITY" OR ObjectName="*\\SYSTEM"
| table _time, Computer, SubjectUserName, ProcessName, ObjectName
```
**Severity:** Critical | **MITRE:** T1003.002

### 6.3 NTDS.dit Access (T1003.003)
```spl
index=wineventlog EventCode=4663 ObjectName="*ntds.dit*"
| table _time, Computer, SubjectUserName, ProcessName, ObjectName
```
**Severity:** Critical | **MITRE:** T1003.003

### 6.4 Credential Manager Access (T1555)
```spl
index=wineventlog EventCode=5379
| table _time, Computer, SubjectUserName, TargetName, Type
```
**Severity:** Medium | **MITRE:** T1555

### 6.5 Sensitive Privilege Use (T1134)
```spl
index=wineventlog EventCode=4673
| search PrivilegeList IN ("SeTcbPrivilege", "SeDebugPrivilege", "SeCreateTokenPrivilege")
| table _time, Computer, SubjectUserName, PrivilegeList, ProcessName
```
**Severity:** High | **MITRE:** T1134

### 6.6 Kerberoasting - RC4 Ticket Requested (T1558.003)
```spl
index=wineventlog EventCode=4769 TicketEncryptionType=0x17 TicketOptions=0x40810000
| search ServiceName!="krbtgt" ServiceName!="*$"
| stats count by TargetUserName, ServiceName, IpAddress
| where count > 5
| sort -count
```
**Severity:** High | **MITRE:** T1558.003

### 6.7 AS-REP Roasting (T1558.004)
```spl
index=wineventlog EventCode=4768 PreAuthType=0
| stats count by TargetUserName, IpAddress
| sort -count
```
**Severity:** High | **MITRE:** T1558.004

### 6.8 DCSync Attack Detection (T1003.006)
```spl
index=wineventlog EventCode=4662
| search Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*89e95b76-444d-4c62-991a-0facbeda640c*"
| where NOT match(SubjectUserName, "(?i)^(MSOL_|AAD_)")
| table _time, Computer, SubjectUserName, ObjectName, Properties
```
**Severity:** Critical | **MITRE:** T1003.006

---

## 7. Defense Evasion

### 7.1 Security Log Cleared (T1070.001)
```spl
index=wineventlog (EventCode=1102 OR EventCode=517)
| table _time, Computer, SubjectUserName
```
**Severity:** Critical | **MITRE:** T1070.001

### 7.2 Any Event Log Cleared
```spl
index=wineventlog EventCode=104
| table _time, Computer, SubjectUserName, Channel
```
**Severity:** High | **MITRE:** T1070.001

### 7.3 Audit Policy Disabled (T1562.002)
```spl
index=wineventlog EventCode=4719
| search AuditPolicyChanges="*removed*" OR AuditPolicyChanges="*Failure removed*" OR AuditPolicyChanges="*Success removed*"
| table _time, Computer, SubjectUserName, SubcategoryGuid, AuditPolicyChanges
```
**Severity:** Critical | **MITRE:** T1562.002

### 7.4 Windows Firewall Rule Added (T1562.004)
```spl
index=wineventlog EventCode=4946
| table _time, Computer, RuleName, RuleId, Direction
```
**Severity:** Medium | **MITRE:** T1562.004

### 7.5 Windows Firewall Rule Modified
```spl
index=wineventlog EventCode=4947
| table _time, Computer, RuleName, RuleId
```
**Severity:** Medium | **MITRE:** T1562.004

### 7.6 Windows Firewall Rule Deleted
```spl
index=wineventlog EventCode=4948
| table _time, Computer, RuleName, RuleId
```
**Severity:** Medium | **MITRE:** T1562.004

### 7.7 Windows Defender Disabled (T1562.001)
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-Windows Defender/Operational" EventCode=5001
| table _time, Computer
```
**Severity:** Critical | **MITRE:** T1562.001

### 7.8 Time Manipulation (T1070.006)
```spl
index=wineventlog EventCode=4616
| table _time, Computer, SubjectUserName, PreviousTime, NewTime
```
**Severity:** High | **MITRE:** T1070.006

---

## 8. Discovery

### 8.1 User/Group Enumeration (T1087)
```spl
index=wineventlog (EventCode=4798 OR EventCode=4799)
| stats count by SubjectUserName, Computer
| where count > 10
| sort -count
```
**Severity:** Medium | **MITRE:** T1087

### 8.2 Security Group Enumeration (T1069)
```spl
index=wineventlog EventCode=4799
| stats count by SubjectUserName, TargetUserName, Computer
| where count > 5
| sort -count
```
**Severity:** Medium | **MITRE:** T1069

### 8.3 Directory Service Access (T1087.002)
```spl
index=wineventlog EventCode=4662 ObjectType="*domainDNS*"
| stats count by SubjectUserName, Computer
| where count > 20
| sort -count
```
**Severity:** Medium | **MITRE:** T1087.002

### 8.4 LDAP Query Spike (T1087.002)
```spl
index=wineventlog EventCode=4662
| bucket _time span=5m
| stats count by _time, SubjectUserName, Computer
| where count > 100
| sort -count
```
**Severity:** Medium | **MITRE:** T1087.002

---

## 9. PowerShell Logging

### 9.1 Suspicious PowerShell Commands (T1059.001)
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search ScriptBlockText="*-EncodedCommand*" OR ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*Invoke-Expression*" OR ScriptBlockText="*IEX*" OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*DownloadFile*" OR ScriptBlockText="*Invoke-WebRequest*" OR ScriptBlockText="*Net.WebClient*"
| table _time, Computer, ScriptBlockText
```
**Severity:** High | **MITRE:** T1059.001

### 9.2 PowerShell Encoded Commands
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search ScriptBlockText="*-enc*" OR ScriptBlockText="*-encodedcommand*" OR ScriptBlockText="*[Convert]::FromBase64String*"
| table _time, Computer, ScriptBlockText
```
**Severity:** High | **MITRE:** T1027

### 9.3 PowerShell Download Cradle
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search ScriptBlockText="*Net.WebClient*" OR ScriptBlockText="*Invoke-WebRequest*" OR ScriptBlockText="*wget*" OR ScriptBlockText="*curl*" OR ScriptBlockText="*Start-BitsTransfer*"
| table _time, Computer, ScriptBlockText
```
**Severity:** High | **MITRE:** T1105

### 9.4 PowerShell Credential Theft Indicators
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search ScriptBlockText="*Mimikatz*" OR ScriptBlockText="*DumpCreds*" OR ScriptBlockText="*sekurlsa*" OR ScriptBlockText="*kerberos::*" OR ScriptBlockText="*Invoke-Mimikatz*" OR ScriptBlockText="*Get-GPPPassword*"
| table _time, Computer, ScriptBlockText
```
**Severity:** Critical | **MITRE:** T1003

### 9.5 PowerShell Lateral Movement
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search ScriptBlockText="*Invoke-Command*" OR ScriptBlockText="*Enter-PSSession*" OR ScriptBlockText="*New-PSSession*" OR ScriptBlockText="*Invoke-WmiMethod*"
| table _time, Computer, ScriptBlockText
```
**Severity:** High | **MITRE:** T1021.006

### 9.6 PowerShell AMSI Bypass (T1562.001)
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search ScriptBlockText="*AmsiInitFailed*" OR ScriptBlockText="*AmsiScanBuffer*" OR ScriptBlockText="*amsi.dll*" OR ScriptBlockText="*Disable-*"
| table _time, Computer, ScriptBlockText
```
**Severity:** Critical | **MITRE:** T1562.001

### 9.7 PowerShell Module Logging (T1059.001)
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4103
| search Payload="*Invoke-*" OR Payload="*Download*" OR Payload="*WebClient*"
| table _time, Computer, Payload
```
**Severity:** Medium | **MITRE:** T1059.001

### 9.8 PowerShell Remote Execution
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search ScriptBlockText="*-ComputerName*" OR ScriptBlockText="*Invoke-Command -Session*"
| table _time, Computer, ScriptBlockText
```
**Severity:** High | **MITRE:** T1059.001

---

## 10. Active Directory

### 10.1 Domain Controller Authentication (T1078.002)
```spl
index=wineventlog EventCode=4624 Computer="*DC*"
| stats count by TargetUserName, IpAddress, LogonType
| sort -count
```
**Severity:** Low | **MITRE:** T1078.002

### 10.2 Replication Request from Non-DC (T1003.006)
```spl
index=wineventlog EventCode=4662 AccessMask="0x100"
| search Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"
| where NOT match(SubjectUserName, "\$")
| table _time, Computer, SubjectUserName, ObjectName
```
**Severity:** Critical | **MITRE:** T1003.006

### 10.3 SID History Modification (T1134.005)
```spl
index=wineventlog EventCode=4765 OR EventCode=4766
| table _time, Computer, SubjectUserName, TargetUserName, SidHistory
```
**Severity:** Critical | **MITRE:** T1134.005

### 10.4 AdminSDHolder Modification
```spl
index=wineventlog EventCode=4662 ObjectName="*AdminSDHolder*"
| table _time, Computer, SubjectUserName, ObjectName, OperationType
```
**Severity:** Critical | **MITRE:** T1098

### 10.5 GPO Modification (T1484.001)
```spl
index=wineventlog EventCode=5136 ObjectClass="groupPolicyContainer"
| table _time, Computer, SubjectUserName, ObjectDN, AttributeLDAPDisplayName
```
**Severity:** High | **MITRE:** T1484.001

### 10.6 Trust Relationship Created (T1482)
```spl
index=wineventlog EventCode=4706
| table _time, Computer, SubjectUserName, TrustDirection, TrustType, SidFilteringEnabled
```
**Severity:** Critical | **MITRE:** T1482

### 10.7 Trust Relationship Removed
```spl
index=wineventlog EventCode=4707
| table _time, Computer, SubjectUserName, DomainName
```
**Severity:** High | **MITRE:** T1482

### 10.8 Domain Policy Changed
```spl
index=wineventlog EventCode=4739
| table _time, Computer, SubjectUserName, DomainPolicyChanged
```
**Severity:** High | **MITRE:** T1484

### 10.9 Computer Account Created (T1136.002)
```spl
index=wineventlog EventCode=4741
| table _time, Computer, SubjectUserName, TargetUserName, SamAccountName
```
**Severity:** Medium | **MITRE:** T1136.002

### 10.10 Computer Account Deleted
```spl
index=wineventlog EventCode=4743
| table _time, Computer, SubjectUserName, TargetUserName
```
**Severity:** Medium | **MITRE:** T1531

---

## 11. File & Object Access

### 11.1 Sensitive File Access (T1005)
```spl
index=wineventlog EventCode=4663
| search ObjectName="*.pst" OR ObjectName="*.ost" OR ObjectName="*password*" OR ObjectName="*credential*" OR ObjectName="*.kdbx" OR ObjectName="*.key" OR ObjectName="*.pfx" OR ObjectName="*.p12"
| table _time, Computer, SubjectUserName, ObjectName, ProcessName
```
**Severity:** High | **MITRE:** T1005

### 11.2 Network Share Access (T1039)
```spl
index=wineventlog EventCode=5140
| stats count by SubjectUserName, ShareName, IpAddress
| sort -count
```
**Severity:** Low | **MITRE:** T1039

### 11.3 File Deletion from Network Share (T1070.004)
```spl
index=wineventlog EventCode=5145 AccessMask="0x10000"
| table _time, Computer, SubjectUserName, ShareName, RelativeTargetName, IpAddress
```
**Severity:** Medium | **MITRE:** T1070.004

### 11.4 Sensitive Directory Access
```spl
index=wineventlog EventCode=4663
| search ObjectName="*\\Windows\\System32\\config\\*" OR ObjectName="*\\Windows\\NTDS\\*" OR ObjectName="*\\Windows\\repair\\*"
| table _time, Computer, SubjectUserName, ObjectName, ProcessName
```
**Severity:** High | **MITRE:** T1005

### 11.5 Backup File Access (T1003.003)
```spl
index=wineventlog EventCode=4663
| search ObjectName="*.bak" OR ObjectName="*backup*" OR ObjectName="*NTDS*"
| table _time, Computer, SubjectUserName, ObjectName, ProcessName
```
**Severity:** High | **MITRE:** T1003.003

---

## 12. Network & Firewall

### 12.1 Outbound Connection to Suspicious Port (T1571)
```spl
index=wineventlog EventCode=5156 Direction="Outbound"
| search DestPort IN (4444, 5555, 6666, 8080, 8443, 1337, 31337, 12345)
| table _time, Computer, Application, SourceAddress, DestAddress, DestPort
```
**Severity:** High | **MITRE:** T1571

### 12.2 RDP Connection (T1021.001)
```spl
index=wineventlog EventCode=5156 DestPort=3389 Direction="Inbound"
| stats count by SourceAddress, DestAddress
| sort -count
```
**Severity:** Medium | **MITRE:** T1021.001

### 12.3 SMB Connection (T1021.002)
```spl
index=wineventlog EventCode=5156 DestPort=445
| stats count by SourceAddress, DestAddress, Direction
| sort -count
```
**Severity:** Low | **MITRE:** T1021.002

### 12.4 WinRM Connection (T1021.006)
```spl
index=wineventlog EventCode=5156 DestPort IN (5985, 5986)
| table _time, Computer, SourceAddress, DestAddress, Direction
```
**Severity:** Medium | **MITRE:** T1021.006

### 12.5 DNS Query to Suspicious Domain (T1071.004)
```spl
index=wineventlog source="WinEventLog:DNS Server" EventCode=256
| search QNAME="*.xyz" OR QNAME="*.top" OR QNAME="*.tk" OR QNAME="*.pw" OR QNAME="*dyndns*" OR QNAME="*no-ip*"
| table _time, Computer, QNAME, QTYPE
```
**Severity:** Medium | **MITRE:** T1071.004

### 12.6 Firewall Disabled (T1562.004)
```spl
index=wineventlog EventCode=4950 OR EventCode=4951
| table _time, Computer, ProfileChanged, State
```
**Severity:** Critical | **MITRE:** T1562.004

---

## 13. System Integrity

### 13.1 Driver Load (T1543.003)
```spl
index=wineventlog EventCode=6 OR EventCode=7045
| search ImageLoaded="*.sys"
| where NOT match(ImageLoaded, "(?i)\\Windows\\System32\\drivers")
| table _time, Computer, ImageLoaded, Signature, SignatureStatus
```
**Severity:** High | **MITRE:** T1543.003

### 13.2 Code Integrity Violation
```spl
index=wineventlog EventCode=3001 OR EventCode=3002 OR EventCode=3003 OR EventCode=3004
| table _time, Computer, FileHash, PolicyName
```
**Severity:** High | **MITRE:** T1553

### 13.3 Boot Configuration Changed
```spl
index=wineventlog EventCode=4826
| table _time, Computer, SubjectUserName, BootConfigurationData
```
**Severity:** Critical | **MITRE:** T1542

### 13.4 Windows Update Disabled
```spl
index=wineventlog source="WinEventLog:System" EventCode=7040
| search ServiceName="wuauserv" AND param1="disabled"
| table _time, Computer, ServiceName, param1
```
**Severity:** High | **MITRE:** T1562.001

### 13.5 Security Center Alert
```spl
index=wineventlog source="WinEventLog:System" EventCode=7036
| search ServiceName="*Security*" OR ServiceName="*Defender*" OR ServiceName="*Firewall*"
| where param1="stopped"
| table _time, Computer, ServiceName, param1
```
**Severity:** High | **MITRE:** T1562.001

---

## Alert Priority Matrix

| Severity | Response Time | Examples |
|----------|---------------|----------|
| **Critical** | Immediate (<15 min) | DCSync, LSASS access, Log cleared, Audit disabled |
| **High** | <1 hour | Service installed, Scheduled task, Admin share access |
| **Medium** | <4 hours | Failed logons, Account changes, RDP connections |
| **Low** | Next business day | Successful logons, Group enumeration |

---

## Recommended Alert Thresholds

| Alert | Threshold | Timeframe |
|-------|-----------|-----------|
| Failed Logons (single user) | ≥5 | 5 minutes |
| Failed Logons (password spray) | ≥20 unique users | 10 minutes |
| Account Lockouts | ≥3 | 1 hour |
| Privilege Escalation | Any | Immediate |
| Log Cleared | Any | Immediate |
| Service Installation | Any from non-admin | Immediate |
| Admin Share Access | ≥3 hosts | 1 hour |
| Lateral Movement | ≥3 hosts | 15 minutes |

---

**Versione:** 1.0.0
**Ultimo Aggiornamento:** 30 Dicembre 2025
**Autore:** Security Engineering Team
